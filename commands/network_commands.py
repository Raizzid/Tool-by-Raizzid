import os
import socket
import logging
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
from bs4 import BeautifulSoup
import urllib.parse
import threading


from dotenv import load_dotenv
import requests
import ipaddress
from utils.utils import print_colored_message, is_valid_ip

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

IPGEO_API_KEY = os.getenv("IPGEO_API_KEY", "votre_ipgeolocation_api_key")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "votre_abuseipdb_api_key")
ABSTRACTAPI_KEY = os.getenv("ABSTRACT_API_KEY", "votre_abstract_key")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "VOTRE_CLE_API_VIRUSTOTAL")
VULNERS_API_URL = os.getenv("VULNERS_API_URL")

def obtenir_infos_reseau_local():
    print_colored_message("\n📍 Informations sur le Réseau Local 📍")
    try:
        nom_machine = socket.gethostname()
        print_colored_message(f"Nom de l'ordinateur : {nom_machine}")
    except socket.gaierror:
        print_colored_message("Impossible de récupérer le nom de l'ordinateur.")

    try:
        adresse_ip_locale = socket.gethostbyname(nom_machine)
        print_colored_message(f"Adresse IP locale : {adresse_ip_locale}")
    except socket.gaierror:
        print_colored_message("Impossible de récupérer l'adresse IP locale.")

    try:
        system = platform.system()
        if system == "Windows":
            obtenir_infos_reseau_windows()
        elif system == "Linux" or system == "Darwin":
            obtenir_infos_reseau_linux_macos()
        else:
            print_colored_message(f"Système d'exploitation non reconnu : {system}")
    except Exception as e:
        print_colored_message(f"Une erreur s'est produite lors de la récupération des infos réseau : {e}")

def obtenir_infos_reseau_windows():
    try:
        resultat = subprocess.run(['ipconfig'], capture_output=True, text=True, check=True)
        adresse_ip_trouvee = False
        masque_trouve = False
        passerelle_trouvee = False

        for ligne in resultat.stdout.splitlines():
            if "Carte réseau sans fil Wi-Fi" in ligne:
                print_colored_message("\n--- Informations de la carte Wi-Fi ---")
            elif "Adresse IPv4" in ligne and not adresse_ip_trouvee:
                adresse_ip_locale_windows = ligne.split(":")[1].strip()
                print_colored_message(f"Adresse IPv4 : {adresse_ip_locale_windows}")
                adresse_ip_trouvee = True
            elif "Masque de sous-réseau" in ligne and not masque_trouve:
                masque_reseau_windows = ligne.split(":")[1].strip()
                print_colored_message(f"Masque de sous-réseau : {masque_reseau_windows}")
                masque_trouve = True
            elif "Passerelle par défaut" in ligne and not passerelle_trouvee:
                passerelle_windows = ligne.split(":")[1].strip()
                print_colored_message(f"Passerelle par défaut : {passerelle_windows}")
                passerelle_trouvee = True

        if not adresse_ip_trouvee or not masque_trouve or not passerelle_trouvee:
            print_colored_message("\nCertaines informations n'ont pas été trouvées.")

    except FileNotFoundError:
        print_colored_message("Erreur: La commande 'ipconfig' n'est pas disponible.")
    except subprocess.CalledProcessError as e:
        print_colored_message(f"Erreur lors de l'exécution de la commande réseau : {e}")
    except PermissionError:
        print_colored_message("Erreur: Permission refusée. Exécutez en tant qu'administrateur.")
    except Exception as e:
        print_colored_message(f"Une erreur s'est produite lors de la récupération des infos réseau : {e}")

def obtenir_infos_reseau_linux_macos():
    try:
        resultat = subprocess.run(['ip', 'addr', 'show', 'eth0'], capture_output=True, text=True, check=True)
        for ligne in resultat.stdout.splitlines():
            if "inet " in ligne:
                parts = ligne.split()
                adresse_ip_cidr_linux = parts[1]
                print_colored_message(f"Adresse IP (Linux/macOS) : {adresse_ip_cidr_linux}")
                try:
                    ip_obj = ipaddress.ip_interface(adresse_ip_cidr_linux)
                    print_colored_message(f"Masque de sous-réseau (Linux/macOS) : {ip_obj.netmask}")
                except ValueError:
                    print_colored_message("Masque de sous-réseau non trouvé.")
                break  # On suppose que l'IPv4 est la première inet

        resultat_route = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, check=True)
        for ligne in resultat_route.stdout.splitlines():
            if "default via" in ligne:
                passerelle_linux = ligne.split()[2]
                print_colored_message(f"Passerelle par défaut (Linux/macOS) : {passerelle_linux}")
                break

    except FileNotFoundError:
        print_colored_message("Erreur: La commande 'ip' n'est pas disponible.")
    except subprocess.CalledProcessError as e:
        print_colored_message(f"Erreur lors de l'exécution de la commande réseau : {e}")
    except PermissionError:
        print_colored_message("Erreur: Permission refusée. Exécutez en tant qu'administrateur.")
    except Exception as e:
        print_colored_message(f"Une erreur s'est produite lors de la récupération des infos réseau : {e}")

def traceroute_ip(ip_address, max_hops=30, timeout=5):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        if platform.system().lower() == "windows":
            command = ['tracert', '-h', str(max_hops), '-w', str(timeout * 1000), ip_address]
        else:
            command = ['traceroute', '-m', str(max_hops), '-w', str(timeout), ip_address]

        result = subprocess.run(command, capture_output=True, text=True, check=True) # Check=true added to see error

        print_colored_message(f"\n{'=' * 60}\nTRACEROUTE {ip_address}\n{'=' * 60}")
        print(result.stdout)

    except subprocess.CalledProcessError as cpe:
        logging.error(f"Commande échouée avec l'erreur : {cpe}")
        print_colored_message(f"Commande échouée avec l'erreur : {cpe}")
    except FileNotFoundError:
        print_colored_message("Commande traceroute introuvable. Assurez-vous qu'elle est installée sur votre système.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors du traceroute : {e}")
        print_colored_message(f"Une erreur s'est produite lors du traceroute : {e}")


def port_scan(ip_address, start_port=1, end_port=1024, protocol='tcp', timeout=1, max_workers=100):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    open_ports = []
    total_ports = end_port - start_port + 1

    print_colored_message(f"\n{'=' * 60}")
    print_colored_message(f"Scan des ports {start_port}-{end_port} sur {ip_address} ({total_ports} ports)")
    print_colored_message(f"Timeout: {timeout}s | Threads: {max_workers} | Protocol: {protocol.upper()}")
    print_colored_message(f"{'=' * 60}")

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_port, ip_address, port, protocol, timeout): port
                for port in range(start_port, end_port + 1)
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(port)
                        print_colored_message(f"→ Port {port}/{protocol.upper()} ouvert")
                except Exception as e:
                    logging.warning(f"Erreur sur le port {port}: {str(e)}")

        if open_ports:
            print_colored_message(f"\n{'=' * 60}")
            print_colored_message(f"SCAN TERMINÉ - {len(open_ports)} ports ouverts")
            print_colored_message(f"{'=' * 60}")
            for port in sorted(open_ports):
                print_colored_message(f"Port {port}/{protocol.upper()} - OUVERT")
        else:
            print_colored_message("\nAucun port ouvert trouvé dans cette plage.")

    except KeyboardInterrupt:
        print_colored_message("\nScan interrompu par l'utilisateur")
    except Exception as e:
        logging.error(f"Erreur fatale lors du scan : {e}")
        print_colored_message(f"ERREUR: {str(e)}")

def scan_port(ip_address, port, protocol='tcp', timeout=1):
    """Scans a single port for the specified IP address and protocol."""
    sock = None
    try:
        if protocol.lower() == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol.lower() == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            return "Invalid protocol"
        sock.settimeout(timeout)
        if protocol.lower() == 'tcp':
            result = sock.connect_ex((ip_address, port))
        else:  # UDP doesn't use connect
            sock.sendto(b"Hello", (ip_address, port))
            result = 0  # Assume open if no error
        if result == 0:
            return port
        else:
            return None
    except socket.error as e:
        logging.error(f"Erreur lors de l'analyse du port {port}: {e}")
        return None
    finally:
        if sock:
            sock.close()


async def check_firewall(ip_address, port):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        commande = [
            "nmap",
            "-Pn",  # Traiter tous les hôtes comme étant en ligne
            "-p", str(port),
            ip_address
        ]
        resultat = subprocess.run(commande, capture_output=True, text=True, check=True)

        print_colored_message(f"\n{'=' * 60}\nVérification du pare-feu sur {ip_address}:{port}\n{'=' * 60}")
        print_colored_message(resultat.stdout)

    except subprocess.CalledProcessError as e:
        logging.error(f"Commande échouée avec l'erreur : {e}")
        print_colored_message(f"Commande échouée avec l'erreur : {e}")
    except FileNotFoundError:
        print_colored_message(
            "Commande nmap introuvable. Assurez-vous qu'elle est installée sur votre système.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la vérification du pare-feu : {e}")
        print_colored_message(f"Une erreur s'est produite lors de la vérification du pare-feu : {e}")

def check_vpn_proxy(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting,query"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        print_colored_message(f"\n{'=' * 60}\nVérification VPN/Proxy pour {ip_address}\n{'=' * 60}")

        if data['proxy']:
            print_colored_message("→ Détection d'un proxy.")
        else:
            print_colored_message("→ Aucun proxy détecté.")

        if data['hosting']:
            print_colored_message("→ Détection d'un service d'hébergement (VPS).")
        else:
            print_colored_message("→ Aucun service d'hébergement détecté.")
    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de la vérification VPN/Proxy : {e}")
        print_colored_message(f"Erreur HTTP lors de la vérification VPN/Proxy : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de la vérification VPN/Proxy : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")

def ping_ip(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        commande = ['ping', param, '1', ip_address]

        resultat = subprocess.run(commande, capture_output=True, text=True, check=True) # Check=True added to check error

        print_colored_message(f"\n{'=' * 60}\nPING {ip_address}\n{'=' * 60}")
        print_colored_message(resultat.stdout)

    except subprocess.CalledProcessError as e:
        logging.error(f"Commande échouée avec l'erreur : {e}")
        print_colored_message(f"Commande échouée avec l'erreur : {e}")
    except FileNotFoundError:
        print_colored_message("Commande ping introuvable. Assurez-vous qu'elle est installée sur votre système.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors du ping : {e}")
        print_colored_message(f"Une erreur s'est produite lors du ping : {e}")


def check_firewall(ip_address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            print_colored_message(f"Port {port} is open on {ip_address}")  # or any form of print
        else:
            print_colored_message(f"Port {port} is closed on {ip_address}")  # or any form of print
        sock.close()
    except socket.gaierror:
        print_colored_message("Hostname could not be resolved.") #Or any form of print
    except socket.error as e:
        print_colored_message(f"Could not connect to {ip_address}:{port}. Error: {e}")# Or any form of print


def test_ssl_tls_configuration(domain):
    try:
        # Supprimer le préfixe "http://" ou "https://" si présent
        if domain.startswith("http://"):
            domain = domain[7:]
        elif domain.startswith("https://"):
            domain = domain[8:]

        # Connexion sécurisée
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)

        # Obtenir les informations SSL/TLS du serveur
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()

        # Affichage des résultats de manière plus soignée
        print(f"\n{'=' * 60}")
        print(f"Configuration SSL/TLS pour : {domain}")
        print(f"{'=' * 60}\n")

        print(f"Certificat SSL/TLS :\n")
        print(f"{'=' * 60}")
        for key, value in ssl_info.items():
            print(f"{key}: {value}")
        print(f"{'=' * 60}")

        # Vérifier la version SSL/TLS utilisée
        ssl_version = conn.version()
        print(f"Version SSL/TLS utilisée : {ssl_version}\n")

        # Afficher des informations supplémentaires si disponibles
        print(f"Informations supplémentaires :\n")
        print(f"OCSP URL : {ssl_info.get('OCSP', 'Non disponible')}")
        print(f"CA Issuers : {ssl_info.get('caIssuers', 'Non disponible')}")
        print(f"CRL Distribution Points : {ssl_info.get('crlDistributionPoints', 'Non disponible')}")
        
        conn.close()
    except Exception as e:
        print(f"\nErreur lors de la connexion SSL/TLS pour {domain}: {str(e)}")



def check_http_headers(url):
    """ Vérifie les en-têtes HTTP du site """
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        issues = []

        if 'X-XSS-Protection' not in headers:
            issues.append("❌ Protection XSS absente")
        if 'X-Frame-Options' not in headers:
            issues.append("❌ Protection contre le Clickjacking absente")
        if 'Content-Security-Policy' not in headers:
            issues.append("❌ Content Security Policy absente")
        if 'Strict-Transport-Security' not in headers:
            issues.append("❌ HSTS absente (HTTPS mal sécurisé)")
        
        return issues if issues else ["✅ En-têtes de sécurité bien configurées"]
    except requests.RequestException:
        return ["⚠️ Impossible d'accéder au site"]

def detect_cms(url):
    """ Tente de détecter le CMS utilisé par le site """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        if "wp-content" in response.text:
            return "WordPress détecté"
        if "Joomla" in response.text or "com_content" in response.text:
            return "Joomla détecté"
        if soup.find("meta", {"name": "generator"}):
            return f"CMS détecté : {soup.find('meta', {'name': 'generator'})['content']}"
        
        return "Aucun CMS connu détecté"
    except requests.RequestException:
        return "⚠️ Impossible d'accéder au site"

def check_google_safe_browsing(url):
    """ Vérifie si le site est signalé comme dangereux par Google """
    safe_browsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={urllib.parse.quote(url)}"
    return f"🔍 Vérifie ici : {safe_browsing_url}"

def scan_site(url):
    print(f"🔎 Analyse de {url} en cours...")
    
    print("\n✅ [1] Vérification des en-têtes HTTP")
    for issue in check_http_headers(url):
        print(" -", issue)
    
    print("\n✅ [2] Détection du CMS")
    print(" -", detect_cms(url))
    
    print("\n✅ [3] Vérification Google Safe Browsing")
    print(" -", check_google_safe_browsing(url))       

