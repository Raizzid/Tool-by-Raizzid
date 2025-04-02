import os
import socket
import logging
import subprocess
from utils.utils import *

import whois
from dotenv import load_dotenv
import requests
import ipaddress
from utils.utils import print_colored_message, is_valid_ip, format_timezone

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

IPGEO_API_KEY = os.getenv("IPGEO_API_KEY", "votre_ipgeolocation_api_key")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "votre_abuseipdb_api_key")
ABSTRACTAPI_KEY = os.getenv("ABSTRACT_API_KEY", "votre_abstract_key")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "VOTRE_CLE_API_VIRUSTOTAL")
VULNERS_API_URL = os.getenv("VULNERS_API_URL")


# --- Fonctions d'analyse d'adresses IP ---
def get_ip_information(ip_address):
    if not is_valid_ip(ip_address):
        malvaillant("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        # Requête à l'API pour obtenir les informations sur l'IP
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={IPGEO_API_KEY}&ip={ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Lève une exception pour les erreurs HTTP
        data = response.json()

        # Affichage des informations IP
        print_colored_message(f"\n{'=' * 60}\nInformations IP pour {ip_address}\n{'=' * 60}")
        
        ip_info = {
            "Adresse IP": data.get("ip", "Non disponible"),
            "Continent": f"{data.get('continent_name', 'Non disponible')} ({data.get('continent_code', 'Non disponible')})",
            "Pays": f"{data.get('country_name', 'Non disponible')} ({data.get('country_code3', 'Non disponible')})",
            "Région": data.get("state_prov", "Non disponible"),
            "Ville": data.get("city", "Non disponible"),
            "Code Postal": data.get("zipcode", "Non disponible"),
            "Latitude": data.get("latitude", "Non disponible"),
            "Longitude": data.get("longitude", "Non disponible"),
            "Fuseau Horaire": format_timezone(data.get('time_zone', 'Non disponible')),
            "Fournisseur d'accès": data.get("isp", "Non disponible"),
            "Organisation": data.get("organization", "Non disponible"),
            "Domaine": data.get("domain", "Non disponible"),
            "ASN": data.get("asn", "Non disponible"),
            "Altitude": data.get("altitude", "Non disponible"),
            "Niveau de menace (TOR)": data.get("threat", {}).get("is_tor", "Non disponible")
        }

        # Afficher chaque clé et valeur des informations
        for key, value in ip_info.items():
            print_colored_message(f"{key}: {value}")

    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de la récupération des informations IP : {e}")
        print_colored_message(f"Erreur HTTP lors de la récupération des informations IP : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de la récupération des informations IP : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")


def calculer_sous_reseau(adresse_ip_cidr):
    try:
        reseau = ipaddress.ip_network(adresse_ip_cidr, strict=False)
        print_colored_message(f"\n{'=' * 60}\nCalculateur de Sous-réseaux pour {adresse_ip_cidr}\n{'=' * 60}")
        print_colored_message(f"Adresse Réseau: {reseau.network_address}")
        print_colored_message(f"Adresse de Diffusion: {reseau.broadcast_address}")
        print_colored_message(f"Nombre Total d'Adresses: {reseau.num_addresses}")
        if reseau.num_addresses > 1:
            print_colored_message(f"Première Adresse Utilisable: {reseau[1]}")
            print_colored_message(f"Dernière Adresse Utilisable: {reseau[-2]}")
        else:
            print_colored_message("Aucune adresse utilisable dans ce sous-réseau.")
        print_colored_message(f"Masque de Sous-réseau: {reseau.netmask}")
        print_colored_message(f"Masque Wildcard: {reseau.hostmask}")
    except ipaddress.AddressValueError:
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X/XX")
    except ipaddress.NetmaskValueError:
        print_colored_message("Masque de sous-réseau invalide. Format attendu : X.X.X.X/XX (0-32)")
    except ValueError:
        print_colored_message("Format CIDR invalide. Utilisez X.X.X.X/XX.")

def convert_ip_format(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    octets = ip_address.split('.')
    binaire_octets = [bin(int(octet))[2:].zfill(8) for octet in octets]
    hex_octets = [hex(int(octet))[2:].zfill(2) for octet in octets]

    adresse_binaire = "".join(binaire_octets)
    adresse_hexadecimal = "".join(hex_octets)

    print_colored_message(f"\n{'=' * 60}\nConversion IP pour {ip_address}\n{'=' * 60}")
    print_colored_message(f"Adresse IP en binaire : {adresse_binaire}")
    print_colored_message(f"Adresse IP en hexadécimal : {adresse_hexadecimal}")

def reverse_dns_lookup(ip_address, dns_server=None):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        command = ['nslookup', ip_address]
        if dns_server:
            command.append(dns_server)

        result = subprocess.run(command, capture_output=True, text=True)

        print_colored_message(f"\n{'=' * 60}\nREVERSE DNS LOOKUP {ip_address}\n{'=' * 60}")
        print(result.stdout)

    except subprocess.CalledProcessError as cpe:
        logging.error(f"Commande échouée avec l'erreur : {cpe}")
        print_colored_message(f"Commande échouée avec l'erreur : {cpe}")
    except FileNotFoundError:
        print_colored_message("Commande nslookup introuvable. Assurez-vous qu'elle est installée sur votre système.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors du reverse DNS lookup : {e}")
        print_colored_message(f"Une erreur s'est produite lors du reverse DNS lookup : {e}")

def whois_lookup(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        result = whois.whois(ip_address)

        print_colored_message(f"\n{'=' * 60}\nWHOIS LOOKUP {ip_address}\n{'=' * 60}")

        if result:
            for key, value in result.items():
                if value:
                    if isinstance(value, list):
                        for item in value:
                            print_colored_message(f"{key}: {item}")
                    else:
                        print_colored_message(f"{key}: {value}")
                else:
                    print_colored_message("Aucune information WHOIS trouvée pour l'adresse IP.")

    except whois.parser.PywhoisError as e:
        logging.error(f"Échec de la recherche WHOIS : {e}")
        print_colored_message(f"Échec de la recherche WHOIS : {e}")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors du WHOIS lookup : {e}")
        print_colored_message(f"Une erreur s'est produite lors du WHOIS lookup : {e}")

def blacklist_check(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        print_colored_message(f"\n{'=' * 60}\nVérification de liste noire pour {ip_address}\n{'=' * 60}")
        if data['data']['totalReports'] > 0:
            print_colored_message(
                f"L'adresse IP {ip_address} a été signalée {data['data']['totalReports']} fois.")
            print_colored_message(f"Dernier rapport: {data['data']['lastReportedAt']}")
        else:
            print_colored_message(f"L'adresse IP {ip_address} n'a pas été signalée.")

    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de la vérification de la liste noire : {e}")
        print_colored_message(f"Erreur HTTP lors de la vérification de la liste noire : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de la vérification de la liste noire : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")

def asn_info(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        url = f"https://api.bgpview.io/asn/prefix/{ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        print_colored_message(f"\n{'=' * 60}\nInformations ASN pour {ip_address}\n{'=' * 60}")

        if data['status'] == 'ok' and data['data']:
            asn_info = {
                "ASN": data['data']['asn'],
                "Nom": data['data']['name'],
                "Pays": data['data']['country_code'],
                "Description": data['data']['description'],
                "Prefixes": data['data']['prefixes']
            }

            for key, value in asn_info.items():
                print_colored_message(f"{key}: {value}")

        else:
            print_colored_message("Aucune information ASN trouvée pour cette adresse IP.")

    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de la récupération des informations ASN : {e}")
        print_colored_message(f"Erreur HTTP lors de la récupération des informations ASN : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de la récupération des informations ASN : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")

def dns_records(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        result = socket.gethostbyaddr(ip_address)

        print_colored_message(f"\n{'=' * 60}\nEnregistrements DNS pour {ip_address}\n{'=' * 60}")
        print_colored_message(f"Nom d'hôte : {result[0]}")
        print_colored_message(f"Alias : {result[1]}")
        print_colored_message(f"Adresses IP : {result[2]}")

    except socket.herror as e:
        logging.error(f"Erreur lors de la recherche DNS : {e}")
        print_colored_message(f"Erreur lors de la recherche DNS : {e}")
    except socket.gaierror as e:
        logging.error(f"Erreur d'adresse : {e}")
        print_colored_message(f"Erreur d'adresse : {e}")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la récupération des enregistrements DNS : {e}")
        print_colored_message(f"Une erreur s'est produite lors de la récupération des enregistrements DNS : {e}")