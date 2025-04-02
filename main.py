import os
import logging
import datetime
import json
import matplotlib.pyplot as plt
import logging
import socket
import requests
import threading
from queue import Queue

from pystyle import Colorate, Colors, Center
from utils.utils import *
from commands.ip_commands import *
from commands.network_commands import *
from commands.tools_commands import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def worker(domain, queue, found_subdomains, lock):
    while not queue.empty():
        subdomain = queue.get()
        subdomain_url = f"{subdomain}.{domain}"

        # Vérification DNS avant d'envoyer des requêtes HTTP
        try:
            socket.gethostbyname(subdomain_url)
        except socket.gaierror:
            queue.task_done()
            continue

        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain_url}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    with lock:
                        found_subdomains.append(url)
                        print_colored_message(f"✅ Sous-domaine actif : {url}")
                    break  # Pas besoin de tester HTTPS si HTTP fonctionne
            except requests.RequestException:
                continue
        queue.task_done()

def subdomain_finder(domain):
    logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")
    print_colored_message(f"🔍 Recherche massive de sous-domaines pour {domain} ...")

    subdomains = [
        # Services généraux
        "www", "mail", "ftp", "webmail", "smtp", "imap", "pop", "vpn", "dev", "test", "staging", "prod",
        "admin", "portal", "secure", "static", "images", "support", "download", "demo", "git", "ci", "console",
        "analytics", "docs", "status", "forum", "help", "contact", "partners", "careers", "members", "client",
        "service", "reports", "app", "m", "mailserver", "testserver", "private", "privateftp", "db", "video",
        "files", "assets", "beta", "testsite", "web", "store", "cms", "backup", "content", "dashboard", "panel",
        "intranet", "management", "calendar", "customer", "uploads", "tickets", "devops", "jira", "gitlab",
        "gitbucket", "workspace", "mailinglist", "appstore", "feedback", "helpdesk", "profile", "newsroom",
        "backend", "services", "monitoring", "notifications", "payroll", "policy", "remote", "project",
        "platform", "release", "integration", "ad", "event", "tracking", "search", "account", "company",
        "media", "storefront", "teams", "map", "login", "group", "feeds", "file", "distribution", "catalog",
        "proxy", "database", "supportportal", "updates", "monitor", "inventory", "crm", "internal", "finance",
        "hr", "adminpanel", "authentication", "gateway", "billing", "cdn", "devportal", "directory",
        "email", "secureemail", "cloud", "edge", "firewall", "audit", "metrics", "registration", "newsletter",
        
        # Variantes et combinaisons
        "dev1", "dev2", "test1", "test2", "staging1", "staging2", "beta1", "beta2", "sandbox", "preprod", "qa",
        "mobile", "ios", "android", "api", "api1", "api2", "apiv1", "apiv2", "gateway-api", "booking", "careers",
        "catalogue", "cart", "checkout", "community", "conference", "education", "elearning", "enterprise",
        "forum", "global", "info", "it", "legal", "marketing", "network", "operations", "partners", "password",
        "payment", "payments", "pos", "press", "pricing", "privacy", "product", "registration", "resources",
        "review", "sales", "serviceportal", "settings", "social", "solution", "staff", "stats", "subscription",
        "survey", "training", "transport", "uploader", "user", "vendor", "warehouse", "webshop", "workflow",
        "shop", "crm-dev", "statuspage", "online", "checkout", "offers", "discounts", "chat", "messaging",
        "live", "feedback", "docs", "sso", "idp", "admin-login", "admin-portal", "secure-login", "client-portal",
        "customer-service", "api-gateway", "dev-environment", "uat", "vpn1", "vpn2", "proxy1", "proxy2",
        "server1", "server2", "cdn1", "cdn2", "backup1", "backup2", "node1", "node2", "edge1", "edge2",
        "internal-tools", "employee-portal", "help-center", "docs-api", "download-center", "dev-backend",
        "frontend", "backend-services", "payment-gateway", "auth", "oauth", "auth2", "auth-v1", "auth-v2",
        "customer-login", "user-dashboard", "admin-dashboard", "shop-secure", "checkout-secure", "store-api",
        "store-internal", "static-content", "image-cdn", "asset-server", "static-serve", "logistics", "tracking-service",
    ]
    
    print_colored_message(f"\n{'=' * 60}\n🔎 Test de {len(subdomains)} sous-domaines pour {domain}\n{'=' * 60}")
    
    queue = Queue()
    for sub in subdomains:
        queue.put(sub)
    
    found_subdomains = []
    lock = threading.Lock()
    threads = []
    
    for _ in range(20):  # 20 threads
        thread = threading.Thread(target=worker, args=(domain, queue, found_subdomains, lock))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    print_colored_message(f"\n🔍 Recherche terminée : {len(subdomains)} sous-domaines testés.")
    if found_subdomains:
        print_colored_message(f"✅ {len(found_subdomains)} sous-domaines actifs trouvés !")
    else:
        print_colored_message("❌ Aucun sous-domaine actif trouvé.")
    
    return found_subdomains



def get_input(prompt, default=None, cast=str):
    """Récupère une entrée utilisateur avec gestion des valeurs par défaut et conversion de type."""
    user_input = input(prompt).strip()
    return cast(user_input) if user_input else default

def afficher_categories():
    """
    Affiche les catégories et options verticalement.
    """
    categories = {
        "🔍 IP Tools": {
            "1": "Ping IP",
            "2": "Informations IP",
            "3": "Traceroute",
            "4": "Reverse DNS Lookup",
            "5": "Scan de ports",
            "6": "Whois Lookup",
            "7": "Vérif. liste noire",
            "8": "Enregistrements DNS",
            "9": "Informations ASN"
        },
        "🔎 OSINT Tools": {
            "11": "Recherche sous-domaines",
            "12": "Récupérer EXIF",
            "21": "Recherche user",
            "22": "Conseils vie privée",
            "29": "Recherche infos téléphone",
            "30": "Tracker d'email",
            "31": "Recherche infos email"
        },
        "🛡️ Security Tools": {
            "10": "Simuler DOS",
            "13": "Vérif. pare-feu",
            "14": "Vérif. VPN/Proxy",
            "18": "Analyse VirusTotal (IP)",
            "19": "Analyse VirusTotal (Fichier)",
            "24": "Test Force Brute",
            "25": "Test SSL/TLS",
            "27": "Cracking MDP"
        },
        "💡 Other Tools": {
            "15": "Convertir IP binaire/hex",
            "16": "Calcul Sous-réseaux",
            "17": "Récupérer en-têtes HTTP",
            "20": "Ma propre IP",
            "23": "Infos réseau local",
            "26": "Conversion Base64",
            "28": "Détecter vulnérabilités",
            "32": "Base64 vers texte"
        },
        "❌ Quitter": {
            "q": "Quitter"
        }
    }

    for cat, opts in categories.items():
        print(Colorate.Horizontal(Colors.yellow_to_green, f"\n{cat}"))
        for key, val in opts.items():
            print(Colorate.Horizontal(Colors.blue_to_cyan, f"  [{key}] {val}"))

def afficher_titre():
    ascii_title = r"""
 ██▓ ███▄ ▄███▓ ▄▄▄       ███▄    █  ▒█████   ██▓    
▓██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██▒  ██▒▓██▒    
▒██▒▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒▒██░  ██▒▒██░    
░██░▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██   ██░▒██░    
░██░▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░░ ████▓▒░░██████▒
░▓  ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▒░▓  ░
 ▒ ░░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░
 ▒ ░░      ░     ░   ▒      ░   ░ ░ ░ ░ ░ ▒    ░ ░   
 ░         ░         ░  ░         ░     ░ ░      ░  ░                                              
    """
    return Colorate.Horizontal(Colors.red_to_blue, Center.XCenter(ascii_title))

def run_main():
    try:
        while True:
            clear_screen()
            # Affichage du titre (il reste visible pendant la boucle)
            print(afficher_titre())
            # Affichage du menu des catégories verticalement
            afficher_categories()

            choice = input("\n---> ").strip().lower()

            if choice == '1':
                ip_address = input("Entrez l'adresse IP pour Ping : ")
                ping_ip(ip_address)
            elif choice == '2':
                ip_address = input("Entrez l'adresse IP pour avoir des informations : ")
                get_ip_information(ip_address)
            elif choice == '3':
                ip_address = input("Entrez l'adresse IP pour Traceroute : ")
                traceroute_ip(ip_address)
            elif choice == '4':
                ip_address = input("Entrez l'adresse IP pour Reverse DNS Lookup : ")
                reverse_dns_lookup(ip_address)
            elif choice == '5':
                ip_address = input("Entrez l'adresse IP pour scan des Ports : ")
                start_port = int(input("Port de début (défaut 1) : ") or 1)
                end_port = int(input("Port de fin (défaut 1024) : ") or 1024)
                protocol = input("Entrez le protocole (tcp/udp, par défaut tcp) : ") or 'tcp'

                # Validation du protocole
                if protocol.lower() not in ['tcp', 'udp']:
                    print_colored_message("Protocole invalide. Utilisez 'tcp' ou 'udp'.")
                else:
                    # Lancer le scan de port
                    port_scan(ip_address, start_port, end_port, protocol)

            elif choice == '6':
                ip_address = input("Entrez l'adresse IP pour Whois Lookup : ")
                whois_lookup(ip_address)
            elif choice == '7':
                ip_address = input("Entrez l'adresse IP pour vérifier la blacklist : ")
                blacklist_check(ip_address)
            elif choice == '8':
                ip_address = input("Entrez l'adresse IP pour les DNS Records : ")
                dns_records(ip_address)
            elif choice == '9':
                ip_address = input("Entrez l'adresse IP pour ASN Info : ")
                asn_info(ip_address)
            elif choice == '10':
                ip_address = input("Entrez l'adresse IP pour DOS : ")
                num_requests = input("Nombre de requêtes (défaut 100) : ")
                num_requests = int(num_requests) if num_requests else 100  # Si rien n'est entré, le nombre de requêtes par défaut est 100

                # Exécute l'attaque DOS
                dos_attack(ip_address, num_requests)

                # Message d'avertissement
                print_colored_message("⚠️ Fonction à des fins d'apprentissage uniquement. Ne l'utilisez pas sans autorisation.")
            elif choice == '11':
                domain = input("Entrez le nom de domaine : ").strip()
                
                # Vérification basique du format du domaine
                if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
                    print("⚠️ Domaine invalide. Veuillez entrer un nom de domaine correct.")
                else:
                    subdomain_finder(domain)
            elif choice == '12':
                # Demander à l'utilisateur d'entrer le chemin de l'image
                image_path = input("🔹 Entrez le chemin de l'image (ex : /path/to/image.jpg) : ")

                # Vérifier si le fichier existe
                if not os.path.isfile(image_path):
                    print_colored_message("❌ Erreur : Le fichier spécifié n'existe pas. Veuillez vérifier le chemin.")
                else:
                    # Vérifier l'extension du fichier pour s'assurer que c'est une image
                    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']
                    if not any(image_path.lower().endswith(ext) for ext in valid_extensions):
                        print_colored_message("❌ Erreur : Ce fichier n'est pas une image valide. Veuillez entrer un fichier image.")
                    else:
                        # Appeler la fonction pour obtenir les informations EXIF de l'image
                        get_exif_info(image_path)
                get_exif_info(image_path)
            elif choice == '13':
                ip_address = input("Entrez l'adresse IP pour le pare-feu : ")
                port = int(input("Port (défaut 80) : ") or 80)
                check_firewall(ip_address, port)
            elif choice == '14':
                ip_address = input("Entrez l'adresse IP pour VPN/Proxy : ")
                check_vpn_proxy(ip_address)
            elif choice == '15':
                ip_address = input("Entrez l'adresse IP à convertir : ")
                convert_ip_format(ip_address)
            elif choice == '16':
                adresse_ip_cidr = input("Entrez l'adresse IP et CIDR (ex: 192.168.1.0/24) : ")
                calculer_sous_reseau(adresse_ip_cidr)
            elif choice == '17':
                url = input("Entrez l'URL du site web : ")
                recuperer_entetes_http(url)
            elif choice == '18':
                ip_address = input("Entrez l'adresse IP pour VirusTotal : ")
                analyser_ip_virustotal(ip_address)
            elif choice == '19':
                chemin_fichier = input("Entrez le chemin du fichier pour VirusTotal : ")
                analyser_fichier_virustotal(chemin_fichier)
            elif choice == '20':
                print_colored_message("Récupération de votre adresse IP...")
                adresse_ip_locale = trouver_mon_ip()
                if adresse_ip_locale != "Impossible de trouver l'adresse IP":
                    print_colored_message(f"Votre adresse IP est : {adresse_ip_locale}")
                    get_ip_information(adresse_ip_locale)
                else:
                    print_colored_message("Erreur lors de la récupération de l'IP.")
            elif choice == '21':
                print(Colorate.Horizontal(Colors.blue_to_red, "Entrez le nom d'utilisateur à rechercher : "), end="")
                username = input().strip()

                # Récupérer les résultats sous forme de dictionnaire
                resultats_recherche = rechercher_nom_utilisateur(username)

                if resultats_recherche:  # Vérifie que le dictionnaire n'est pas vide
                    print(Colorate.Horizontal(Colors.blue_to_purple, "\n[📊] Résultats de la recherche :"))

                    profils_trouves = []
                    total_sites = len(resultats_recherche)

                    # Parcours des résultats et ajout des profils trouvés
                    for site, resultat in resultats_recherche.items():
                        # Si un profil est trouvé, on ajoute son lien
                        if "✔" in resultat:
                            profils_trouves.append(f"{site}: {resultat.split(': ')[1]}")  # Ajoute juste le lien

                        # Détermination de la couleur en fonction du statut
                        if "✔" in resultat:
                            couleur = Colors.green
                        elif "⚠" in resultat:
                            couleur = Colors.yellow
                        elif "✘" in resultat:
                            couleur = Colors.red
                        else:
                            couleur = Colors.white

                        # Affichage du résultat coloré
                        print(Colorate.Color(couleur, f"{site}: {resultat}"))

                    # Affichage du résumé
                    print(Colorate.Horizontal(Colors.purple_to_blue, "\n[📊] Résumé de la recherche :"))
                    
                    # Affichage du nombre de profils trouvés
                    print(Colorate.Color(Colors.green, f"✔ Profils trouvés ({len(profils_trouves)}/{total_sites}) :"))
                    
                    # Si des profils ont été trouvés, on les affiche
                    if profils_trouves:
                        for profile in profils_trouves:
                            print(Colorate.Color(Colors.cyan, f"  - {profile}"))
                    else:
                        # Sinon, on affiche un message indiquant qu'aucun profil n'a été trouvé
                        print(Colorate.Color(Colors.red, "  Aucun profil trouvé."))

                    # Résumé des profils non trouvés
                    profils_non_trouves = [site for site, resultat in resultats_recherche.items() if "✘" in resultat]
                    if profils_non_trouves:
                        print(Colorate.Color(Colors.red, f"✘ Profils non trouvés ({len(profils_non_trouves)}/{total_sites}) :"))
                        for site in profils_non_trouves:
                            print(Colorate.Color(Colors.red, f"  - {site}"))
                    
                    # Résumé des profils avec des erreurs (par exemple, 429 ou 403)
                    profils_avec_erreur = [site for site, resultat in resultats_recherche.items() if "⚠" in resultat]
                    if profils_avec_erreur:
                        print(Colorate.Color(Colors.yellow, f"⚠ Profils avec erreurs ({len(profils_avec_erreur)}/{total_sites}) :"))
                        for site in profils_avec_erreur:
                            if "Profil privé" in resultats_recherche[site] or "inaccessibilité" in resultats_recherche[site]:
                                print(Colorate.Color(Colors.yellow, f"  - {site}: ⚠ Profil privé ou inaccessibilité pour des raisons de confidentialité"))
                            else:
                                print(Colorate.Color(Colors.yellow, f"  - {site}"))
                else:
                    # Si aucun résultat n'est retourné
                    print(Colorate.Color(Colors.red, "[❌] Aucune information trouvée ou erreur de connexion."))


            elif choice == '22':
                afficher_conseils_vie_privee()
            elif choice == '23':
                obtenir_infos_reseau_local()
            elif choice == '24':
                run_brute_force_attack()
            elif choice == '25':
                domain = input("Entrez le nom de domaine pour SSL/TLS : ")
                test_ssl_tls_configuration(domain)
            elif choice == '26':
                text = input("Entrez le texte pour Base64 : ")
                convert_text_to_base64(text)
            elif choice == '27':
                hashed_password = input("Entrez le mot de passe haché : ")
                hash_type = input("Type (md5, sha1, sha256) : ").strip().lower()
                dictionary_file = input("Chemin du fichier dictionnaire (défaut 'passwords.txt') : ") or 'passwords.txt'
                crack_password_hash(hashed_password, hash_type, dictionary_file)
            elif choice == '28':
                url = input("\n🔹 Entrez l'URL pour analyser les vulnérabilités : ")
                results = detect_vulnerabilities(url)

                # Ajouter un timestamp pour l'analyse
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                print("\n" + "="*50)
                print(f"🔍 ANALYSE DE SÉCURITÉ - {timestamp}")
                print("="*50 + "\n")

                if "error" in results:
                    print(f"❌ Erreur : {results['error']}\n")
                    retry = input("Souhaitez-vous réessayer l'analyse (O/N) ? ").strip().lower()
                    if retry == 'o':
                        continue  # Réessayer l'analyse si l'utilisateur souhaite
                else:
                    # Afficher un récapitulatif rapide
                    total_vulnerabilities = len(results["vulnerabilities"])
                    print(f"⚠️  Vulnérabilités détectées : {total_vulnerabilities}")

                    if total_vulnerabilities > 0:
                        print("⚠️ Voici les vulnérabilités trouvées :\n")
                        for vuln in results["vulnerabilities"]:
                            print(f"   - {vuln}")
                        print("\n" + "-"*50)
                    else:
                        print("✅ Aucune vulnérabilité détectée.\n")

                    if results["recommendations"]:
                        print("💡 Recommandations pour améliorer la sécurité :\n")
                        for reco in results["recommendations"]:
                            print(f"   - {reco}")
                        print("\n" + "="*50)

                    # Affichage du statut HTTP de la réponse (si possible)
                    if 'status_code' in results:
                        print(f"📊 Code HTTP de la réponse : {results.get('status_code', 'Non disponible')}")
                    print("="*50)

                    # Ajouter un enregistrement dans un fichier de log (par exemple, fichier .json)
                    log_filename = "vulnerability_scan_log.json"
                    log_data = {
                        "timestamp": timestamp,
                        "url": url,
                        "vulnerabilities": results["vulnerabilities"],
                        "recommendations": results["recommendations"],
                        "status_code": results.get('status_code', 'Non disponible'),
                    }

                    try:
                        with open(log_filename, 'a') as log_file:
                            json.dump(log_data, log_file, indent=4)
                            log_file.write("\n")  # Nouvelle ligne pour chaque entrée de log
                        print(f"📜 Résultats enregistrés dans le fichier '{log_filename}'.")
                    except Exception as e:
                        print(f"⚠️ Impossible d'enregistrer les résultats dans le fichier : {str(e)}")

                    # Option d'exportation des résultats en fichier texte
                    export_choice = input("Souhaitez-vous exporter les résultats dans un fichier texte (O/N) ? ").strip().lower()
                    if export_choice == 'o':
                        try:
                            export_filename = "scan_results.txt"
                            with open(export_filename, 'w') as file:
                                file.write(f"🔍 ANALYSE DE SÉCURITÉ - {timestamp}\n")
                                file.write("="*50 + "\n")
                                file.write(f"URL analysée : {url}\n")
                                file.write(f"Statut HTTP : {results.get('status_code', 'Non disponible')}\n\n")

                                file.write(f"🔹 Vulnérabilités détectées : {total_vulnerabilities}\n")
                                if total_vulnerabilities > 0:
                                    for vuln in results["vulnerabilities"]:
                                        file.write(f"   - {vuln}\n")
                                else:
                                    file.write("   Aucune vulnérabilité détectée.\n")

                                file.write("\n💡 Recommandations :\n")
                                for reco in results["recommendations"]:
                                    file.write(f"   - {reco}\n")

                            print(f"📂 Résultats exportés dans le fichier '{export_filename}'.")
                        except Exception as e:
                            print(f"⚠️ Impossible d'exporter les résultats : {str(e)}")

                    # Option de génération d'un graphique statistique sur les vulnérabilités
                    plot_choice = input("Souhaitez-vous voir un graphique des vulnérabilités détectées (O/N) ? ").strip().lower()
                    if plot_choice == 'o':
                        vuln_types = {}
                        for vuln in results["vulnerabilities"]:
                            vuln_type = vuln.split(" ")[0]  # Exemple : 'XSS', 'SQL', etc.
                            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

                        if vuln_types:
                            labels = list(vuln_types.keys())
                            values = list(vuln_types.values())
                            plt.bar(labels, values)
                            plt.title("Répartition des vulnérabilités détectées")
                            plt.xlabel("Type de vulnérabilité")
                            plt.ylabel("Nombre de fois")
                            plt.show()
                        else:
                            print("❌ Aucun graphique disponible - aucune vulnérabilité détectée.")
            elif choice == '29':
                phone_lookup()
            elif choice == '30':
                print("Lancement du tracker d'e-mail...")
                results = email_tracker()
                print(f"Résultats : {results}")
            elif choice == '31':
                email_lookup()
            elif choice == '32':
                base64_string = input("Entrez la chaîne Base64 à décoder : ")
                convert_base64_to_text(base64_string)
            elif choice == 'q':
                print_colored_message("Au revoir !")
                break
            else:
                print_colored_message("Option invalide. Veuillez réessayer.")

            input("\nAppuyez sur 'Entrée' pour continuer...")
    
    except Exception as e:
        print(f"Erreur inattendue : {str(e)}")
        input("\nAppuyez sur 'Entrée' pour quitter.")

if __name__ == "__main__":
    run_main()

