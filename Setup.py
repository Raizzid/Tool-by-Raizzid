import os
import sys
import subprocess
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def install_requirements():
    """
    Installe les dépendances listées dans requirements.txt.
    """
    if not os.path.exists("requirements.txt"):
        logging.error("Le fichier requirements.txt est introuvable.")
        sys.exit(1)

    try:
        logging.info("Mise à jour de pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        logging.info("Installation des dépendances...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        
        logging.info("Installation terminée.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Échec de l'installation des dépendances : {e}")
        sys.exit(1)

def execute_main():
    """
    Exécute le fichier principal main.py après l'installation.
    """
    if not os.path.exists("main.py"):
        logging.error("Le fichier main.py est introuvable.")
        sys.exit(1)

    try:
        logging.info("Lancement du programme principal...")
        subprocess.run([sys.executable, "main.py"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Échec du lancement du programme principal : {e}")
        sys.exit(1)

if __name__ == "__main__":
    logging.info("Détection du système d'exploitation...")
    if os.name == 'nt':
        logging.info("Système détecté : Windows.")
    else:
        logging.info("Système détecté : Linux/Unix.")
    
    install_requirements()
    execute_main()
