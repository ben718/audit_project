
import subprocess
import os
import json
import logging

# Configuration du logging pour ce module
logger = logging.getLogger(__name__)

def run_command(command):
    """Exécute une commande shell et retourne sa sortie ou une erreur."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de la commande 
'{command}': {e.stderr.strip()}")
        return f"ERREUR: {e.stderr.strip()}"
    except FileNotFoundError:
        logger.error(f"Commande non trouvée : {command.split()[0]}")
        return f"ERREUR: Commande non trouvée : {command.split()[0]}"

def get_os_info():
    """Collecte les informations sur le système d'exploitation."""
    info = {
        "Nom du système d'exploitation": run_command("lsb_release -d | cut -f2"),
        "Version du noyau": run_command("uname -r"),
        "Architecture": run_command("uname -m"),
        "Uptime": run_command("uptime -p"),
        "Utilisateurs connectés": run_command("who").splitlines()
    }
    return info

def get_user_accounts():
    """Collecte les informations sur les comptes utilisateurs."""
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    users.append({
                        "Nom d'utilisateur": parts[0],
                        "UID": parts[2],
                        "GID": parts[3],
                        "Répertoire personnel": parts[5],
                        "Shell": parts[6]
                    })
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de /etc/passwd: {e}")
        users = [f"ERREUR: {e}"]
    return users

def get_network_config():
    """Collecte les informations sur la configuration réseau."""
    info = {
        "Interfaces réseau": run_command("ip -br a").splitlines(),
        "Routes": run_command("ip r").splitlines(),
        "Ports ouverts (TCP)": run_command("ss -tuln").splitlines()
    }
    return info

def get_installed_packages():
    """Collecte la liste des paquets installés (pour Debian/Ubuntu)."""
    packages = run_command("dpkg -l | grep ^ii").splitlines()
    return packages

def get_sudoers_file_content():
    """Récupère le contenu du fichier sudoers."""
    content = run_command("cat /etc/sudoers")
    return content

def run_linux_audit():
    """Exécute l'audit complet du système Linux."""
    logger.info("Début de l'audit système Linux.")
    audit_results = {
        "Date de l'audit": str(datetime.datetime.now()),
        "Informations OS": get_os_info(),
        "Comptes utilisateurs": get_user_accounts(),
        "Configuration réseau": get_network_config(),
        "Paquets installés": get_installed_packages(),
        "Contenu du fichier sudoers": get_sudoers_file_content()
    }

    output_file_txt = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reports', 'audit_systeme.txt')
    output_file_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reports', 'audit_systeme.json')

    with open(output_file_txt, "w") as f:
        for key, value in audit_results.items():
            f.write(f"{key}:\n")
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    f.write(f"  {sub_key}: {sub_value}\n")
            elif isinstance(value, list):
                for item in value:
                    f.write(f"  {item}\n")
            else:
                f.write(f"  {value}\n")
            f.write("\n")
    logger.info(f"Résultats de l'audit système enregistrés dans {output_file_txt}")

    with open(output_file_json, "w") as f:
        json.dump(audit_results, f, indent=4)
    logger.info(f"Résultats de l'audit système enregistrés dans {output_file_json}")
    logger.info("Fin de l'audit système Linux.")

import datetime # Importation ajoutée pour datetime dans linux_audit.py


