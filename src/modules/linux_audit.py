import subprocess
import os
import json
import logging
import datetime  # Importé en haut pour être disponible partout

# Configuration du logging pour ce module
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_command(command):
    """Exécute une commande shell et retourne sa sortie ou une erreur."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de la commande '{command}': {e.stderr.strip()}")
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
        "Ports ouverts (TCP
