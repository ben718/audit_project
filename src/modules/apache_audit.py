import subprocess
import os
import json
import logging
import datetime

# Configuration du logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_command(command):
    """Exécute une commande shell et retourne sa sortie ou une erreur."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(
            f"Erreur lors de l'exécution de la commande '{command}': {e.stderr.strip()}"
        )
        return f"ERREUR: {e.stderr.strip()}"
    except FileNotFoundError:
        logger.error(f"Commande non trouvée : {command.split()[0]}")
        return f"ERREUR: Commande non trouvée : {command.split()[0]}"

def find_apache_config_files():
    """Trouve les fichiers de configuration Apache."""
    config_files = run_command(
        'find /etc/apache2 -name "*.conf" -o -name "*.conf.d" -o -name ".htaccess"'
    ).splitlines()
    return [f for f in config_files if f]

def get_apache_version():
    """Récupère la version d'Apache."""
    return run_command(
        "apache2 -v | grep 'Server version' | cut -d: -f2"
    ).strip()

def get_apache_modules():
    """Liste les modules Apache activés."""
    modules = run_command("apache2ctl -M").splitlines()
    return [m.strip() for m in modules if m.strip() and not m.strip().startswith("Loaded Modules:")]

def get_apache_virtual_hosts():
    """Récupère les informations sur les Virtual Hosts."""
    vhosts = run_command("apache2ctl -S").splitlines()
    return [v.strip() for v in vhosts if v.strip()]

def get_apache_env_vars():
    """Récupère les variables d'environnement Apache."""
    env_vars = run_command(
        "apache2ctl -t -D DUMP_RUN_ENV"
    ).splitlines()
    return [e.strip(]()
