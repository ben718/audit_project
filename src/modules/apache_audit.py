
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

def find_apache_config_files():
    """Trouve les fichiers de configuration Apache."""
    config_files = run_command("find /etc/apache2 -name \"*.conf\" -o -name \"*.conf.d\" -o -name \"*.htaccess\"").splitlines()
    return [f for f in config_files if f]

def get_apache_version():
    """Récupère la version d'Apache."""
    return run_command("apache2 -v | grep \"Server version\" | cut -d: -f2").strip()

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
    env_vars = run_command("apache2ctl -t -D DUMP_VHOSTS -D DUMP_RUN_DUMP_ENV").splitlines()
    return [e.strip() for e in env_vars if e.strip() and "Apache/" not in e and "ServerRoot" not in e]

def run_apache_audit():
    """Exécute l'audit complet du serveur Apache."""
    logger.info("Début de l'audit Apache.")
    audit_results = {
        "Date de l'audit": str(datetime.datetime.now()),
        "Version Apache": get_apache_version(),
        "Fichiers de configuration trouvés": find_apache_config_files(),
        "Modules Apache activés": get_apache_modules(),
        "Virtual Hosts": get_apache_virtual_hosts(),
        "Variables d'environnement Apache": get_apache_env_vars()
    }

    output_file_txt = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reports', 'audit_apache.txt')
    output_file_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reports', 'audit_apache.json')

    with open(output_file_txt, "w") as f:
        for key, value in audit_results.items():
            f.write(f"{key}:\n")
            if isinstance(value, list):
                for item in value:
                    f.write(f"  {item}\n")
            else:
                f.write(f"  {value}\n")
            f.write("\n")
    logger.info(f"Résultats de l'audit Apache enregistrés dans {output_file_txt}")

    with open(output_file_json, "w") as f:
        json.dump(audit_results, f, indent=4)
    logger.info(f"Résultats de l'audit Apache enregistrés dans {output_file_json}")
    logger.info("Fin de l'audit Apache.")

import datetime # Importation ajoutée pour datetime dans apache_audit.py


