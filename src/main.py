#!/usr/bin/env python3

import os
import sys
import datetime
import logging
from modules import linux_audit
from modules import apache_audit

# Préparation du dossier de logs
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, 'audit.log')

# Configuration du logging
logging.basicConfig(filename=log_file, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def display_menu():
    """Affiche le menu interactif à l'utilisateur."""
    print("\n--- Menu d'Audit de Configuration ---")
    print("1. Lancer un audit système Linux uniquement")
    print("2. Lancer un audit Apache uniquement")
    print("3. Lancer les deux audits")
    print("4. Quitter")
    print("--------------------------------------")

def main():
    logging.info("Script d'audit démarré.")
    while True:
        display_menu()
        try:
            choice = input("Veuillez choisir une option (1-4) : ")
        except EOFError:
            print("\nEntrée interrompue. Fin du script.")
            logging.warning("Entrée interrompue par EOF.")
            sys.exit(1)

        if choice == '1':
            logging.info("Option choisie : Audit système Linux.")
            print("\n--------------------------------------")
            print("Lancement de l'audit système Linux...")
            linux_audit.run_linux_audit()
            print("Audit système Linux terminé.")
        elif choice == '2':
            logging.info("Option choisie : Audit Apache.")
            print("\n--------------------------------------")
            print("Lancement de l'audit Apache...")
            apache_audit.run_apache_audit()
            print("Audit Apache terminé.")
        elif choice == '3':
            logging.info("Option choisie : Audit système Linux et Apache.")
            print("\n--------------------------------------")
            print("Lancement des deux audits...")
            linux_audit.run_linux_audit()
            apache_audit.run_apache_audit()
            print("Les deux audits sont terminés.")
        elif choice == '4':
            logging.info("Script d'audit terminé par l'utilisateur.")
            print("Fin du script. Au revoir.")
            for handler in logging.root.handlers:
                handler.flush()
            sys.exit(0)
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
