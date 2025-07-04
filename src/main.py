#!/usr/bin/env python3

import os
import sys
import datetime
import logging
from modules import linux_audit
from modules import apache_audit

# Configuration du logging
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'audit.log')
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
        choice = input("Veuillez choisir une option (1-4) : ")

        if choice == '1':
            logging.info("Option choisie : Audit système Linux.")
            print("Lancement de l'audit système Linux...")
            linux_audit.run_linux_audit()
            print("Audit système Linux terminé.")
        elif choice == '2':
            logging.info("Option choisie : Audit Apache.")
            print("Lancement de l'audit Apache...")
            apache_audit.run_apache_audit()
            print("Audit Apache terminé.")
        elif choice == '3':
            logging.info("Option choisie : Audit système Linux et Apache.")
            print("Lancement des deux audits...")
            linux_audit.run_linux_audit()
            apache_audit.run_apache_audit()
            print("Les deux audits sont terminés.")
        elif choice == '4':
            logging.info("Script d'audit terminé par l'utilisateur.")
            print("Quitting...")
            sys.exit(0)
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()


