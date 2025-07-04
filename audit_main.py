#!/usr/bin/env python3
"""
Script d'audit de sécurité pour serveur Linux et Apache
Module principal avec menu interactif

Auteur: Projet YNOV - Module Scripting 2024-2025
Date: Juillet 2025
Version: 1.0

Ce script permet d'effectuer des audits de sécurité basés sur :
- CIS Benchmarks pour Ubuntu Linux
- CIS Benchmarks pour Apache HTTP Server
- Recommandations ANSSI (ANSSI-BP-028)
"""

import os
import sys
import logging
import datetime
from pathlib import Path

# Import des modules d'audit
try:
    from audit_system import SystemAudit
    from audit_apache import ApacheAudit
except ImportError as e:
    print(f"Erreur d'import des modules d'audit : {e}")
    print("Assurez-vous que les fichiers audit_system.py et audit_apache.py sont présents.")
    sys.exit(1)


class AuditManager:
    """Gestionnaire principal des audits de sécurité"""
    
    def __init__(self):
        """Initialisation du gestionnaire d'audit"""
        self.setup_logging()
        self.system_audit = SystemAudit()
        self.apache_audit = ApacheAudit()
        
        # Création du répertoire de sortie
        self.output_dir = Path("audit_results")
        self.output_dir.mkdir(exist_ok=True)
        
        logging.info("=== DÉBUT DE L'AUDIT DE SÉCURITÉ ===")
        logging.info(f"Date et heure : {datetime.datetime.now()}")
        
    def setup_logging(self):
        """Configuration du système de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('audit.log', mode='w', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
    def display_menu(self):
        """Affichage du menu principal"""
        print("\n" + "="*60)
        print("    AUDIT DE SÉCURITÉ LINUX/APACHE")
        print("    Basé sur CIS Benchmarks et ANSSI-BP-028")
        print("="*60)
        print("\nOptions disponibles :")
        print("1. Lancer un audit système uniquement")
        print("2. Lancer un audit Apache uniquement") 
        print("3. Lancer les deux audits")
        print("4. Quitter")
        print("-"*60)
        
    def run_system_audit(self):
        """Exécution de l'audit système Linux"""
        print("\n🔍 Démarrage de l'audit système Linux...")
        logging.info("Début de l'audit système Linux")
        
        try:
            results = self.system_audit.run_audit()
            
            # Sauvegarde des résultats
            output_file = self.output_dir / "audit_systeme.json"
            self.system_audit.save_results(results, output_file)
            
            print(f"✅ Audit système terminé. Résultats sauvegardés dans : {output_file}")
            logging.info(f"Audit système terminé avec succès - {len(results)} contrôles effectués")
            
            return results
            
        except Exception as e:
            error_msg = f"Erreur lors de l'audit système : {e}"
            print(f"❌ {error_msg}")
            logging.error(error_msg)
            return None
            
    def run_apache_audit(self):
        """Exécution de l'audit Apache"""
        print("\n🔍 Démarrage de l'audit Apache...")
        logging.info("Début de l'audit Apache")
        
        try:
            results = self.apache_audit.run_audit()
            
            # Sauvegarde des résultats
            output_file = self.output_dir / "audit_apache.json"
            self.apache_audit.save_results(results, output_file)
            
            print(f"✅ Audit Apache terminé. Résultats sauvegardés dans : {output_file}")
            logging.info(f"Audit Apache terminé avec succès - {len(results)} contrôles effectués")
            
            return results
            
        except Exception as e:
            error_msg = f"Erreur lors de l'audit Apache : {e}"
            print(f"❌ {error_msg}")
            logging.error(error_msg)
            return None
            
    def run_complete_audit(self):
        """Exécution des deux audits"""
        print("\n🔍 Démarrage de l'audit complet (Système + Apache)...")
        logging.info("Début de l'audit complet")
        
        system_results = self.run_system_audit()
        apache_results = self.run_apache_audit()
        
        if system_results is not None and apache_results is not None:
            print("\n✅ Audit complet terminé avec succès !")
            logging.info("Audit complet terminé avec succès")
        else:
            print("\n⚠️  Audit complet terminé avec des erreurs")
            logging.warning("Audit complet terminé avec des erreurs")
            
    def run(self):
        """Boucle principale du programme"""
        try:
            while True:
                self.display_menu()
                
                try:
                    choice = input("\nVeuillez choisir une option (1-4) : ").strip()
                except KeyboardInterrupt:
                    print("\n\nArrêt demandé par l'utilisateur.")
                    break
                    
                if choice == "1":
                    self.run_system_audit()
                elif choice == "2":
                    self.run_apache_audit()
                elif choice == "3":
                    self.run_complete_audit()
                elif choice == "4":
                    print("\nAu revoir !")
                    break
                else:
                    print("❌ Option invalide. Veuillez choisir entre 1 et 4.")
                    
                input("\nAppuyez sur Entrée pour continuer...")
                
        except Exception as e:
            error_msg = f"Erreur critique dans le programme principal : {e}"
            print(f"❌ {error_msg}")
            logging.critical(error_msg)
        finally:
            logging.info("=== FIN DE L'AUDIT DE SÉCURITÉ ===")


def main():
    """Point d'entrée principal du programme"""
    print("Initialisation du système d'audit...")
    
    # Vérification des privilèges
    if os.geteuid() != 0:
        print("⚠️  Attention : Ce script nécessite des privilèges administrateur pour certains contrôles.")
        print("   Certaines vérifications pourraient être limitées.")
        
    try:
        audit_manager = AuditManager()
        audit_manager.run()
    except KeyboardInterrupt:
        print("\n\nArrêt du programme.")
    except Exception as e:
        print(f"❌ Erreur fatale : {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

