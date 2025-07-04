#!/usr/bin/env python3
"""
Module d'audit Apache HTTP Server
Basé sur CIS Apache HTTP Server 2.4 Benchmark

Ce module collecte les paramètres essentiels de configuration
du serveur Apache pour détecter les mauvaises pratiques
et vulnérabilités de sécurité.
"""

import os
import subprocess
import json
import re
import datetime
from pathlib import Path
import logging


class ApacheAudit:
    """Classe pour l'audit de sécurité d'Apache HTTP Server"""
    
    def __init__(self):
        """Initialisation de l'audit Apache"""
        self.results = {}
        self.checks_performed = 0
        self.apache_paths = self._detect_apache_paths()
        
    def _detect_apache_paths(self):
        """Détection automatique des chemins Apache"""
        paths = {
            'binary': None,
            'config_dir': None,
            'main_config': None,
            'modules_dir': None,
            'log_dir': None,
            'document_root': None
        }
        
        # Chemins possibles pour le binaire Apache
        possible_binaries = [
            '/usr/sbin/apache2',
            '/usr/sbin/httpd',
            '/usr/bin/apache2',
            '/usr/bin/httpd'
        ]
        
        for binary in possible_binaries:
            if os.path.exists(binary):
                paths['binary'] = binary
                break
                
        # Chemins possibles pour la configuration
        possible_configs = [
            '/etc/apache2/apache2.conf',
            '/etc/httpd/conf/httpd.conf',
            '/etc/apache2/httpd.conf',
            '/usr/local/apache2/conf/httpd.conf'
        ]
        
        for config in possible_configs:
            if os.path.exists(config):
                paths['main_config'] = config
                paths['config_dir'] = str(Path(config).parent)
                break
                
        # Répertoires de modules
        possible_modules = [
            '/usr/lib/apache2/modules',
            '/etc/httpd/modules',
            '/usr/lib64/httpd/modules'
        ]
        
        for modules_dir in possible_modules:
            if os.path.exists(modules_dir):
                paths['modules_dir'] = modules_dir
                break
                
        # Répertoires de logs
        possible_logs = [
            '/var/log/apache2',
            '/var/log/httpd',
            '/var/log/apache'
        ]
        
        for log_dir in possible_logs:
            if os.path.exists(log_dir):
                paths['log_dir'] = log_dir
                break
                
        return paths
        
    def run_command(self, command, shell=True):
        """Exécution sécurisée d'une commande système"""
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                'returncode': result.returncode,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {'returncode': -1, 'stdout': '', 'stderr': 'Timeout'}
        except Exception as e:
            return {'returncode': -1, 'stdout': '', 'stderr': str(e)}
            
    def check_apache_installation(self):
        """Vérification de l'installation Apache (CIS 1.1-1.3)"""
        logging.info("Vérification de l'installation Apache")
        
        installation_info = {}
        
        # Détection d'Apache
        installation_info['paths'] = self.apache_paths
        installation_info['apache_detected'] = self.apache_paths['binary'] is not None
        
        if not installation_info['apache_detected']:
            installation_info['status'] = 'Apache non détecté sur le système'
            self.checks_performed += 1
            return installation_info
            
        # Version d'Apache
        if self.apache_paths['binary']:
            result = self.run_command(f"{self.apache_paths['binary']} -v")
            installation_info['version'] = result['stdout']
            
        # Modules compilés
        if self.apache_paths['binary']:
            result = self.run_command(f"{self.apache_paths['binary']} -l")
            installation_info['compiled_modules'] = result['stdout']
            
        # Modules chargés
        if self.apache_paths['binary']:
            result = self.run_command(f"{self.apache_paths['binary']} -M")
            installation_info['loaded_modules'] = result['stdout']
            
        # Statut du service
        result = self.run_command("systemctl is-active apache2")
        if result['returncode'] != 0:
            result = self.run_command("systemctl is-active httpd")
            
        installation_info['service_status'] = result['stdout']
        
        self.checks_performed += 1
        return installation_info
        
    def check_apache_configuration(self):
        """Audit de la configuration Apache (CIS 2.1-2.9)"""
        logging.info("Audit de la configuration Apache")
        
        config_audit = {}
        
        if not self.apache_paths['main_config']:
            config_audit['status'] = 'Fichier de configuration principal non trouvé'
            self.checks_performed += 1
            return config_audit
            
        # Lecture du fichier de configuration principal
        try:
            with open(self.apache_paths['main_config'], 'r') as f:
                main_config = f.read()
            config_audit['main_config_content'] = main_config
        except Exception as e:
            config_audit['main_config_error'] = str(e)
            main_config = ""
            
        # Analyse des directives de sécurité importantes
        security_directives = {
            'ServerTokens': r'ServerTokens\\s+(\\S+)',
            'ServerSignature': r'ServerSignature\\s+(\\S+)',
            'DocumentRoot': r'DocumentRoot\\s+(\\S+)',
            'Directory': r'<Directory\\s+([^>]+)>',
            'AllowOverride': r'AllowOverride\\s+(\\S+)',
            'Options': r'Options\\s+([^\\n]+)',
            'User': r'User\\s+(\\S+)',
            'Group': r'Group\\s+(\\S+)',
            'Listen': r'Listen\\s+(\\S+)',
            'LoadModule': r'LoadModule\\s+(\\S+)\\s+(\\S+)'
        }
        
        directive_analysis = {}
        for directive, pattern in security_directives.items():
            matches = re.findall(pattern, main_config, re.IGNORECASE | re.MULTILINE)
            directive_analysis[directive] = matches
            
        config_audit['security_directives'] = directive_analysis
        
        # Vérification des permissions du fichier de configuration
        if os.path.exists(self.apache_paths['main_config']):
            stat_info = os.stat(self.apache_paths['main_config'])
            config_audit['config_file_permissions'] = {
                'mode': oct(stat_info.st_mode)[-3:],
                'owner_uid': stat_info.st_uid,
                'group_gid': stat_info.st_gid
            }
            
        # Fichiers de configuration inclus
        include_files = re.findall(r'Include(?:Optional)?\\s+(\\S+)', main_config, re.IGNORECASE)
        config_audit['included_files'] = include_files
        
        self.checks_performed += 1
        return config_audit
        
    def check_apache_modules(self):
        """Audit des modules Apache (CIS 3.1-3.12)"""
        logging.info("Audit des modules Apache")
        
        modules_audit = {}
        
        if not self.apache_paths['binary']:
            modules_audit['status'] = 'Binaire Apache non trouvé'
            self.checks_performed += 1
            return modules_audit
            
        # Modules chargés
        result = self.run_command(f"{self.apache_paths['binary']} -M")
        if result['returncode'] == 0:
            loaded_modules = result['stdout'].split('\\n')
            modules_audit['loaded_modules'] = [m.strip() for m in loaded_modules if m.strip()]
        else:
            modules_audit['loaded_modules'] = []
            
        # Modules potentiellement dangereux à surveiller
        dangerous_modules = [
            'mod_userdir',
            'mod_autoindex',
            'mod_status',
            'mod_info',
            'mod_cgi',
            'mod_include',
            'mod_dav',
            'mod_dav_fs'
        ]
        
        dangerous_found = []
        for module in dangerous_modules:
            if any(module in loaded for loaded in modules_audit.get('loaded_modules', [])):
                dangerous_found.append(module)
                
        modules_audit['potentially_dangerous_modules'] = dangerous_found
        
        # Modules de sécurité recommandés
        security_modules = [
            'mod_ssl',
            'mod_headers',
            'mod_rewrite',
            'mod_security',
            'mod_evasive'
        ]
        
        security_found = []
        for module in security_modules:
            if any(module in loaded for loaded in modules_audit.get('loaded_modules', [])):
                security_found.append(module)
                
        modules_audit['security_modules_found'] = security_found
        
        self.checks_performed += 1
        return modules_audit
        
    def check_ssl_configuration(self):
        """Audit de la configuration SSL/TLS (CIS 4.1-4.8)"""
        logging.info("Audit de la configuration SSL/TLS")
        
        ssl_audit = {}
        
        if not self.apache_paths['main_config']:
            ssl_audit['status'] = 'Configuration non accessible'
            self.checks_performed += 1
            return ssl_audit
            
        # Recherche des configurations SSL
        ssl_configs = []
        config_dir = Path(self.apache_paths['config_dir'])
        
        # Recherche dans le répertoire de configuration
        for config_file in config_dir.rglob('*.conf'):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    if 'SSLEngine' in content or 'SSLCertificateFile' in content:
                        ssl_configs.append(str(config_file))
            except:
                continue
                
        ssl_audit['ssl_config_files'] = ssl_configs
        
        # Analyse des directives SSL
        ssl_directives = {}
        for config_file in ssl_configs:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    
                ssl_patterns = {
                    'SSLEngine': r'SSLEngine\\s+(\\S+)',
                    'SSLProtocol': r'SSLProtocol\\s+([^\\n]+)',
                    'SSLCipherSuite': r'SSLCipherSuite\\s+([^\\n]+)',
                    'SSLCertificateFile': r'SSLCertificateFile\\s+(\\S+)',
                    'SSLCertificateKeyFile': r'SSLCertificateKeyFile\\s+(\\S+)',
                    'SSLHonorCipherOrder': r'SSLHonorCipherOrder\\s+(\\S+)',
                    'Header': r'Header\\s+([^\\n]+)'
                }
                
                file_directives = {}
                for directive, pattern in ssl_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    file_directives[directive] = matches
                    
                ssl_directives[config_file] = file_directives
                
            except Exception as e:
                ssl_directives[config_file] = {'error': str(e)}
                
        ssl_audit['ssl_directives'] = ssl_directives
        
        # Vérification des certificats SSL
        cert_files = []
        for config_file, directives in ssl_directives.items():
            if 'SSLCertificateFile' in directives:
                cert_files.extend(directives['SSLCertificateFile'])
                
        cert_info = {}
        for cert_file in cert_files:
            if os.path.exists(cert_file):
                result = self.run_command(f"openssl x509 -in {cert_file} -text -noout")
                cert_info[cert_file] = {
                    'exists': True,
                    'info': result['stdout'] if result['returncode'] == 0 else result['stderr']
                }
            else:
                cert_info[cert_file] = {'exists': False}
                
        ssl_audit['certificate_info'] = cert_info
        
        self.checks_performed += 1
        return ssl_audit
        
    def check_access_controls(self):
        """Audit des contrôles d'accès (CIS 5.1-5.13)"""
        logging.info("Audit des contrôles d'accès")
        
        access_audit = {}
        
        if not self.apache_paths['main_config']:
            access_audit['status'] = 'Configuration non accessible'
            self.checks_performed += 1
            return access_audit
            
        # Recherche des directives de contrôle d'accès
        config_files = [self.apache_paths['main_config']]
        config_dir = Path(self.apache_paths['config_dir'])
        
        # Ajout des fichiers de configuration inclus
        for config_file in config_dir.rglob('*.conf'):
            config_files.append(str(config_file))
            
        access_directives = {}
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    
                access_patterns = {
                    'Directory': r'<Directory\\s+([^>]+)>([^<]*)</Directory>',
                    'Location': r'<Location\\s+([^>]+)>([^<]*)</Location>',
                    'Files': r'<Files\\s+([^>]+)>([^<]*)</Files>',
                    'Require': r'Require\\s+([^\\n]+)',
                    'Allow': r'Allow\\s+from\\s+([^\\n]+)',
                    'Deny': r'Deny\\s+from\\s+([^\\n]+)',
                    'Order': r'Order\\s+([^\\n]+)'
                }
                
                file_directives = {}
                for directive, pattern in access_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                    file_directives[directive] = matches
                    
                access_directives[config_file] = file_directives
                
            except Exception as e:
                access_directives[config_file] = {'error': str(e)}
                
        access_audit['access_directives'] = access_directives
        
        # Vérification des fichiers .htaccess
        if self.apache_paths['config_dir']:
            result = self.run_command(f"find {self.apache_paths['config_dir']} -name '.htaccess' 2>/dev/null")
            access_audit['htaccess_files'] = result['stdout'].split('\\n') if result['stdout'] else []
            
        self.checks_performed += 1
        return access_audit
        
    def check_logging_configuration(self):
        """Audit de la configuration des logs (CIS 6.1-6.7)"""
        logging.info("Audit de la configuration des logs")
        
        logging_audit = {}
        
        # Répertoire des logs
        if self.apache_paths['log_dir']:
            logging_audit['log_directory'] = self.apache_paths['log_dir']
            
            # Fichiers de logs présents
            log_files = []
            for log_file in Path(self.apache_paths['log_dir']).glob('*'):
                if log_file.is_file():
                    stat_info = os.stat(log_file)
                    log_files.append({
                        'file': str(log_file),
                        'size': stat_info.st_size,
                        'permissions': oct(stat_info.st_mode)[-3:],
                        'owner_uid': stat_info.st_uid,
                        'group_gid': stat_info.st_gid
                    })
                    
            logging_audit['log_files'] = log_files
        else:
            logging_audit['log_directory'] = 'Non trouvé'
            logging_audit['log_files'] = []
            
        # Configuration des logs dans Apache
        if self.apache_paths['main_config']:
            try:
                with open(self.apache_paths['main_config'], 'r') as f:
                    content = f.read()
                    
                log_patterns = {
                    'ErrorLog': r'ErrorLog\\s+(\\S+)',
                    'CustomLog': r'CustomLog\\s+(\\S+)\\s+([^\\n]+)',
                    'LogLevel': r'LogLevel\\s+(\\S+)',
                    'LogFormat': r'LogFormat\\s+"([^"]+)"\\s+(\\S+)'
                }
                
                log_directives = {}
                for directive, pattern in log_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    log_directives[directive] = matches
                    
                logging_audit['log_directives'] = log_directives
                
            except Exception as e:
                logging_audit['log_directives'] = {'error': str(e)}
                
        self.checks_performed += 1
        return logging_audit
        
    def check_performance_security(self):
        """Audit des paramètres de performance et sécurité (CIS 7.1-7.12)"""
        logging.info("Audit des paramètres de performance et sécurité")
        
        performance_audit = {}
        
        if not self.apache_paths['main_config']:
            performance_audit['status'] = 'Configuration non accessible'
            self.checks_performed += 1
            return performance_audit
            
        try:
            with open(self.apache_paths['main_config'], 'r') as f:
                content = f.read()
                
            # Directives de performance et sécurité
            perf_patterns = {
                'Timeout': r'Timeout\\s+(\\d+)',
                'KeepAlive': r'KeepAlive\\s+(\\S+)',
                'MaxKeepAliveRequests': r'MaxKeepAliveRequests\\s+(\\d+)',
                'KeepAliveTimeout': r'KeepAliveTimeout\\s+(\\d+)',
                'LimitRequestBody': r'LimitRequestBody\\s+(\\d+)',
                'LimitRequestFields': r'LimitRequestFields\\s+(\\d+)',
                'LimitRequestFieldSize': r'LimitRequestFieldSize\\s+(\\d+)',
                'LimitRequestLine': r'LimitRequestLine\\s+(\\d+)',
                'ServerLimit': r'ServerLimit\\s+(\\d+)',
                'MaxRequestWorkers': r'MaxRequestWorkers\\s+(\\d+)'
            }
            
            perf_directives = {}
            for directive, pattern in perf_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                perf_directives[directive] = matches
                
            performance_audit['performance_directives'] = perf_directives
            
        except Exception as e:
            performance_audit['performance_directives'] = {'error': str(e)}
            
        self.checks_performed += 1
        return performance_audit
        
    def run_audit(self):
        """Exécution complète de l'audit Apache"""
        logging.info("Démarrage de l'audit Apache complet")
        
        audit_results = {
            'audit_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'audit_type': 'apache_security',
                'standards': ['CIS Apache HTTP Server 2.4 Benchmark'],
                'version': '1.0'
            }
        }
        
        # Exécution de tous les contrôles
        try:
            audit_results['apache_installation'] = self.check_apache_installation()
            
            # Si Apache n'est pas détecté, on arrête l'audit
            if not audit_results['apache_installation'].get('apache_detected', False):
                audit_results['audit_summary'] = {
                    'total_checks': self.checks_performed,
                    'completion_status': 'apache_not_found',
                    'message': 'Apache HTTP Server non détecté sur le système',
                    'completion_time': datetime.datetime.now().isoformat()
                }
                return audit_results
                
            audit_results['apache_configuration'] = self.check_apache_configuration()
            audit_results['apache_modules'] = self.check_apache_modules()
            audit_results['ssl_configuration'] = self.check_ssl_configuration()
            audit_results['access_controls'] = self.check_access_controls()
            audit_results['logging_configuration'] = self.check_logging_configuration()
            audit_results['performance_security'] = self.check_performance_security()
            
            audit_results['audit_summary'] = {
                'total_checks': self.checks_performed,
                'completion_status': 'success',
                'completion_time': datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Erreur lors de l'audit Apache : {e}")
            audit_results['audit_summary'] = {
                'total_checks': self.checks_performed,
                'completion_status': 'error',
                'error_message': str(e),
                'completion_time': datetime.datetime.now().isoformat()
            }
            
        return audit_results
        
    def save_results(self, results, output_file):
        """Sauvegarde des résultats d'audit"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logging.info(f"Résultats sauvegardés dans {output_file}")
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde : {e}")
            raise

