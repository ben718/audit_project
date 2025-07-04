#!/usr/bin/env python3
"""
Module d'audit système Linux
Basé sur CIS Ubuntu Linux Benchmark et ANSSI-BP-028

Ce module collecte les informations critiques de configuration
du système d'exploitation pour détecter les mauvaises pratiques
et points faibles potentiels.
"""

import os
import subprocess
import json
import pwd
import grp
import stat
import socket
import datetime
from pathlib import Path
import logging


class SystemAudit:
    """Classe pour l'audit de sécurité du système Linux"""
    
    def __init__(self):
        """Initialisation de l'audit système"""
        self.results = {}
        self.checks_performed = 0
        
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
            
    def check_system_info(self):
        """Collecte des informations système de base"""
        logging.info("Collecte des informations système de base")
        
        info = {}
        
        # Version du système
        result = self.run_command("lsb_release -a")
        if result['returncode'] == 0:
            info['os_release'] = result['stdout']
        else:
            # Fallback
            result = self.run_command("cat /etc/os-release")
            info['os_release'] = result['stdout']
            
        # Version du noyau
        result = self.run_command("uname -a")
        info['kernel_version'] = result['stdout']
        
        # Uptime
        result = self.run_command("uptime")
        info['uptime'] = result['stdout']
        
        # Architecture
        result = self.run_command("arch")
        info['architecture'] = result['stdout']
        
        self.checks_performed += 1
        return info
        
    def check_users_and_groups(self):
        """Audit des utilisateurs et groupes (ANSSI R1-R10)"""
        logging.info("Audit des utilisateurs et groupes")
        
        users_audit = {}
        
        # Utilisateurs avec UID 0 (root privileges)
        root_users = []
        for user in pwd.getpwall():
            if user.pw_uid == 0:
                root_users.append({
                    'name': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell
                })
                
        users_audit['root_users'] = root_users
        
        # Utilisateurs avec shell de connexion
        login_users = []
        valid_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/dash']
        for user in pwd.getpwall():
            if user.pw_shell in valid_shells:
                login_users.append({
                    'name': user.pw_name,
                    'uid': user.pw_uid,
                    'shell': user.pw_shell,
                    'home': user.pw_dir
                })
                
        users_audit['login_users'] = login_users
        
        # Comptes sans mot de passe
        result = self.run_command("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
        if result['returncode'] == 0 and result['stdout']:
            users_audit['users_without_password'] = result['stdout'].split('\n')
        else:
            users_audit['users_without_password'] = []
            
        # Groupes avec privilèges élevés
        privileged_groups = ['sudo', 'wheel', 'admin', 'root']
        group_members = {}
        for group_name in privileged_groups:
            try:
                group = grp.getgrnam(group_name)
                group_members[group_name] = list(group.gr_mem)
            except KeyError:
                group_members[group_name] = []
                
        users_audit['privileged_groups'] = group_members
        
        self.checks_performed += 1
        return users_audit
        
    def check_file_permissions(self):
        """Audit des permissions de fichiers critiques (ANSSI R11-R20)"""
        logging.info("Audit des permissions de fichiers critiques")
        
        permissions_audit = {}
        
        # Fichiers critiques à vérifier
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/gshadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/boot/grub/grub.cfg',
            '/etc/crontab'
        ]
        
        file_permissions = {}
        for file_path in critical_files:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                file_permissions[file_path] = {
                    'mode': oct(stat_info.st_mode)[-3:],
                    'owner_uid': stat_info.st_uid,
                    'group_gid': stat_info.st_gid,
                    'owner_name': pwd.getpwuid(stat_info.st_uid).pw_name,
                    'group_name': grp.getgrgid(stat_info.st_gid).gr_name
                }
            else:
                file_permissions[file_path] = {'status': 'file_not_found'}
                
        permissions_audit['critical_files'] = file_permissions
        
        # Fichiers avec permissions world-writable
        result = self.run_command("find /etc -type f -perm -002 2>/dev/null")
        if result['returncode'] == 0:
            permissions_audit['world_writable_etc'] = result['stdout'].split('\n') if result['stdout'] else []
        else:
            permissions_audit['world_writable_etc'] = []
            
        # Fichiers SUID/SGID
        result = self.run_command("find /usr /bin /sbin -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null")
        if result['returncode'] == 0:
            permissions_audit['suid_sgid_files'] = result['stdout'].split('\n') if result['stdout'] else []
        else:
            permissions_audit['suid_sgid_files'] = []
            
        self.checks_performed += 1
        return permissions_audit
        
    def check_network_configuration(self):
        """Audit de la configuration réseau (ANSSI R30-R40)"""
        logging.info("Audit de la configuration réseau")
        
        network_audit = {}
        
        # Ports ouverts
        result = self.run_command("ss -tuln")
        network_audit['listening_ports'] = result['stdout']
        
        # Configuration du pare-feu
        firewall_status = {}
        
        # UFW
        result = self.run_command("ufw status")
        firewall_status['ufw'] = {
            'status': result['stdout'],
            'available': result['returncode'] == 0
        }
        
        # iptables
        result = self.run_command("iptables -L -n")
        firewall_status['iptables'] = {
            'rules': result['stdout'],
            'available': result['returncode'] == 0
        }
        
        network_audit['firewall'] = firewall_status
        
        # Configuration IP forwarding
        result = self.run_command("sysctl net.ipv4.ip_forward")
        network_audit['ip_forwarding'] = result['stdout']
        
        # Configuration ICMP redirects
        result = self.run_command("sysctl net.ipv4.conf.all.accept_redirects")
        network_audit['icmp_redirects'] = result['stdout']
        
        # Interfaces réseau
        result = self.run_command("ip addr show")
        network_audit['network_interfaces'] = result['stdout']
        
        self.checks_performed += 1
        return network_audit
        
    def check_services_and_processes(self):
        """Audit des services et processus (ANSSI R21-R29)"""
        logging.info("Audit des services et processus")
        
        services_audit = {}
        
        # Services systemd actifs
        result = self.run_command("systemctl list-units --type=service --state=active --no-pager")
        services_audit['active_services'] = result['stdout']
        
        # Services activés au démarrage
        result = self.run_command("systemctl list-unit-files --type=service --state=enabled --no-pager")
        services_audit['enabled_services'] = result['stdout']
        
        # Processus en cours d'exécution
        result = self.run_command("ps aux --no-headers")
        services_audit['running_processes'] = result['stdout']
        
        # Services critiques à vérifier
        critical_services = ['ssh', 'cron', 'rsyslog', 'systemd-timesyncd']
        service_status = {}
        for service in critical_services:
            result = self.run_command(f"systemctl is-active {service}")
            service_status[service] = {
                'active': result['stdout'] == 'active',
                'status': result['stdout']
            }
            
        services_audit['critical_services'] = service_status
        
        self.checks_performed += 1
        return services_audit
        
    def check_kernel_parameters(self):
        """Audit des paramètres du noyau (ANSSI R41-R50)"""
        logging.info("Audit des paramètres du noyau")
        
        kernel_audit = {}
        
        # Paramètres de sécurité importants
        security_params = [
            'kernel.dmesg_restrict',
            'kernel.kptr_restrict',
            'kernel.yama.ptrace_scope',
            'net.ipv4.conf.all.log_martians',
            'net.ipv4.conf.all.send_redirects',
            'net.ipv4.conf.all.accept_source_route',
            'net.ipv4.tcp_syncookies',
            'fs.suid_dumpable'
        ]
        
        sysctl_values = {}
        for param in security_params:
            result = self.run_command(f"sysctl {param}")
            if result['returncode'] == 0:
                sysctl_values[param] = result['stdout']
            else:
                sysctl_values[param] = f"Error: {result['stderr']}"
                
        kernel_audit['security_parameters'] = sysctl_values
        
        # Modules du noyau chargés
        result = self.run_command("lsmod")
        kernel_audit['loaded_modules'] = result['stdout']
        
        # Configuration de la randomisation ASLR
        result = self.run_command("sysctl kernel.randomize_va_space")
        kernel_audit['aslr'] = result['stdout']
        
        self.checks_performed += 1
        return kernel_audit
        
    def check_logging_and_audit(self):
        """Audit de la configuration des logs et audit (ANSSI R51-R60)"""
        logging.info("Audit de la configuration des logs et audit")
        
        logging_audit = {}
        
        # Configuration rsyslog
        if os.path.exists('/etc/rsyslog.conf'):
            with open('/etc/rsyslog.conf', 'r') as f:
                logging_audit['rsyslog_config'] = f.read()
        else:
            logging_audit['rsyslog_config'] = "Configuration non trouvée"
            
        # Fichiers de logs présents
        log_files = []
        log_dirs = ['/var/log', '/var/log/auth.log', '/var/log/syslog', '/var/log/kern.log']
        for log_path in log_dirs:
            if os.path.exists(log_path):
                if os.path.isdir(log_path):
                    log_files.extend([str(p) for p in Path(log_path).glob('*') if p.is_file()])
                else:
                    log_files.append(log_path)
                    
        logging_audit['log_files'] = log_files
        
        # Configuration auditd si présent
        result = self.run_command("systemctl is-active auditd")
        logging_audit['auditd_status'] = result['stdout']
        
        if result['stdout'] == 'active':
            result = self.run_command("auditctl -l")
            logging_audit['audit_rules'] = result['stdout']
        else:
            logging_audit['audit_rules'] = "auditd non actif"
            
        self.checks_performed += 1
        return logging_audit
        
    def check_updates_and_packages(self):
        """Audit des mises à jour et packages (ANSSI R61-R69)"""
        logging.info("Audit des mises à jour et packages")
        
        updates_audit = {}
        
        # Packages installés
        result = self.run_command("dpkg -l")
        if result['returncode'] == 0:
            updates_audit['installed_packages'] = result['stdout']
        else:
            # Fallback pour autres distributions
            result = self.run_command("rpm -qa")
            updates_audit['installed_packages'] = result['stdout']
            
        # Mises à jour disponibles
        result = self.run_command("apt list --upgradable 2>/dev/null")
        if result['returncode'] == 0:
            updates_audit['available_updates'] = result['stdout']
        else:
            updates_audit['available_updates'] = "Impossible de vérifier les mises à jour"
            
        # Configuration des sources de packages
        if os.path.exists('/etc/apt/sources.list'):
            with open('/etc/apt/sources.list', 'r') as f:
                updates_audit['package_sources'] = f.read()
        else:
            updates_audit['package_sources'] = "Configuration non trouvée"
            
        # Packages de sécurité critiques
        security_packages = ['openssh-server', 'ufw', 'fail2ban', 'apparmor']
        package_status = {}
        for package in security_packages:
            result = self.run_command(f"dpkg -l {package}")
            package_status[package] = {
                'installed': result['returncode'] == 0,
                'info': result['stdout'].split('\n')[0] if result['stdout'] else ''
            }
            
        updates_audit['security_packages'] = package_status
        
        self.checks_performed += 1
        return updates_audit
        
    def run_audit(self):
        """Exécution complète de l'audit système"""
        logging.info("Démarrage de l'audit système complet")
        
        audit_results = {
            'audit_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'audit_type': 'system_security',
                'standards': ['CIS Ubuntu Linux Benchmark', 'ANSSI-BP-028'],
                'version': '1.0'
            }
        }
        
        # Exécution de tous les contrôles
        try:
            audit_results['system_info'] = self.check_system_info()
            audit_results['users_and_groups'] = self.check_users_and_groups()
            audit_results['file_permissions'] = self.check_file_permissions()
            audit_results['network_configuration'] = self.check_network_configuration()
            audit_results['services_and_processes'] = self.check_services_and_processes()
            audit_results['kernel_parameters'] = self.check_kernel_parameters()
            audit_results['logging_and_audit'] = self.check_logging_and_audit()
            audit_results['updates_and_packages'] = self.check_updates_and_packages()
            
            audit_results['audit_summary'] = {
                'total_checks': self.checks_performed,
                'completion_status': 'success',
                'completion_time': datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Erreur lors de l'audit système : {e}")
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

