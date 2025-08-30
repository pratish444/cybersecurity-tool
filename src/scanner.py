import nmap
import socket
import requests
import json
import sqlite3
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackSurfaceScanner:
    def __init__(self, db_path="data/results.db"):
        self.db_path = db_path
        self.nm = nmap.PortScanner()
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                port INTEGER,
                state TEXT,
                service TEXT,
                version TEXT,
                risk_level TEXT,
                description TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vulnerability_type TEXT,
                severity TEXT,
                description TEXT,
                recommendation TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def validate_target(self, target):
        """Validate if target is reachable"""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            logger.error(f"Target {target} is not reachable")
            return False
    
    def port_scan(self, target, port_range="1-1000"):
        """Perform port scan on target"""
        if not self.validate_target(target):
            return None
        
        logger.info(f"Starting port scan on {target}")
        
        try:
            # Perform nmap scan
            self.nm.scan(target, port_range, arguments='-sV -sC')
            
            results = []
            for host in self.nm.all_hosts():
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        
                        result = {
                            'target': target,
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        # Assess risk level
                        result['risk_level'] = self.assess_port_risk(port, result['service'])
                        result['description'] = self.get_port_description(port, result['service'])
                        
                        results.append(result)
            
            # Store results in database
            self.store_scan_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            return None
    
    def assess_port_risk(self, port, service):
        """Assess risk level based on port and service"""
        high_risk_ports = [21, 23, 53, 135, 139, 445, 1433, 1521, 3389]
        medium_risk_ports = [22, 25, 80, 110, 143, 993, 995]
        
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_port_description(self, port, service):
        """Get description for common ports"""
        port_descriptions = {
            21: "FTP - File Transfer Protocol (Unencrypted)",
            22: "SSH - Secure Shell",
            23: "Telnet - Unencrypted remote access",
            25: "SMTP - Simple Mail Transfer Protocol",
            53: "DNS - Domain Name System",
            80: "HTTP - Web server (Unencrypted)",
            110: "POP3 - Post Office Protocol",
            135: "Microsoft RPC",
            139: "NetBIOS Session Service",
            143: "IMAP - Internet Message Access Protocol",
            443: "HTTPS - Secure web server",
            445: "SMB - Server Message Block",
            993: "IMAPS - Secure IMAP",
            995: "POP3S - Secure POP3",
            1433: "MSSQL - Microsoft SQL Server",
            1521: "Oracle Database",
            3389: "RDP - Remote Desktop Protocol"
        }
        
        return port_descriptions.get(port, f"{service} service on port {port}")
    
    def check_misconfigurations(self, scan_results):
        """Check for common security misconfigurations"""
        vulnerabilities = []
        
        for result in scan_results:
            port = result['port']
            service = result['service']
            target = result['target']
            
            # Check for insecure services
            if port == 21 and result['state'] == 'open':
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_type': 'Insecure Service',
                    'severity': 'HIGH',
                    'description': 'FTP service detected - transmits data in clear text',
                    'recommendation': 'Disable FTP and use SFTP/SCP instead'
                })
            
            if port == 23 and result['state'] == 'open':
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_type': 'Insecure Service',
                    'severity': 'HIGH',
                    'description': 'Telnet service detected - unencrypted remote access',
                    'recommendation': 'Disable Telnet and use SSH instead'
                })
            
            if port == 22 and result['state'] == 'open':
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_type': 'Exposed Service',
                    'severity': 'MEDIUM',
                    'description': 'SSH service exposed to internet',
                    'recommendation': 'Configure SSH key-based auth, disable root login, change default port'
                })
            
            if port == 3389 and result['state'] == 'open':
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_type': 'High Risk Service',
                    'severity': 'HIGH',
                    'description': 'RDP service exposed - common brute force target',
                    'recommendation': 'Implement VPN access, enable NLA, use strong passwords'
                })
            
            if port in [135, 139, 445] and result['state'] == 'open':
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_type': 'Windows Service Exposure',
                    'severity': 'HIGH',
                    'description': f'Windows service on port {port} exposed',
                    'recommendation': 'Restrict access using firewall rules, disable if not needed'
                })
        
        # Store vulnerabilities
        self.store_vulnerabilities(vulnerabilities)
        
        return vulnerabilities
    
    def store_scan_results(self, results):
        """Store scan results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for result in results:
            cursor.execute('''
                INSERT INTO scan_results 
                (target, port, state, service, version, risk_level, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                result['target'],
                result['port'],
                result['state'],
                result['service'],
                result['version'],
                result['risk_level'],
                result['description']
            ))
        
        conn.commit()
        conn.close()
    
    def store_vulnerabilities(self, vulnerabilities):
        """Store vulnerabilities in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (target, vulnerability_type, severity, description, recommendation)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                vuln['target'],
                vuln['vulnerability_type'],
                vuln['severity'],
                vuln['description'],
                vuln['recommendation']
            ))
        
        conn.commit()
        conn.close()
    
    def get_scan_results(self, target=None):
        """Retrieve scan results from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if target:
            cursor.execute('SELECT * FROM scan_results WHERE target = ?', (target,))
        else:
            cursor.execute('SELECT * FROM scan_results ORDER BY scan_time DESC LIMIT 100')
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def get_vulnerabilities(self, target=None):
        """Retrieve vulnerabilities from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if target:
            cursor.execute('SELECT * FROM vulnerabilities WHERE target = ?', (target,))
        else:
            cursor.execute('SELECT * FROM vulnerabilities ORDER BY scan_time DESC')
        
        results = cursor.fetchall()
        conn.close()
        
        return results

# Example usage
if __name__ == "__main__":
    scanner = AttackSurfaceScanner()
    
    # Example scan
    target = input("Enter target IP/domain: ")
    results = scanner.port_scan(target)
    
    if results:
        print(f"\nScan completed for {target}")
        print(f"Found {len(results)} open ports")
        
        # Check for misconfigurations
        vulnerabilities = scanner.check_misconfigurations(results)
        print(f"Identified {len(vulnerabilities)} potential vulnerabilities")
        
        # Display results
        for result in results:
            print(f"Port {result['port']}: {result['service']} ({result['risk_level']} risk)")