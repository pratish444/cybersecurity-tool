import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import io
import base64
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAdvisoryGenerator:
    def __init__(self, db_path="data/results.db"):
        self.db_path = db_path
        self.cis_controls = self.load_cis_controls()
        self.nist_framework = self.load_nist_framework()
    
    def load_cis_controls(self):
        """Load CIS Critical Security Controls mapping"""
        return {
            'inventory': {
                'control': 'CIS Control 1',
                'title': 'Inventory and Control of Hardware Assets',
                'description': 'Actively manage all hardware devices on the network'
            },
            'software_inventory': {
                'control': 'CIS Control 2',
                'title': 'Inventory and Control of Software Assets', 
                'description': 'Actively manage all software on the network'
            },
            'secure_config': {
                'control': 'CIS Control 5',
                'title': 'Secure Configuration for Hardware and Software',
                'description': 'Establish secure configurations for all systems'
            },
            'access_control': {
                'control': 'CIS Control 6',
                'title': 'Maintenance, Monitoring and Analysis of Audit Logs',
                'description': 'Collect, manage and analyze audit logs'
            },
            'network_monitoring': {
                'control': 'CIS Control 12',
                'title': 'Boundary Defense',
                'description': 'Detect and prevent data exfiltration'
            }
        }
    
    def load_nist_framework(self):
        """Load NIST Cybersecurity Framework mapping"""
        return {
            'identify': {
                'function': 'Identify (ID)',
                'description': 'Develop organizational understanding to manage cybersecurity risk'
            },
            'protect': {
                'function': 'Protect (PR)',
                'description': 'Implement safeguards to ensure delivery of services'
            },
            'detect': {
                'function': 'Detect (DE)',
                'description': 'Implement activities to identify cybersecurity events'
            },
            'respond': {
                'function': 'Respond (RS)',
                'description': 'Implement activities to address detected cybersecurity incident'
            },
            'recover': {
                'function': 'Recover (RC)',
                'description': 'Implement activities to restore services impaired by incident'
            }
        }
    
    def get_scan_data(self):
        """Retrieve scan results from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get scan results
        cursor.execute('''
            SELECT target, port, state, service, version, risk_level, description, scan_time
            FROM scan_results 
            ORDER BY scan_time DESC
        ''')
        scan_results = cursor.fetchall()
        
        # Get vulnerabilities
        cursor.execute('''
            SELECT target, vulnerability_type, severity, description, recommendation, scan_time
            FROM vulnerabilities 
            ORDER BY scan_time DESC
        ''')
        vulnerabilities = cursor.fetchall()
        
        # Get threat alerts
        cursor.execute('''
            SELECT alert_type, severity, source_ip, description, confidence_score, detection_time
            FROM threat_alerts 
            ORDER BY detection_time DESC
        ''')
        threats = cursor.fetchall()
        
        conn.close()
        
        return {
            'scan_results': scan_results,
            'vulnerabilities': vulnerabilities,
            'threats': threats
        }
    
    def map_to_cis_controls(self, vulnerabilities):
        """Map vulnerabilities to CIS Controls"""
        cis_mappings = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln[1].lower()
            
            if 'insecure service' in vuln_type:
                cis_mappings.append({
                    'vulnerability': vuln,
                    'cis_control': self.cis_controls['secure_config'],
                    'gap_analysis': 'Insecure services indicate inadequate secure configuration practices'
                })
            
            elif 'exposed service' in vuln_type:
                cis_mappings.append({
                    'vulnerability': vuln,
                    'cis_control': self.cis_controls['network_monitoring'],
                    'gap_analysis': 'Exposed services require better boundary defense controls'
                })
            
            elif 'windows service' in vuln_type:
                cis_mappings.append({
                    'vulnerability': vuln,
                    'cis_control': self.cis_controls['access_control'],
                    'gap_analysis': 'Windows service exposure indicates insufficient access controls'
                })
            
            else:
                cis_mappings.append({
                    'vulnerability': vuln,
                    'cis_control': self.cis_controls['secure_config'],
                    'gap_analysis': 'General security misconfiguration detected'
                })
        
        return cis_mappings
    
    def map_to_nist_framework(self, data):
        """Map findings to NIST Cybersecurity Framework"""
        nist_mappings = {
            'identify': [],
            'protect': [],
            'detect': [],
            'respond': [],
            'recover': []
        }
        
        # Map scan results to NIST functions
        for scan in data['scan_results']:
            if scan[3] != 'closed':  # Open/filtered services
                nist_mappings['identify'].append({
                    'finding': f"Open service: {scan[3]} on port {scan[1]}",
                    'recommendation': 'Inventory and assess all exposed services'
                })
        
        # Map vulnerabilities to NIST functions
        for vuln in data['vulnerabilities']:
            nist_mappings['protect'].append({
                'finding': vuln[3],
                'recommendation': vuln[4]
            })
        
        # Map threats to NIST functions
        for threat in data['threats']:
            nist_mappings['detect'].append({
                'finding': f"{threat[0]}: {threat[3]}",
                'recommendation': 'Implement continuous monitoring and threat detection'
            })
            
            nist_mappings['respond'].append({
                'finding': f"Response needed for: {threat[0]}",
                'recommendation': 'Develop incident response procedures for this threat type'
            })
        
        return nist_mappings
    
    def calculate_risk_scores(self, data):
        """Calculate overall risk scores"""
        risk_scores = {
            'overall': 0,
            'network': 0,
            'system': 0,
            'application': 0
        }
        
        # Calculate network risk
        high_risk_ports = sum(1 for scan in data['scan_results'] if scan[5] == 'HIGH')
        medium_risk_ports = sum(1 for scan in data['scan_results'] if scan[5] == 'MEDIUM')
        
        risk_scores['network'] = min(100, (high_risk_ports * 20) + (medium_risk_ports * 10))
        
        # Calculate system risk
        high_severity_vulns = sum(1 for vuln in data['vulnerabilities'] if vuln[2] == 'HIGH')
        medium_severity_vulns = sum(1 for vuln in data['vulnerabilities'] if vuln[2] == 'MEDIUM')
        
        risk_scores['system'] = min(100, (high_severity_vulns * 25) + (medium_severity_vulns * 15))
        
        # Calculate application risk
        threat_count = len(data['threats'])
        risk_scores['application'] = min(100, threat_count * 10)
        
        # Overall risk (weighted average)
        risk_scores['overall'] = int((risk_scores['network'] * 0.4) + 
                                   (risk_scores['system'] * 0.4) + 
                                   (risk_scores['application'] * 0.2))
        
        return risk_scores
    
    def generate_recommendations(self, data):
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # High priority recommendations
        high_severity_vulns = [v for v in data['vulnerabilities'] if v[2] == 'HIGH']
        for vuln in high_severity_vulns:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Vulnerability Management',
                'finding': vuln[3],
                'recommendation': vuln[4],
                'timeline': 'Immediate (0-7 days)'
            })
        
        # Medium priority recommendations
        medium_severity_vulns = [v for v in data['vulnerabilities'] if v[2] == 'MEDIUM']
        for vuln in medium_severity_vulns:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'System Hardening',
                'finding': vuln[3],
                'recommendation': vuln[4],
                'timeline': 'Short-term (1-4 weeks)'
            })
        
        # Threat-based recommendations
        unique_threats = list(set([t[0] for t in data['threats']]))
        for threat_type in unique_threats:
            if threat_type == 'Brute Force Attack':
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Access Control',
                    'finding': 'Brute force attacks detected',
                    'recommendation': 'Implement account lockout policies, MFA, and IP blocking',
                    'timeline': 'Immediate (0-7 days)'
                })
            
            elif threat_type == 'Port Scan':
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Network Security',
                    'finding': 'Port scanning activity detected',
                    'recommendation': 'Review firewall rules and implement intrusion prevention',
                    'timeline': 'Short-term (1-4 weeks)'
                })
        
        # General recommendations
        recommendations.append({
            'priority': 'LOW',
            'category': 'Security Monitoring',
            'finding': 'Need for continuous monitoring',
            'recommendation': 'Implement SIEM solution and regular security assessments',
            'timeline': 'Long-term (1-3 months)'
        })
        
        return sorted(recommendations, key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x['priority']))
    
    def generate_executive_summary(self, data, risk_scores):
        """Generate executive summary"""
        total_findings = len(data['vulnerabilities']) + len(data['threats'])
        high_risk_findings = len([v for v in data['vulnerabilities'] if v[2] == 'HIGH'])
        high_risk_findings += len([t for t in data['threats'] if t[1] == 'HIGH'])
        
        summary = f"""
        This security assessment identified {total_findings} total security findings across the assessed infrastructure. 
        Of these findings, {high_risk_findings} are classified as high risk and require immediate attention.
        
        The overall risk score is {risk_scores['overall']}/100, indicating a 
        {'high' if risk_scores['overall'] > 70 else 'medium' if risk_scores['overall'] > 40 else 'low'} 
        risk environment.
        
        Key areas of concern include:
        - Network security: {len([s for s in data['scan_results'] if s[5] == 'HIGH'])} high-risk exposed services
        - System vulnerabilities: {len([v for v in data['vulnerabilities'] if v[2] == 'HIGH'])} critical vulnerabilities
        - Threat activity: {len(data['threats'])} security incidents detected
        
        Immediate action is required to address high-risk vulnerabilities and implement recommended security controls.
        """
        
        return summary.strip()
    
    def create_charts(self, data, risk_scores):
        """Create charts for the report"""
        plt.style.use('default')
        charts = {}
        
        # Risk Score Chart
        fig, ax = plt.subplots(figsize=(8, 6))
        categories = ['Network', 'System', 'Application', 'Overall']
        scores = [risk_scores['network'], risk_scores['system'], 
                 risk_scores['application'], risk_scores['overall']]
        
        colors_list = ['red' if score > 70 else 'orange' if score > 40 else 'green' for score in scores]
        bars = ax.bar(categories, scores, color=colors_list, alpha=0.7)
        
        ax.set_ylabel('Risk Score')
        ax.set_title('Security Risk Assessment by Category')
        ax.set_ylim(0, 100)
        
        # Add value labels on bars
        for bar, score in zip(bars, scores):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                   str(score), ha='center', va='bottom')
        
        plt.tight_layout()
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
        img_buffer.seek(0)
        charts['risk_scores'] = img_buffer.getvalue()
        plt.close()
        
        # Vulnerability Distribution Chart
        if data['vulnerabilities']:
            fig, ax = plt.subplots(figsize=(8, 6))
            severities = [v[2] for v in data['vulnerabilities']]
            severity_counts = {s: severities.count(s) for s in ['HIGH', 'MEDIUM', 'LOW']}
            
            colors_pie = ['red', 'orange', 'yellow']
            plt.pie(severity_counts.values(), labels=severity_counts.keys(), 
                   colors=colors_pie, autopct='%1.1f%%', startangle=90)
            plt.title('Vulnerability Distribution by Severity')
            
            plt.tight_layout()
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
            img_buffer.seek(0)
            charts['vuln_distribution'] = img_buffer.getvalue()
            plt.close()
        
        return charts
    
    def generate_pdf_report(self, output_path="reports/security_advisory_report.pdf"):
        """Generate comprehensive PDF security advisory report"""
        logger.info("Generating security advisory report...")
        
        # Get data
        data = self.get_scan_data()
        risk_scores = self.calculate_risk_scores(data)
        recommendations = self.generate_recommendations(data)
        executive_summary = self.generate_executive_summary(data, risk_scores)
        cis_mappings = self.map_to_cis_controls(data['vulnerabilities'])
        nist_mappings = self.map_to_nist_framework(data)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20
        )
        
        # Build story
        story = []
        
        # Title Page
        story.append(Paragraph("Cybersecurity Advisory Report", title_style))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(executive_summary, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Risk Assessment Summary
        story.append(Paragraph("Risk Assessment Summary", heading_style))
        
        risk_data = [
            ['Risk Category', 'Score (0-100)', 'Risk Level'],
            ['Network Security', str(risk_scores['network']), 
             'High' if risk_scores['network'] > 70 else 'Medium' if risk_scores['network'] > 40 else 'Low'],
            ['System Security', str(risk_scores['system']),
             'High' if risk_scores['system'] > 70 else 'Medium' if risk_scores['system'] > 40 else 'Low'],
            ['Application Security', str(risk_scores['application']),
             'High' if risk_scores['application'] > 70 else 'Medium' if risk_scores['application'] > 40 else 'Low'],
            ['Overall Risk', str(risk_scores['overall']),
             'High' if risk_scores['overall'] > 70 else 'Medium' if risk_scores['overall'] > 40 else 'Low']
        ]
        
        risk_table = Table(risk_data)
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(PageBreak())
        
        # Detailed Findings
        story.append(Paragraph("Detailed Security Findings", heading_style))
        
        # Vulnerabilities
        if data['vulnerabilities']:
            story.append(Paragraph("Vulnerabilities Identified", styles['Heading3']))
            
            for i, vuln in enumerate(data['vulnerabilities'][:10]):  # Limit to top 10
                story.append(Paragraph(f"<b>{i+1}. {vuln[1]} - {vuln[2]} Severity</b>", styles['Normal']))
                story.append(Paragraph(f"Description: {vuln[3]}", styles['Normal']))
                story.append(Paragraph(f"Recommendation: {vuln[4]}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        # Threat Alerts
        if data['threats']:
            story.append(Paragraph("Security Threats Detected", styles['Heading3']))
            
            for i, threat in enumerate(data['threats'][:10]):  # Limit to top 10
                story.append(Paragraph(f"<b>{i+1}. {threat[0]} - {threat[1]} Severity</b>", styles['Normal']))
                story.append(Paragraph(f"Source: {threat[2] or 'Unknown'}", styles['Normal']))
                story.append(Paragraph(f"Description: {threat[3]}", styles['Normal']))
                story.append(Paragraph(f"Confidence: {threat[4]:.1%}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        story.append(PageBreak())
        
        # CIS Controls Mapping
        story.append(Paragraph("CIS Controls Gap Analysis", heading_style))
        
        for mapping in cis_mappings[:5]:  # Show top 5
            story.append(Paragraph(f"<b>{mapping['cis_control']['control']}: {mapping['cis_control']['title']}</b>", styles['Normal']))
            story.append(Paragraph(f"Gap: {mapping['gap_analysis']}", styles['Normal']))
            story.append(Paragraph(f"Finding: {mapping['vulnerability'][3]}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", heading_style))
        
        # Group recommendations by priority
        high_priority = [r for r in recommendations if r['priority'] == 'HIGH']
        medium_priority = [r for r in recommendations if r['priority'] == 'MEDIUM']
        
        if high_priority:
            story.append(Paragraph("High Priority (Immediate Action Required)", styles['Heading3']))
            for i, rec in enumerate(high_priority):
                story.append(Paragraph(f"<b>{i+1}. {rec['category']}</b>", styles['Normal']))
                story.append(Paragraph(f"Finding: {rec['finding']}", styles['Normal']))
                story.append(Paragraph(f"Recommendation: {rec['recommendation']}", styles['Normal']))
                story.append(Paragraph(f"Timeline: {rec['timeline']}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        if medium_priority:
            story.append(Paragraph("Medium Priority", styles['Heading3']))
            for i, rec in enumerate(medium_priority[:5]):  # Limit to 5
                story.append(Paragraph(f"<b>{i+1}. {rec['category']}</b>", styles['Normal']))
                story.append(Paragraph(f"Finding: {rec['finding']}", styles['Normal']))
                story.append(Paragraph(f"Recommendation: {rec['recommendation']}", styles['Normal']))
                story.append(Paragraph(f"Timeline: {rec['timeline']}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(story)
        logger.info(f"Report generated: {output_path}")
        
        return output_path
    
    def generate_json_report(self, output_path="reports/security_data.json"):
        """Generate machine-readable JSON report"""
        data = self.get_scan_data()
        risk_scores = self.calculate_risk_scores(data)
        recommendations = self.generate_recommendations(data)
        
        json_report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'report_type': 'security_advisory'
            },
            'risk_assessment': risk_scores,
            'findings': {
                'vulnerabilities': [
                    {
                        'target': v[0],
                        'type': v[1],
                        'severity': v[2],
                        'description': v[3],
                        'recommendation': v[4],
                        'detected_at': v[5]
                    } for v in data['vulnerabilities']
                ],
                'threats': [
                    {
                        'type': t[0],
                        'severity': t[1],
                        'source_ip': t[2],
                        'description': t[3],
                        'confidence': t[4],
                        'detected_at': t[5]
                    } for t in data['threats']
                ],
                'exposed_services': [
                    {
                        'target': s[0],
                        'port': s[1],
                        'state': s[2],
                        'service': s[3],
                        'version': s[4],
                        'risk_level': s[5]
                    } for s in data['scan_results'] if s[2] == 'open'
                ]
            },
            'recommendations': recommendations
        }
        
        with open(output_path, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {output_path}")
        return output_path

# Example usage
if __name__ == "__main__":
    advisor = SecurityAdvisoryGenerator()
    
    # Generate reports
    pdf_report = advisor.generate_pdf_report()
    json_report = advisor.generate_json_report()
    
    print(f"Reports generated:")
    print(f"- PDF Report: {pdf_report}")
    print(f"- JSON Report: {json_report}")