import streamlit as st
import pandas as pd
import sqlite3
import os
import sys
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner import AttackSurfaceScanner
from detector import ThreatDetector
from advisory import SecurityAdvisoryGenerator

# Page configuration
st.set_page_config(
    page_title="CyberSec Monitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #1f77b4;
    }
    .high-risk {
        border-left-color: #ff4b4b;
    }
    .medium-risk {
        border-left-color: #ff8c00;
    }
    .low-risk {
        border-left-color: #00ff00;
    }
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 1.1rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

class CyberSecDashboard:
    def __init__(self):
        self.scanner = AttackSurfaceScanner()
        self.detector = ThreatDetector()
        self.advisor = SecurityAdvisoryGenerator()
        
        # Ensure directories exist
        os.makedirs("data", exist_ok=True)
        os.makedirs("reports", exist_ok=True)
    
    def get_dashboard_data(self):
        """Get all dashboard data from database"""
        conn = sqlite3.connect(self.scanner.db_path)
        
        # Scan results
        scan_df = pd.read_sql_query("""
            SELECT * FROM scan_results 
            ORDER BY scan_time DESC
        """, conn)
        
        # Vulnerabilities
        vuln_df = pd.read_sql_query("""
            SELECT * FROM vulnerabilities 
            ORDER BY scan_time DESC
        """, conn)
        
        # Threat alerts
        threat_df = pd.read_sql_query("""
            SELECT * FROM threat_alerts 
            ORDER BY detection_time DESC
        """, conn)
        
        conn.close()
        
        return scan_df, vuln_df, threat_df
    
    def create_risk_gauge(self, risk_score, title):
        """Create risk gauge chart"""
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = risk_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': title},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
        return fig
    
    def create_vulnerability_chart(self, vuln_df):
        """Create vulnerability severity distribution chart"""
        if vuln_df.empty:
            return go.Figure()
        
        severity_counts = vuln_df['severity'].value_counts()
        
        fig = px.pie(
            values=severity_counts.values, 
            names=severity_counts.index,
            title="Vulnerability Distribution by Severity",
            color_discrete_map={'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}
        )
        
        return fig
    
    def create_threat_timeline(self, threat_df):
        """Create threat detection timeline"""
        if threat_df.empty:
            return go.Figure()
        
        threat_df['detection_time'] = pd.to_datetime(threat_df['detection_time'])
        daily_threats = threat_df.groupby(threat_df['detection_time'].dt.date).size().reset_index()
        daily_threats.columns = ['date', 'count']
        
        fig = px.line(
            daily_threats, 
            x='date', 
            y='count',
            title="Threat Detection Timeline",
            labels={'count': 'Number of Threats', 'date': 'Date'}
        )
        
        return fig
    
    def create_port_analysis_chart(self, scan_df):
        """Create port analysis chart"""
        if scan_df.empty:
            return go.Figure()
        
        # Filter open ports only
        open_ports = scan_df[scan_df['state'] == 'open']
        
        if open_ports.empty:
            return go.Figure()
        
        # Count ports by risk level
        risk_counts = open_ports['risk_level'].value_counts()
        
        fig = px.bar(
            x=risk_counts.index, 
            y=risk_counts.values,
            title="Open Ports by Risk Level",
            color=risk_counts.index,
            color_discrete_map={'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'green'}
        )
        
        fig.update_layout(
            xaxis_title="Risk Level",
            yaxis_title="Number of Ports",
            showlegend=False
        )
        
        return fig
    
    def display_scan_module(self):
        """Display attack surface scanning module"""
        st.header("🔍 Attack Surface Scanning")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            target = st.text_input("Target IP/Domain:", placeholder="192.168.1.1 or example.com")
            port_range = st.text_input("Port Range:", value="1-1000", placeholder="1-1000 or 80,443,22")
        
        with col2:
            st.write("") # Spacing
            st.write("") # Spacing
            scan_button = st.button("🚀 Start Scan", type="primary")
        
        if scan_button and target:
            with st.spinner(f"Scanning {target}..."):
                try:
                    results = self.scanner.port_scan(target, port_range)
                    
                    if results:
                        st.success(f"✅ Scan completed! Found {len(results)} open ports")
                        
                        # Check for vulnerabilities
                        vulnerabilities = self.scanner.check_misconfigurations(results)
                        
                        if vulnerabilities:
                            st.warning(f"⚠️ Identified {len(vulnerabilities)} potential vulnerabilities")
                        
                        # Display results
                        df = pd.DataFrame(results)
                        st.subheader("Scan Results")
                        st.dataframe(df, use_container_width=True)
                        
                        # Display vulnerabilities if any
                        if vulnerabilities:
                            st.subheader("Vulnerabilities Detected")
                            vuln_df = pd.DataFrame(vulnerabilities)
                            st.dataframe(vuln_df, use_container_width=True)
                    
                    else:
                        st.error("❌ Scan failed or no results found")
                
                except Exception as e:
                    st.error(f"❌ Error during scan: {str(e)}")
        
        # Display recent scan results
        st.subheader("Recent Scan Results")
        recent_scans = self.scanner.get_scan_results()
        
        if recent_scans:
            scan_data = []
            for scan in recent_scans[:10]:  # Show last 10
                scan_data.append({
                    'Target': scan[1],
                    'Port': scan[2],
                    'State': scan[3],
                    'Service': scan[4],
                    'Risk Level': scan[6],
                    'Scan Time': scan[8]
                })
            
            df = pd.DataFrame(scan_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No recent scan results available. Run a scan to see results here.")
    
    def display_threat_detection_module(self):
        """Display threat detection module"""
        st.header("🛡️ Threat Detection & Log Analysis")
        
        tab1, tab2 = st.tabs(["📄 Log Upload", "🔍 Sample Analysis"])
        
        with tab1:
            st.subheader("Upload Log Files")
            
            log_type = st.selectbox("Log Type:", ["auth", "firewall", "mixed"])
            uploaded_file = st.file_uploader("Choose a log file", type=['log', 'txt'])
            
            if uploaded_file is not None:
                log_content = str(uploaded_file.read(), "utf-8")
                
                analyze_button = st.button("🔍 Analyze Logs", type="primary")
                
                if analyze_button:
                    with st.spinner("Analyzing logs for threats..."):
                        try:
                            events, alerts = self.detector.analyze_logs(log_content, log_type)
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Events", len(events))
                            with col2:
                                st.metric("Threats Detected", len(alerts))
                            with col3:
                                high_severity = len([a for a in alerts if a['severity'] == 'HIGH'])
                                st.metric("High Severity", high_severity)
                            
                            if alerts:
                                st.subheader("🚨 Threat Alerts")
                                for alert in alerts:
                                    severity_color = {
                                        'HIGH': '🔴',
                                        'MEDIUM': '🟡',
                                        'LOW': '🟢'
                                    }.get(alert['severity'], '⚪')
                                    
                                    st.write(f"{severity_color} **{alert['alert_type']}** ({alert['severity']})")
                                    st.write(f"   📍 Source: {alert.get('source_ip', 'Unknown')}")
                                    st.write(f"   📝 {alert['description']}")
                                    st.write(f"   🎯 Confidence: {alert['confidence_score']:.1%}")
                                    st.write("---")
                            else:
                                st.success("✅ No threats detected in the analyzed logs")
                        
                        except Exception as e:
                            st.error(f"❌ Error analyzing logs: {str(e)}")
        
        with tab2:
            st.subheader("Sample Log Analysis")
            st.info("Click below to analyze sample logs and see how the threat detection works")
            
            if st.button("🧪 Analyze Sample Logs"):
                with st.spinner("Analyzing sample logs..."):
                    sample_logs = self.detector.generate_sample_logs()
                    events, alerts = self.detector.analyze_logs(sample_logs, 'auth')
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Sample Events", len(events))
                    with col2:
                        st.metric("Threats Found", len(alerts))
                    with col3:
                        high_severity = len([a for a in alerts if a['severity'] == 'HIGH'])
                        st.metric("High Severity", high_severity)
                    
                    if alerts:
                        st.subheader("🚨 Detected Threats in Sample")
                        alerts_df = pd.DataFrame(alerts)
                        st.dataframe(alerts_df, use_container_width=True)
        
        # Display recent alerts
        st.subheader("Recent Threat Alerts")
        recent_alerts = self.detector.get_recent_alerts(20)
        
        if recent_alerts:
            alert_data = []
            for alert in recent_alerts:
                alert_data.append({
                    'Alert Type': alert[1],
                    'Severity': alert[2],
                    'Source IP': alert[3] or 'Unknown',
                    'Description': alert[4],
                    'Confidence': f"{alert[6]:.1%}" if alert[6] else 'N/A',
                    'Detection Time': alert[7]
                })
            
            df = pd.DataFrame(alert_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No recent alerts available. Analyze some logs to see alerts here.")
    
    def display_advisory_module(self):
        """Display security advisory and reporting module"""
        st.header("📊 Security Advisory & Reporting")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Generate PDF Report", type="primary"):
                with st.spinner("Generating comprehensive security report..."):
                    try:
                        report_path = self.advisor.generate_pdf_report()
                        st.success(f"✅ PDF report generated successfully!")
                        
                        # Provide download button
                        with open(report_path, "rb") as pdf_file:
                            st.download_button(
                                label="📥 Download PDF Report",
                                data=pdf_file.read(),
                                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf"
                            )
                    
                    except Exception as e:
                        st.error(f"❌ Error generating PDF report: {str(e)}")
        
        with col2:
            if st.button("💾 Generate JSON Report"):
                with st.spinner("Generating JSON security data..."):
                    try:
                        json_path = self.advisor.generate_json_report()
                        st.success("✅ JSON report generated successfully!")
                        
                        # Provide download button
                        with open(json_path, "rb") as json_file:
                            st.download_button(
                                label="📥 Download JSON Report",
                                data=json_file.read(),
                                file_name=f"security_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                    
                    except Exception as e:
                        st.error(f"❌ Error generating JSON report: {str(e)}")
        
        # Show compliance mapping preview
        st.subheader("🎯 Compliance Framework Mapping")
        
        framework = st.selectbox("Select Framework:", ["CIS Controls", "NIST Cybersecurity Framework"])
        
        if framework == "CIS Controls":
            st.write("**CIS Critical Security Controls Mapping:**")
            cis_controls = self.advisor.load_cis_controls()
            
            for key, control in cis_controls.items():
                with st.expander(f"{control['control']}: {control['title']}"):
                    st.write(f"**Description:** {control['description']}")
                    
        else:
            st.write("**NIST Cybersecurity Framework Functions:**")
            nist_framework = self.advisor.load_nist_framework()
            
            for key, function in nist_framework.items():
                with st.expander(f"{function['function']}"):
                    st.write(f"**Description:** {function['description']}")
    
    def display_dashboard_overview(self):
        """Display main dashboard overview"""
        st.header("🎛️ Security Dashboard Overview")
        
        # Get data
        scan_df, vuln_df, threat_df = self.get_dashboard_data()
        
        # Calculate metrics
        total_scans = len(scan_df)
        open_ports = len(scan_df[scan_df['state'] == 'open']) if not scan_df.empty else 0
        total_vulns = len(vuln_df)
        high_risk_vulns = len(vuln_df[vuln_df['severity'] == 'HIGH']) if not vuln_df.empty else 0
        total_threats = len(threat_df)
        recent_threats = len(threat_df[pd.to_datetime(threat_df['detection_time']) > datetime.now() - timedelta(days=7)]) if not threat_df.empty else 0
        
        # Top metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="🔍 Total Scans",
                value=total_scans,
                delta=f"{open_ports} open ports"
            )
        
        with col2:
            st.metric(
                label="🚨 Vulnerabilities",
                value=total_vulns,
                delta=f"{high_risk_vulns} high risk"
            )
        
        with col3:
            st.metric(
                label="🛡️ Threats Detected", 
                value=total_threats,
                delta=f"{recent_threats} this week"
            )
        
        with col4:
            # Calculate overall risk score
            risk_score = min(100, (high_risk_vulns * 20) + (recent_threats * 10))
            risk_level = "🔴 High" if risk_score > 70 else "🟡 Medium" if risk_score > 30 else "🟢 Low"
            st.metric(
                label="⚠️ Risk Level",
                value=f"{risk_score}/100",
                delta=risk_level
            )
        
        # Charts row
        st.subheader("📈 Security Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Vulnerability distribution
            if not vuln_df.empty:
                vuln_chart = self.create_vulnerability_chart(vuln_df)
                st.plotly_chart(vuln_chart, use_container_width=True)
            else:
                st.info("No vulnerability data available")
        
        with col2:
            # Port analysis
            if not scan_df.empty:
                port_chart = self.create_port_analysis_chart(scan_df)
                st.plotly_chart(port_chart, use_container_width=True)
            else:
                st.info("No scan data available")
        
        # Threat timeline
        if not threat_df.empty:
            st.subheader("🕒 Threat Detection Timeline")
            timeline_chart = self.create_threat_timeline(threat_df)
            st.plotly_chart(timeline_chart, use_container_width=True)
        
        # Recent activity summary
        st.subheader("📋 Recent Activity Summary")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**🔍 Latest Scans:**")
            if not scan_df.empty:
                recent_scans = scan_df.head(5)[['target', 'port', 'service', 'risk_level', 'scan_time']]
                st.dataframe(recent_scans, use_container_width=True, hide_index=True)
            else:
                st.info("No recent scans")
        
        with col2:
            st.write("**🚨 Latest Alerts:**")
            if not threat_df.empty:
                recent_alerts = threat_df.head(5)[['alert_type', 'severity', 'source_ip', 'detection_time']]
                st.dataframe(recent_alerts, use_container_width=True, hide_index=True)
            else:
                st.info("No recent alerts")

def main():
    """Main dashboard application"""
    # App title and header
    st.title("🔒 CyberSec Monitor")
    st.markdown("**AI-Driven Attack Surface Monitoring & Threat Detection Tool**")
    st.markdown("---")
    
    # Initialize dashboard
    dashboard = CyberSecDashboard()
    
    # Sidebar navigation
    with st.sidebar:
        st.image("https://via.placeholder.com/150x50/1f77b4/ffffff?text=CyberSec", width=150)
        st.markdown("### 🚀 Navigation")
        
        page = st.selectbox(
            "Choose a module:",
            ["🎛️ Dashboard", "🔍 Attack Surface Scan", "🛡️ Threat Detection", "📊 Security Advisory"]
        )
        
        st.markdown("---")
        st.markdown("### 📊 Quick Stats")
        
        # Quick stats in sidebar
        scan_df, vuln_df, threat_df = dashboard.get_dashboard_data()
        
        st.metric("Scans Today", len(scan_df[pd.to_datetime(scan_df['scan_time']).dt.date == datetime.now().date()]) if not scan_df.empty else 0)
        st.metric("Active Threats", len(threat_df[pd.to_datetime(threat_df['detection_time']) > datetime.now() - timedelta(hours=24)]) if not threat_df.empty else 0)
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
        **CyberSec Monitor** combines:
        - 🔍 Attack Surface Management
        - 🛡️ AI-Powered Threat Detection  
        - 📊 Compliance Reporting
        - 🚨 Real-time Monitoring
        """)
    
    # Main content area
    if page == "🎛️ Dashboard":
        dashboard.display_dashboard_overview()
    
    elif page == "🔍 Attack Surface Scan":
        dashboard.display_scan_module()
    
    elif page == "🛡️ Threat Detection":
        dashboard.display_threat_detection_module()
    
    elif page == "📊 Security Advisory":
        dashboard.display_advisory_module()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "🔒 CyberSec Monitor v1.0 | Built with Streamlit | "
        f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        "</div>", 
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()