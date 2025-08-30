#!/usr/bin/env python3
"""
CyberSec Monitor - Quick Run Script
One-command launcher for the cybersecurity monitoring tool
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║          🔒 CyberSec Monitor v1.0 🔒             ║
    ║    AI-Driven Cybersecurity Monitoring Tool       ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)

def check_installation():
    """Check if the tool is properly installed"""
    required_files = [
        "src/scanner.py",
        "src/detector.py", 
        "src/advisory.py",
        "src/dashboard.py",
        "requirements.txt"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Installation incomplete! Missing files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("\n💡 Please run: python setup.py")
        return False
    
    return True

def run_dashboard():
    """Launch the Streamlit dashboard"""
    print("🚀 Starting CyberSec Monitor Dashboard...")
    print("📱 Dashboard will be available at: http://localhost:8501")
    print("🛑 Press Ctrl+C to stop the server\n")
    
    try:
        os.chdir("src")
        subprocess.run(["streamlit", "run", "dashboard.py", "--server.port=8501"], check=True)
    except subprocess.CalledProcessError:
        print("❌ Failed to start dashboard")
        print("💡 Try: pip install streamlit --upgrade")
        return False
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
        return True

def run_scanner(target, port_range):
    """Run attack surface scanner"""
    print(f"🔍 Starting attack surface scan of {target}")
    
    try:
        sys.path.append("src")
        from scanner import AttackSurfaceScanner
        
        scanner = AttackSurfaceScanner()
        results = scanner.port_scan(target, port_range)
        
        if results:
            print(f"\n✅ Scan completed! Found {len(results)} open ports:")
            for result in results:
                risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
                print(f"   {risk_emoji.get(result['risk_level'], '⚪')} Port {result['port']}: {result['service']} ({result['risk_level']} risk)")
            
            # Check vulnerabilities
            vulnerabilities = scanner.check_misconfigurations(results)
            if vulnerabilities:
                print(f"\n⚠️  Found {len(vulnerabilities)} potential vulnerabilities:")
                for vuln in vulnerabilities:
                    print(f"   🚨 {vuln['vulnerability_type']}: {vuln['description']}")
        else:
            print("❌ Scan failed or no results found")
            
    except Exception as e:
        print(f"❌ Scanner error: {e}")
        return False
    
    return True

def run_threat_detection(log_file=None):
    """Run threat detection analysis"""
    print("🛡️  Starting threat detection analysis...")
    
    try:
        sys.path.append("src")
        from detector import ThreatDetector
        
        detector = ThreatDetector()
        
        if log_file and Path(log_file).exists():
            with open(log_file, 'r') as f:
                log_content = f.read()
            print(f"📄 Analyzing log file: {log_file}")
        else:
            log_content = detector.generate_sample_logs()
            print("📄 Analyzing sample logs...")
        
        events, alerts = detector.analyze_logs(log_content, 'auth')
        
        print(f"\n📊 Analysis Results:")
        print(f"   📋 Total events parsed: {len(events)}")
        print(f"   🚨 Threats detected: {len(alerts)}")
        
        if alerts:
            print(f"\n🚨 Threat Details:")
            for alert in alerts:
                severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
                print(f"   {severity_emoji.get(alert['severity'], '⚪')} {alert['alert_type']} ({alert['severity']})")
                print(f"      Source: {alert.get('source_ip', 'Unknown')}")
                print(f"      Confidence: {alert['confidence_score']:.1%}")
                print(f"      Description: {alert['description']}\n")
        else:
            print("✅ No threats detected")
            
    except Exception as e:
        print(f"❌ Threat detection error: {e}")
        return False
    
    return True

def generate_reports():
    """Generate security reports"""
    print("📊 Generating security reports...")
    
    try:
        sys.path.append("src")
        from advisory import SecurityAdvisoryGenerator
        
        advisor = SecurityAdvisoryGenerator()
        
        # Generate PDF report
        print("📄 Generating PDF report...")
        pdf_path = advisor.generate_pdf_report()
        print(f"✅ PDF report saved: {pdf_path}")
        
        # Generate JSON report
        print("💾 Generating JSON report...")
        json_path = advisor.generate_json_report()
        print(f"✅ JSON report saved: {json_path}")
        
        print(f"\n📋 Reports Summary:")
        print(f"   📄 PDF Report: {pdf_path}")
        print(f"   💾 JSON Data: {json_path}")
        
    except Exception as e:
        print(f"❌ Report generation error: {e}")
        return False
    
    return True

def run_full_assessment(target):
    """Run complete security assessment"""
    print(f"🎯 Starting comprehensive security assessment of {target}")
    
    success_count = 0
    
    # 1. Attack Surface Scan
    print("\n" + "="*50)
    print("PHASE 1: ATTACK SURFACE SCANNING")
    print("="*50)
    if run_scanner(target, "1-1000"):
        success_count += 1
    
    # 2. Threat Detection (sample)
    print("\n" + "="*50)
    print("PHASE 2: THREAT DETECTION ANALYSIS")
    print("="*50)
    if run_threat_detection():
        success_count += 1
    
    # 3. Generate Reports
    print("\n" + "="*50)
    print("PHASE 3: SECURITY REPORTING")
    print("="*50)
    if generate_reports():
        success_count += 1
    
    print("\n" + "="*50)
    print("ASSESSMENT COMPLETE")
    print("="*50)
    print(f"✅ Completed phases: {success_count}/3")
    
    if success_count == 3:
        print("🎉 Full assessment completed successfully!")
        print("📊 Check the reports/ directory for detailed findings")
    else:
        print("⚠️  Assessment completed with some issues")
        print("💡 Check error messages above for details")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="CyberSec Monitor - AI-Driven Cybersecurity Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Launch dashboard
  python run.py --scan 192.168.1.1       # Scan target
  python run.py --detect sample_logs.log  # Analyze logs
  python run.py --report                  # Generate reports
  python run.py --full 192.168.1.1       # Complete assessment
        """
    )
    
    parser.add_argument(
        "--scan", "-s",
        metavar="TARGET",
        help="Run attack surface scan on target IP/domain"
    )
    
    parser.add_argument(
        "--ports", "-p",
        default="1-1000",
        help="Port range for scanning (default: 1-1000)"
    )
    
    parser.add_argument(
        "--detect", "-d",
        metavar="LOGFILE",
        nargs="?",
        const="sample",
        help="Run threat detection (optionally specify log file)"
    )
    
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Generate security reports"
    )
    
    parser.add_argument(
        "--full", "-f",
        metavar="TARGET",
        help="Run complete security assessment"
    )
    
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch web dashboard (default if no args)"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    # Determine action
    if args.scan:
        success = run_scanner(args.scan, args.ports)
    elif args.detect:
        log_file = args.detect if args.detect != "sample" else None
        success = run_threat_detection(log_file)
    elif args.report:
        success = generate_reports()
    elif args.full:
        run_full_assessment(args.full)
        success = True
    else:
        # Default: launch dashboard
        success = run_dashboard()
    
    if not success:
        print("\n💡 For help, run: python run.py --help")
        print("📖 Check README.md for detailed documentation")
        sys.exit(1)

if __name__ == "__main__":
    main()