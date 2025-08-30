#!/usr/bin/env python3
"""
CyberSec Monitor Setup Script
Automated setup and installation script for the cybersecurity monitoring tool
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Print setup banner"""
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║          🔒 CyberSec Monitor Setup 🔒             ║
    ║    AI-Driven Cybersecurity Monitoring Tool       ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    print("📋 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required!")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python {sys.version.split()[0]} - Compatible!")

def check_system_dependencies():
    """Check for system-level dependencies"""
    print("\n🔍 Checking system dependencies...")
    
    # Check for nmap
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Nmap - Found")
        else:
            print("⚠️  Nmap - Not found or not working properly")
            install_nmap()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("❌ Nmap - Not found")
        install_nmap()

def install_nmap():
    """Install nmap based on operating system"""
    system = platform.system().lower()
    
    print("\n📦 Installing Nmap...")
    
    if system == "linux":
        # Try different package managers
        for cmd in [
            ["sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "nmap"],
            ["sudo", "yum", "install", "-y", "nmap"],
            ["sudo", "dnf", "install", "-y", "nmap"],
            ["sudo", "pacman", "-S", "--noconfirm", "nmap"]
        ]:
            try:
                subprocess.run(cmd, check=True, shell=True)
                print("✅ Nmap installed successfully!")
                return
            except subprocess.CalledProcessError:
                continue
        
        print("⚠️  Could not automatically install Nmap.")
        print("   Please install manually: sudo apt-get install nmap")
    
    elif system == "darwin":  # macOS
        try:
            subprocess.run(["brew", "install", "nmap"], check=True)
            print("✅ Nmap installed successfully!")
        except subprocess.CalledProcessError:
            print("⚠️  Could not install Nmap via Homebrew.")
            print("   Please install manually: brew install nmap")
    
    elif system == "windows":
        print("⚠️  Please download and install Nmap manually from:")
        print("   https://nmap.org/download.html")
    
    else:
        print(f"⚠️  Unknown operating system: {system}")
        print("   Please install Nmap manually")

def create_virtual_environment():
    """Create and setup virtual environment"""
    print("\n🐍 Setting up Python virtual environment...")
    
    venv_path = Path("cybersec-env")
    
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return str(venv_path)
    
    try:
        subprocess.run([sys.executable, "-m", "venv", "cybersec-env"], check=True)
        print("✅ Virtual environment created successfully!")
        return str(venv_path)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        sys.exit(1)

def install_python_dependencies(venv_path):
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    # Determine pip path based on OS
    if platform.system().lower() == "windows":
        pip_path = Path(venv_path) / "Scripts" / "pip"
        python_path = Path(venv_path) / "Scripts" / "python"
    else:
        pip_path = Path(venv_path) / "bin" / "pip"
        python_path = Path(venv_path) / "bin" / "python"
    
    try:
        # Upgrade pip first
        subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"], check=True)
        
        # Install requirements
        subprocess.run([str(pip_path), "install", "-r", "requirements.txt"], check=True)
        print("✅ Python dependencies installed successfully!")
        return str(python_path)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("💡 Try running manually: pip install -r requirements.txt")
        return None

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating project directories...")
    
    directories = ["data", "reports", "reports/pdf", "reports/json"]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}/")

def initialize_database():
    """Initialize the SQLite database"""
    print("\n🗄️  Initializing database...")
    
    try:
        # Import and initialize scanner to create database
        sys.path.append("src")
        from scanner import AttackSurfaceScanner
        from detector import ThreatDetector
        
        scanner = AttackSurfaceScanner()
        detector = ThreatDetector()
        
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"⚠️  Database initialization warning: {e}")
        print("   Database will be created on first use")

def test_installation():
    """Test the installation"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test imports
        sys.path.append("src")
        from scanner import AttackSurfaceScanner
        from detector import ThreatDetector
        from advisory import SecurityAdvisoryGenerator
        
        print("✅ All modules import successfully!")
        
        # Test sample threat detection
        detector = ThreatDetector()
        sample_logs = detector.generate_sample_logs()
        events, alerts = detector.analyze_logs(sample_logs, 'auth')
        
        print(f"✅ Threat detection test: {len(alerts)} threats detected in sample logs")
        
        return True
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False

def print_usage_instructions(venv_path, python_path):
    """Print usage instructions"""
    print("\n" + "="*60)
    print("🎉 INSTALLATION COMPLETED SUCCESSFULLY! 🎉")
    print("="*60)
    
    activation_cmd = (
        f"cybersec-env\\Scripts\\activate" if platform.system().lower() == "windows" 
        else f"source cybersec-env/bin/activate"
    )
    
    instructions = f"""
🚀 Quick Start Instructions:

1. Activate virtual environment:
   {activation_cmd}

2. Launch the dashboard:
   cd src
   streamlit run dashboard.py

3. Open your browser and go to:
   http://localhost:8501

📖 Alternative Usage:

   • Command line scanning:
     python src/scanner.py
   
   • Threat detection:
     python src/detector.py
   
   • Generate reports:
     python src/advisory.py

📚 Documentation:
   • Read README.md for detailed usage guide
   • Check data/sample_logs.log for sample data
   • Reports will be saved in reports/ directory

🔧 Troubleshooting:
   • If Streamlit doesn't start: pip install streamlit --upgrade
   • If Nmap errors occur: ensure it's installed and in PATH
   • For permission issues: check file/directory permissions

⚠️  Security Note:
   Only scan systems you own or have permission to test!

Happy Security Monitoring! 🔒✨
"""
    
    print(instructions)

def main():
    """Main setup function"""
    print_banner()
    
    try:
        # Pre-installation checks
        check_python_version()
        check_system_dependencies()
        
        # Setup environment
        venv_path = create_virtual_environment()
        python_path = install_python_dependencies(venv_path)
        
        # Setup project
        create_directories()
        initialize_database()
        
        # Test installation
        if test_installation():
            print_usage_instructions(venv_path, python_path)
        else:
            print("\n⚠️  Installation completed with warnings.")
            print("   Please check error messages above and README.md")
    
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("💡 Please check the README.md for manual installation steps")
        sys.exit(1)

if __name__ == "__main__":
    main()