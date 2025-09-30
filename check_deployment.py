#!/usr/bin/env python3
"""
Deployment startup checker - run this to validate your environment before deployment
"""

import os
import sys
import importlib.util

def check_environment():
    """Check if all required environment variables and dependencies are available"""
    
    print("🔍 Checking deployment environment...")
    print("=" * 50)
    
    # Check required environment variables
    required_env_vars = [
        "STOREDGE_API_KEY",
        "STOREDGE_API_SECRET",
        "PROXY_BEARER"
    ]
    
    optional_env_vars = [
        "COMPANY_ID",
        "PORT", 
        "FLASK_DEBUG"
    ]
    
    print("📋 Environment Variables:")
    all_env_good = True
    
    for var in required_env_vars:
        value = os.getenv(var)
        if value:
            print(f"  ✅ {var}: SET (length: {len(value)})")
        else:
            print(f"  ❌ {var}: MISSING")
            all_env_good = False
    
    for var in optional_env_vars:
        value = os.getenv(var)
        if value:
            print(f"  ℹ️  {var}: {value}")
        else:
            print(f"  ⚪ {var}: not set (using default)")
    
    # Check Python dependencies
    print("\n📦 Python Dependencies:")
    required_packages = [
        "flask",
        "requests", 
        "requests_oauthlib",
        "pandas",
        "numpy",
        "python_dotenv"
    ]
    
    optional_packages = [
        "pytds",
        "pyodbc"
    ]
    
    all_deps_good = True
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package}: Available")
        except ImportError:
            print(f"  ❌ {package}: MISSING")
            all_deps_good = False
    
    for package in optional_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package}: Available")
        except ImportError:
            print(f"  ⚪ {package}: Missing (optional - database features disabled)")
    
    # Check main.py syntax
    print("\n🐍 Python Syntax Check:")
    try:
        import main
        print("  ✅ main.py: Imports successfully")
        
        # Check if Flask app exists
        if hasattr(main, 'app'):
            print("  ✅ Flask app: Found")
            
            # Try to get app configuration
            try:
                with main.app.app_context():
                    print("  ✅ Flask context: Working")
            except Exception as e:
                print(f"  ⚠️  Flask context: {str(e)}")
        else:
            print("  ❌ Flask app: Not found")
            all_deps_good = False
            
    except Exception as e:
        print(f"  ❌ main.py: Import failed - {str(e)}")
        all_deps_good = False
    
    # Final result
    print("\n" + "=" * 50)
    if all_env_good and all_deps_good:
        print("🎉 DEPLOYMENT READY!")
        print("Your environment looks good for deployment.")
        return True
    else:
        print("🚨 DEPLOYMENT ISSUES FOUND")
        if not all_env_good:
            print("   - Fix missing environment variables")
        if not all_deps_good:
            print("   - Install missing dependencies")
        print("   - Check the errors above and fix them before deploying")
        return False

if __name__ == "__main__":
    success = check_environment()
    sys.exit(0 if success else 1)