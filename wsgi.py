#!/usr/bin/env python3
"""
WSGI entry point for deployment platforms.
This file is used by gunicorn and other WSGI servers.
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import the Flask application
from main import app

# This is what WSGI servers will import
application = app

if __name__ == "__main__":
    # For local development
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)