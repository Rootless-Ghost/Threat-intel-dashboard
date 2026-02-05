#!/usr/bin/env python3
"""
Threat Intel Dashboard - Web Interface
Author: RootlessGhost
Description: Flask-based web dashboard for threat intelligence lookups.
"""

from flask import Flask, render_template, request, jsonify
from threat_intel import ThreatIntelLookup
import os

app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')

# Initialize the lookup engine
lookup_engine = ThreatIntelLookup('../config.yaml')


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/lookup', methods=['POST'])
def lookup():
    """API endpoint for IOC lookups."""
    data = request.get_json()
    
    if not data or 'ioc' not in data:
        return jsonify({'error': 'No IOC provided'}), 400
    
    ioc = data.get('ioc', '').strip()
    ioc_type = data.get('type', None)
    
    if not ioc:
        return jsonify({'error': 'Empty IOC'}), 400
    
    # Perform lookup
    result = lookup_engine.lookup(ioc, ioc_type)
    
    return jsonify(result)


@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'threat-intel-dashboard'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    print(f"""
    ╔═══════════════════════════════════════════════╗
    ║       THREAT INTEL DASHBOARD v1.0             ║
    ║            Web Interface                      ║
    ╚═══════════════════════════════════════════════╝
    
    [*] Starting web server on http://localhost:{port}
    [*] Press Ctrl+C to stop
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
