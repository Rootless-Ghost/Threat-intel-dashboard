#!/usr/bin/env python3
"""
Threat Intelligence Lookup Tool
Author: RootlessGhost
Description: Queries multiple threat intel sources for IOC reputation data.
"""

import argparse
import sys
import re
import json
import hashlib
from pathlib import Path
from datetime import datetime

# Optional imports - will work without them in demo mode
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ThreatIntelLookup:
    """Main threat intelligence lookup class."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.api_keys = {}
        self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Load API keys from config file."""
        if YAML_AVAILABLE and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    if config and config.get('api_keys'):
                        self.api_keys = config.get('api_keys', {})
            except Exception:
                pass
    
    def validate_ioc(self, ioc: str, ioc_type: str) -> bool:
        """Validate IOC format."""
        if ioc_type == 'ip':
            # IPv4 pattern
            ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ipv4_pattern, ioc):
                parts = ioc.split('.')
                return all(0 <= int(p) <= 255 for p in parts)
            return False
        
        elif ioc_type == 'domain':
            domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            return bool(re.match(domain_pattern, ioc))
        
        elif ioc_type == 'hash':
            # MD5, SHA1, or SHA256
            hash_patterns = {
                'md5': r'^[a-fA-F0-9]{32}$',
                'sha1': r'^[a-fA-F0-9]{40}$',
                'sha256': r'^[a-fA-F0-9]{64}$'
            }
            return any(re.match(p, ioc) for p in hash_patterns.values())
        
        elif ioc_type == 'url':
            url_pattern = r'^https?://[^\s<>"{}|\\^`\[\]]+'
            return bool(re.match(url_pattern, ioc))
        
        return False
    
    def detect_ioc_type(self, ioc: str) -> str:
        """Auto-detect IOC type."""
        if self.validate_ioc(ioc, 'ip'):
            return 'ip'
        elif self.validate_ioc(ioc, 'hash'):
            return 'hash'
        elif self.validate_ioc(ioc, 'url'):
            return 'url'
        elif self.validate_ioc(ioc, 'domain'):
            return 'domain'
        return 'unknown'
    
    def query_virustotal(self, ioc: str, ioc_type: str) -> dict:
        """Query VirusTotal API."""
        result = {
            'source': 'VirusTotal',
            'available': False,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'details': {}
        }
        
        api_key = self.api_keys.get('virustotal')
        if not api_key or not REQUESTS_AVAILABLE:
            return result
        
        try:
            headers = {'x-apikey': api_key}
            
            if ioc_type == 'ip':
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
            elif ioc_type == 'domain':
                url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
            elif ioc_type == 'hash':
                url = f'https://www.virustotal.com/api/v3/files/{ioc}'
            else:
                return result
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                result['available'] = True
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['clean'] = stats.get('harmless', 0) + stats.get('undetected', 0)
                result['details'] = {
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'total_votes': stats
                }
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def query_abuseipdb(self, ip: str) -> dict:
        """Query AbuseIPDB API (IP addresses only)."""
        result = {
            'source': 'AbuseIPDB',
            'available': False,
            'abuse_score': 0,
            'total_reports': 0,
            'details': {}
        }
        
        api_key = self.api_keys.get('abuseipdb')
        if not api_key or not REQUESTS_AVAILABLE:
            return result
        
        try:
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                result['available'] = True
                result['abuse_score'] = data.get('abuseConfidenceScore', 0)
                result['total_reports'] = data.get('totalReports', 0)
                result['details'] = {
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'is_tor': data.get('isTor', False),
                    'last_reported': data.get('lastReportedAt', None)
                }
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_demo_data(self, ioc: str, ioc_type: str) -> dict:
        """Return demo data when no API keys are configured."""
        # Generate consistent "random" scores based on IOC hash
        seed = int(hashlib.md5(ioc.encode()).hexdigest()[:8], 16) % 100
        
        # Known malicious indicators for demo
        known_bad = ['evil', 'malware', 'hack', 'phish', 'bad']
        is_suspicious = any(bad in ioc.lower() for bad in known_bad)
        
        if is_suspicious:
            vt_malicious = 15 + (seed % 50)
            abuse_score = 60 + (seed % 40)
        else:
            vt_malicious = seed % 5
            abuse_score = seed % 20
        
        results = {
            'virustotal': {
                'source': 'VirusTotal',
                'available': True,
                'malicious': vt_malicious,
                'suspicious': seed % 10,
                'clean': 70 - vt_malicious,
                'details': {'reputation': -vt_malicious if vt_malicious > 5 else 0},
                'demo_mode': True
            }
        }
        
        if ioc_type == 'ip':
            results['abuseipdb'] = {
                'source': 'AbuseIPDB',
                'available': True,
                'abuse_score': abuse_score,
                'total_reports': seed % 50,
                'details': {
                    'country': 'US',
                    'isp': 'Demo ISP',
                    'is_tor': seed % 10 == 0
                },
                'demo_mode': True
            }
        
        return results
    
    def calculate_risk_score(self, results: dict, ioc_type: str) -> int:
        """Calculate composite risk score from all sources."""
        score = 0
        weights = 0
        
        # VirusTotal scoring
        vt = results.get('virustotal', {})
        if vt.get('available'):
            total_detections = vt.get('malicious', 0) + vt.get('suspicious', 0)
            # Scale: 0 detections = 0, 10+ detections = 50 points
            vt_score = min(total_detections * 5, 50)
            score += vt_score
            weights += 50
        
        # AbuseIPDB scoring (IP only)
        abuse = results.get('abuseipdb', {})
        if abuse.get('available'):
            # AbuseIPDB already gives 0-100 score
            abuse_score = abuse.get('abuse_score', 0) * 0.5
            score += abuse_score
            weights += 50
        
        # Normalize to 0-100
        if weights > 0:
            return int((score / weights) * 100)
        return 0
    
    def get_risk_level(self, score: int) -> str:
        """Convert score to risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "CLEAN"
    
    def lookup(self, ioc: str, ioc_type: str = None) -> dict:
        """Perform full IOC lookup across all sources."""
        # Auto-detect type if not specified
        if not ioc_type:
            ioc_type = self.detect_ioc_type(ioc)
        
        if ioc_type == 'unknown':
            return {'error': 'Unable to determine IOC type'}
        
        if not self.validate_ioc(ioc, ioc_type):
            return {'error': f'Invalid {ioc_type} format'}
        
        # Check if we have any API keys configured
        has_keys = any(self.api_keys.get(k) for k in ['virustotal', 'abuseipdb', 'alienvault'])
        
        if has_keys and REQUESTS_AVAILABLE:
            # Real API queries
            results = {
                'virustotal': self.query_virustotal(ioc, ioc_type)
            }
            
            if ioc_type == 'ip':
                results['abuseipdb'] = self.query_abuseipdb(ioc)
        else:
            # Demo mode
            results = self.get_demo_data(ioc, ioc_type)
        
        # Calculate composite score
        risk_score = self.calculate_risk_score(results, ioc_type)
        risk_level = self.get_risk_level(risk_score)
        
        return {
            'ioc': ioc,
            'type': ioc_type,
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'sources': results,
            'demo_mode': not has_keys or not REQUESTS_AVAILABLE
        }


def print_banner():
    """Print the tool banner."""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║       THREAT INTEL DASHBOARD v1.0             ║
    ║          IOC Reputation Lookup                ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)


def output_terminal(result: dict):
    """Output results to terminal with formatting."""
    if 'error' in result:
        print(f"\n[ERROR] {result['error']}")
        return
    
    score = result['risk_score']
    risk = result['risk_level']
    
    # Color coding
    if risk == "CRITICAL":
        risk_display = f"\033[91m{risk}\033[0m"
        score_display = f"\033[91m{score}/100\033[0m"
    elif risk == "HIGH":
        risk_display = f"\033[91m{risk}\033[0m"
        score_display = f"\033[91m{score}/100\033[0m"
    elif risk == "MEDIUM":
        risk_display = f"\033[93m{risk}\033[0m"
        score_display = f"\033[93m{score}/100\033[0m"
    else:
        risk_display = f"\033[92m{risk}\033[0m"
        score_display = f"\033[92m{score}/100\033[0m"
    
    print("\n" + "=" * 60)
    print("                    LOOKUP RESULTS")
    print("=" * 60)
    
    print(f"\n  IOC:        {result['ioc']}")
    print(f"  Type:       {result['type'].upper()}")
    print(f"  Timestamp:  {result['timestamp']}")
    
    if result.get('demo_mode'):
        print(f"\n  \033[93m[DEMO MODE - Configure API keys for real data]\033[0m")
    
    print("\n" + "-" * 60)
    print(f"  RISK SCORE: {score_display}")
    print(f"  RISK LEVEL: {risk_display}")
    print("-" * 60)
    
    # Source details
    print("\n  SOURCE RESULTS:\n")
    
    sources = result.get('sources', {})
    
    # VirusTotal
    vt = sources.get('virustotal', {})
    if vt.get('available'):
        mal = vt.get('malicious', 0)
        sus = vt.get('suspicious', 0)
        clean = vt.get('clean', 0)
        
        if mal > 0:
            print(f"  \033[91m[!]\033[0m VirusTotal: {mal} malicious, {sus} suspicious, {clean} clean")
        else:
            print(f"  \033[92m[+]\033[0m VirusTotal: {mal} malicious, {sus} suspicious, {clean} clean")
    else:
        print(f"  [ ] VirusTotal: Not available")
    
    # AbuseIPDB
    abuse = sources.get('abuseipdb', {})
    if abuse.get('available'):
        abuse_score = abuse.get('abuse_score', 0)
        reports = abuse.get('total_reports', 0)
        details = abuse.get('details', {})
        
        if abuse_score > 50:
            print(f"  \033[91m[!]\033[0m AbuseIPDB: {abuse_score}% confidence, {reports} reports")
        elif abuse_score > 0:
            print(f"  \033[93m[!]\033[0m AbuseIPDB: {abuse_score}% confidence, {reports} reports")
        else:
            print(f"  \033[92m[+]\033[0m AbuseIPDB: {abuse_score}% confidence, {reports} reports")
        
        if details:
            country = details.get('country', 'Unknown')
            isp = details.get('isp', 'Unknown')
            is_tor = details.get('is_tor', False)
            print(f"      Country: {country} | ISP: {isp}" + (" | TOR EXIT NODE" if is_tor else ""))
    
    print("\n" + "=" * 60)
    print("[*] Lookup complete.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Threat Intelligence IOC Lookup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-i", "--ioc",
        required=True,
        help="IOC to look up (IP, domain, hash, or URL)"
    )
    
    parser.add_argument(
        "-t", "--type",
        choices=["ip", "domain", "hash", "url"],
        help="IOC type (auto-detected if not specified)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path (JSON format)"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Initialize lookup engine
    lookup = ThreatIntelLookup(args.config)
    
    print(f"[*] Looking up: {args.ioc}")
    
    # Perform lookup
    result = lookup.lookup(args.ioc, args.type)
    
    # Output results
    output_terminal(result)
    
    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Results saved to: {output_path}")


if __name__ == "__main__":
    main()
