#!/usr/bin/env python3
import requests
import json
import sys
import os
import uuid
import urllib3

# Disable SSL warnings for Wazuh (often uses self-signed certs)
urllib3.disable_warnings()

def map_wazuh_severity(wazuh_severity):
    """Map Wazuh severity levels to standard severity"""
    mapping = {
        'Critical': 'critical',
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low'
    }
    return mapping.get(wazuh_severity, 'medium')

def severity_to_risk_level(severity):
    """Convert severity to risk level (1-10)"""
    mapping = {
        'Critical': 10,
        'High': 8,
        'Medium': 6,
        'Low': 4
    }
    return mapping.get(severity, 5)

def fetch_wazuh_vulnerabilities(credentials):
    """
    Fetch vulnerabilities from Wazuh Manager API
    """
    wazuh_url = credentials.get('api_url', '').rstrip('/')
    username = credentials.get('username', '')
    password = credentials.get('password', '')
    verify_ssl = credentials.get('verify_ssl', False)
    
    if not wazuh_url or not username or not password:
        raise Exception("Wazuh credentials incomplete: api_url, username, and password required")
    
    print(f"🛡️ Connecting to Wazuh Manager: {wazuh_url}")
    
    try:
        # Authenticate with Wazuh API
        auth_response = requests.post(
            f'{wazuh_url}/security/user/authenticate',
            json={'username': username, 'password': password},
            headers={'Content-Type': 'application/json'},
            verify=verify_ssl,
            timeout=10
        )
        
        if auth_response.status_code != 200:
            raise Exception(f"Wazuh authentication failed: {auth_response.text}")
        
        token = auth_response.json()['data']['token']
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        print(f"✅ Authenticated with Wazuh")
        
        # Get list of agents
        agents_response = requests.get(
            f'{wazuh_url}/agents',
            headers=headers,
            verify=verify_ssl,
            params={'limit': 100}
        )
        
        if agents_response.status_code != 200:
            raise Exception(f"Failed to fetch agents: {agents_response.text}")
        
        agents = agents_response.json()['data']['affected_items']
        print(f"📊 Found {len(agents)} Wazuh agents")
        
        all_vulnerabilities = []
        
        # Fetch vulnerabilities for each agent (limit to first 10 for performance)
        agents_to_scan = agents[:10]
        for agent in agents_to_scan:
            agent_id = agent['id']
            agent_name = agent['name']
            agent_ip = agent.get('ip', 'Unknown')
            agent_os = agent.get('os', {}).get('name', 'Unknown OS')
            
            print(f"  🔍 Scanning agent: {agent_name} ({agent_ip})")
            
            try:
                # Get vulnerabilities for this agent
                vulns_response = requests.get(
                    f'{wazuh_url}/vulnerability/{agent_id}',
                    headers=headers,
                    verify=verify_ssl,
                    params={'limit': 500, 'select': 'cve,title,severity,name,version,architecture,detection_time'},
                    timeout=30
                )
                
                if vulns_response.status_code != 200:
                    print(f"  ⚠️ Could not fetch vulnerabilities for agent {agent_name}: {vulns_response.status_code}")
                    continue
                
                vulns = vulns_response.json()['data']['affected_items']
                
                for vuln in vulns:
                    cve_id = vuln.get('cve')
                    if cve_id and cve_id != 'NO-CVE':
                        cve_id_value = cve_id
                    else:
                        cve_id_value = None
                    
                    all_vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'title': f"{vuln.get('name', 'Unknown Package')} - {vuln.get('cve', 'NO-CVE')}",
                        'description': vuln.get('title', 'OS-level vulnerability detected by Wazuh'),
                        'severity': map_wazuh_severity(vuln.get('severity', 'Medium')),
                        'url': f"host://{agent_name}",
                        'cve_id': cve_id_value,
                        'cve_ids': [cve_id_value] if cve_id_value else [],
                        'solution': f"Update {vuln.get('name')} package on {agent_name}",
                        'confidence': 'high',
                        'risk_level': severity_to_risk_level(vuln.get('severity', 'Medium')),
                        
                        # Infrastructure-specific fields
                        'asset_type': 'hostname',
                        'asset_identifier': agent_name,
                        'hostname': agent_name,
                        'ip_address': agent_ip,
                        'package_name': vuln.get('name'),
                        'installed_version': vuln.get('version'),
                        
                        # Scanner attribution
                        'scanner_name': 'wazuh',
                        'scanner_category': 'infrastructure',
                        'layer': 'infrastructure',
                        
                        'remediation_steps': [
                            f"Update {vuln.get('name')} package to latest version",
                            f"Test update in staging environment first",
                            f"Schedule maintenance window for {agent_name}",
                            f"Apply update and verify system stability",
                            f"Re-scan with Wazuh to confirm vulnerability resolved"
                        ],
                        
                        'ai_analysis': f"Wazuh detected CVE {vuln.get('cve')} in package {vuln.get('name')} version {vuln.get('version')} on host {agent_name} ({agent_os}). This is an OS-level vulnerability requiring patch management."
                    })
                    
            except Exception as e:
                print(f"  ⚠️ Error scanning agent {agent_name}: {str(e)}")
                continue
        
        print(f"✅ Wazuh scan completed: {len(all_vulnerabilities)} vulnerabilities from {len(agents_to_scan)} agents")
        
        return {
            'scanner': 'wazuh',
            'target': 'infrastructure',
            'vulnerabilities': all_vulnerabilities,
            'scan_metadata': {
                'agents_scanned': len(agents_to_scan),
                'total_agents': len(agents),
                'wazuh_version': agents_response.json().get('data', {}).get('api_version', 'Unknown')
            }
        }
        
    except Exception as e:
        print(f"❌ Wazuh scan error: {str(e)}")
        raise

if __name__ == "__main__":
    # Get credentials from environment
    api_url = os.environ.get('WAZUH_API_URL', '')
    username = os.environ.get('WAZUH_USERNAME', '')
    password = os.environ.get('WAZUH_PASSWORD', '')
    verify_ssl = os.environ.get('WAZUH_VERIFY_SSL', 'false').lower() == 'true'
    
    if not api_url or not username or not password:
        print("❌ Error: Wazuh credentials not provided")
        print("Required environment variables: WAZUH_API_URL, WAZUH_USERNAME, WAZUH_PASSWORD")
        sys.exit(1)
    
    credentials = {
        'api_url': api_url,
        'username': username,
        'password': password,
        'verify_ssl': verify_ssl
    }
    
    # Get output path from environment
    output_path = os.environ.get('OUTPUT_PATH', '/tmp/reports/wazuh_report.json')
    
    try:
        result = fetch_wazuh_vulnerabilities(credentials)
        
        # Write result to JSON file
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ Wazuh scan results written to {output_path}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

