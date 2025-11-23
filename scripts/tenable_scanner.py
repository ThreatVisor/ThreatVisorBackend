#!/usr/bin/env python3
import requests
import sys
import json
import time
import uuid
import xml.etree.ElementTree as ET

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: tenable_scanner.py <credentials_json>'}))
        sys.exit(1)
    
    credentials = json.loads(sys.argv[1])
    
    try:
        result = fetch_tenable_scan(credentials)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


def fetch_tenable_scan(credentials: dict, scan_id: str = None) -> dict:
    """
    Fetch scan results from customer's Tenable.io instance
    
    Args:
        credentials: {
            'api_url': 'https://cloud.tenable.com',
            'access_key': 'TIO access key',
            'secret_key': 'TIO secret key'
        }
        scan_id: Optional specific scan ID, otherwise fetches latest
    """
    
    api_url = credentials.get('api_url', 'https://cloud.tenable.com').rstrip('/')
    access_key = credentials['access_key']
    secret_key = credentials['secret_key']
    
    headers = {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    print('🔍 Connecting to Tenable.io...', file=sys.stderr)
    
    try:
        # If no scan_id provided, get latest completed scan
        if not scan_id:
            scans_response = requests.get(
                f'{api_url}/scans',
                headers=headers,
                timeout=30
            )
            
            if scans_response.status_code != 200:
                raise Exception(f"Failed to fetch scans: {scans_response.status_code} - {scans_response.text}")
            
            scans_data = scans_response.json()
            scans = scans_data.get('scans', [])
            
            # Filter for completed scans
            completed_scans = [s for s in scans if s.get('status') == 'completed']
            
            if not completed_scans:
                raise Exception("No completed scans found in Tenable.io account")
            
            # Get most recent completed scan
            completed_scans.sort(key=lambda x: x.get('last_modification_date', 0), reverse=True)
            scan_id = completed_scans[0]['id']
            
            print(f'  📊 Using latest scan: {completed_scans[0].get("name", "Unknown")} (ID: {scan_id})', file=sys.stderr)
        
        # Get scan details
        scan_details_response = requests.get(
            f'{api_url}/scans/{scan_id}',
            headers=headers,
            timeout=30
        )
        
        if scan_details_response.status_code != 200:
            raise Exception(f"Failed to fetch scan details: {scan_details_response.status_code}")
        
        scan_data = scan_details_response.json()
        scan_info = scan_data.get('info', {})
        
        print(f'  📋 Scan name: {scan_info.get("name", "Unknown")}', file=sys.stderr)
        print(f'  🖥️  Hosts scanned: {scan_info.get("hostcount", 0)}', file=sys.stderr)
        
        # Export scan in Nessus format
        export_response = requests.post(
            f'{api_url}/scans/{scan_id}/export',
            headers=headers,
            json={'format': 'nessus', 'chapters': 'vuln_hosts_summary'},
            timeout=30
        )
        
        if export_response.status_code != 200:
            raise Exception(f"Failed to export scan: {export_response.status_code}")
        
        file_id = export_response.json()['file']
        
        print(f'  📦 Export initiated (file ID: {file_id})', file=sys.stderr)
        
        # Poll for export completion (max 60 seconds)
        max_attempts = 30
        for attempt in range(max_attempts):
            status_response = requests.get(
                f'{api_url}/scans/{scan_id}/export/{file_id}/status',
                headers=headers,
                timeout=10
            )
            
            status_data = status_response.json()
            status = status_data.get('status')
            
            if status == 'ready':
                print(f'  ✅ Export ready after {attempt * 2} seconds', file=sys.stderr)
                break
            
            time.sleep(2)
        else:
            raise Exception("Export timeout - took longer than 60 seconds")
        
        # Download export file
        download_response = requests.get(
            f'{api_url}/scans/{scan_id}/export/{file_id}/download',
            headers=headers,
            timeout=60
        )
        
        if download_response.status_code != 200:
            raise Exception(f"Failed to download export: {download_response.status_code}")
        
        print(f'  📥 Downloaded export ({len(download_response.content)} bytes)', file=sys.stderr)
        
        # Parse Nessus XML
        vulnerabilities = parse_tenable_xml(download_response.content)
        
        print(f'  ✅ Parsed {len(vulnerabilities)} vulnerabilities', file=sys.stderr)
        
        return {
            'scanner': 'tenable',
            'target': scan_info.get('name', 'Tenable Scan'),
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'scan_id': str(scan_id),
                'scan_name': scan_info.get('name'),
                'total_hosts': scan_info.get('hostcount', 0),
                'scan_start': scan_info.get('scan_start'),
                'scan_end': scan_info.get('scan_end'),
                'scanner_version': 'Tenable.io',
                'import_method': 'api'
            }
        }
        
    except Exception as e:
        raise Exception(f"Tenable.io integration error: {str(e)}")


def parse_tenable_xml(xml_content: bytes) -> list:
    """Parse Nessus XML format (same as Tenable export)"""
    root = ET.fromstring(xml_content)
    vulnerabilities = []
    
    severity_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'}
    
    for report_host in root.findall('.//ReportHost'):
        host = report_host.get('name', 'unknown')
        
        for item in report_host.findall('.//ReportItem'):
            severity = int(item.get('severity', 0))
            
            if severity == 0:  # Skip info findings
                continue
            
            cve_id = item.findtext('cve')
            cve_ids = [cve_id] if cve_id else []
            
            port_str = item.get('port', '0')
            port = int(port_str) if port_str.isdigit() else None
            
            vuln = {
                'id': str(uuid.uuid4()),
                'title': item.get('pluginName', 'Unknown Plugin'),
                'description': (item.findtext('description') or 'No description')[:500],
                'severity': severity_map.get(severity, 'info'),
                'cve_id': cve_id,
                'cve_ids': cve_ids,
                'solution': item.findtext('solution', 'Apply recommended patches'),
                'url': f"https://{host}",
                'confidence': 'high',
                'risk_level': int(float(item.findtext('cvss_base_score', 5) or 5)),
                'asset_type': 'hostname',
                'asset_identifier': host,
                'hostname': host,
                'port': port,
                'service': item.get('svc_name'),
                'scanner_name': 'tenable',
                'scanner_category': 'infrastructure',
                'layer': 'infrastructure',
                'remediation_steps': [(item.findtext('solution') or 'See Tenable documentation')[:200]],
                'ai_analysis': f"Tenable.io detected {item.get('pluginName')} on {host}"
            }
            
            vulnerabilities.append(vuln)
    
    return vulnerabilities


if __name__ == '__main__':
    main()

