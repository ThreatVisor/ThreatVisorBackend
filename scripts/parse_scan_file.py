#!/usr/bin/env python3
import sys
import json
import xml.etree.ElementTree as ET
import uuid

def main():
    if len(sys.argv) < 3:
        print(json.dumps({'error': 'Usage: parse_scan_file.py <file_path> <file_type>'}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    file_type = sys.argv[2]
    
    try:
        result = parse_scan_file(file_path, file_type)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


def parse_scan_file(file_path: str, file_type: str) -> dict:
    """Parse uploaded scan file and return normalized vulnerabilities"""
    
    parsers = {
        'burp_xml': parse_burp_xml,
        'zap_xml': parse_zap_xml,
        'nessus_xml': parse_nessus_xml,
        'nmap_xml': parse_nmap_xml,
        'openvas_xml': parse_openvas_xml
    }
    
    if file_type not in parsers:
        raise ValueError(f"Unsupported file type: {file_type}. Supported: {list(parsers.keys())}")
    
    return parsers[file_type](file_path)


def parse_burp_xml(file_path: str) -> dict:
    """Parse Burp Suite XML export"""
    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []
    
    for issue in root.findall('.//issue'):
        severity_map = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Information': 'info'}
        confidence_map = {'Certain': 'high', 'Firm': 'high', 'Tentative': 'medium'}
        
        severity_text = issue.findtext('severity', 'Information')
        
        host = issue.findtext('host', 'unknown')
        path = issue.findtext('path', '')
        url = f"https://{host}{path}" if host else path
        
        vuln = {
            'id': str(uuid.uuid4()),
            'title': issue.findtext('name', 'Unknown Issue'),
            'description': (issue.findtext('issueBackground') or issue.findtext('issueDetail') or 'No description')[:500],
            'severity': severity_map.get(severity_text, 'info'),
            'url': url,
            'solution': issue.findtext('remediationBackground') or issue.findtext('remediationDetail') or 'See Burp documentation',
            'confidence': confidence_map.get(issue.findtext('confidence', 'Certain'), 'medium'),
            'risk_level': 8 if severity_text == 'High' else 6 if severity_text == 'Medium' else 4,
            'asset_type': 'url',
            'asset_identifier': host or url,
            'scanner_name': 'burp',
            'scanner_category': 'web_app',
            'layer': 'web',
            'remediation_steps': [issue.findtext('remediationDetail') or 'See Burp Suite documentation'],
            'ai_analysis': f"Burp Suite detected {issue.findtext('name', 'vulnerability')}"
        }
        vulnerabilities.append(vuln)
    
    return {
        'scanner': 'burp',
        'vulnerabilities': vulnerabilities,
        'scan_metadata': {
            'file_type': 'burp_xml',
            'total_issues': len(vulnerabilities),
            'import_method': 'file_upload'
        }
    }


def parse_zap_xml(file_path: str) -> dict:
    """Parse OWASP ZAP XML export"""
    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []
    
    for site in root.findall('.//site'):
        site_name = site.get('name', 'unknown')
        
        for alert in site.findall('.//alertitem'):
            risk_code = alert.findtext('riskcode', '0')
            risk_map = {'3': 'high', '2': 'medium', '1': 'low', '0': 'info'}
            
            cwe_id = alert.findtext('cweid')
            wasc_id = alert.findtext('wascid')
            
            vuln = {
                'id': str(uuid.uuid4()),
                'title': alert.findtext('name', 'Unknown Alert'),
                'description': alert.findtext('desc', 'No description')[:500],
                'severity': risk_map.get(risk_code, 'info'),
                'url': alert.findtext('uri', site_name),
                'cve_ids': [],
                'cwe_id': int(cwe_id) if cwe_id and cwe_id.isdigit() else None,
                'wasc_id': int(wasc_id) if wasc_id and wasc_id.isdigit() else None,
                'solution': alert.findtext('solution', 'Apply recommended fixes'),
                'confidence': (alert.findtext('confidence', 'Medium') or 'Medium').lower(),
                'risk_level': int(risk_code) * 2 if risk_code.isdigit() else 5,
                'asset_type': 'url',
                'asset_identifier': site_name,
                'scanner_name': 'zap',
                'scanner_category': 'web_app',
                'layer': 'web',
                'remediation_steps': [alert.findtext('solution', 'Apply recommended security fixes')],
                'ai_analysis': alert.findtext('desc', 'ZAP detected security issue')[:200]
            }
            vulnerabilities.append(vuln)
    
    return {
        'scanner': 'zap',
        'vulnerabilities': vulnerabilities,
        'scan_metadata': {
            'file_type': 'zap_xml',
            'total_sites': len(root.findall('.//site')),
            'import_method': 'file_upload'
        }
    }


def parse_nessus_xml(file_path: str) -> dict:
    """Parse Nessus/Tenable XML export"""
    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []
    
    for report_host in root.findall('.//ReportHost'):
        host = report_host.get('name', 'unknown')
        
        for item in report_host.findall('.//ReportItem'):
            severity = int(item.get('severity', 0))
            if severity == 0:  # Skip informational
                continue
            
            severity_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}
            
            cve_id = item.findtext('cve')
            cve_ids = [cve_id] if cve_id else []
            
            port_str = item.get('port', '0')
            port = int(port_str) if port_str.isdigit() else None
            
            vuln = {
                'id': str(uuid.uuid4()),
                'title': item.get('pluginName', 'Unknown Vulnerability'),
                'description': item.findtext('description', 'No description')[:500],
                'severity': severity_map.get(severity, 'info'),
                'cve_id': cve_id,
                'cve_ids': cve_ids,
                'solution': item.findtext('solution', 'Apply security patches'),
                'url': f"https://{host}",
                'confidence': 'high',
                'risk_level': int(float(item.findtext('cvss_base_score', 5) or 5)),
                'asset_type': 'hostname',
                'asset_identifier': host,
                'hostname': host,
                'ip_address': None,  # Could extract from ReportHost if available
                'port': port,
                'service': item.get('svc_name'),
                'scanner_name': 'nessus',
                'scanner_category': 'infrastructure',
                'layer': 'infrastructure',
                'remediation_steps': [item.findtext('solution', 'Apply recommended patches')],
                'ai_analysis': f"Nessus detected {item.get('pluginName')} on {host}"
            }
            vulnerabilities.append(vuln)
    
    return {
        'scanner': 'nessus',
        'vulnerabilities': vulnerabilities,
        'scan_metadata': {
            'file_type': 'nessus_xml',
            'total_hosts': len(root.findall('.//ReportHost')),
            'import_method': 'file_upload'
        }
    }


def parse_nmap_xml(file_path: str) -> dict:
    """Parse Nmap XML output"""
    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []
    
    for host in root.findall('.//host'):
        ip_elem = host.find('.//address[@addrtype="ipv4"]')
        if ip_elem is None:
            continue
        ip = ip_elem.get('addr')
        
        hostname_elem = host.find('.//hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else ip
        
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            
            portid = port.get('portid')
            service_elem = port.find('service')
            service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
            
            # Create vulnerability for open port
            vuln = {
                'id': str(uuid.uuid4()),
                'title': f"Open Port {portid}/{port.get('protocol', 'tcp')} - {service}",
                'description': f"Port {portid} is open running {service} service",
                'severity': 'info',
                'url': f"tcp://{ip}:{portid}",
                'solution': 'Review if port should be exposed',
                'confidence': 'high',
                'risk_level': 3,
                'asset_type': 'ip_address',
                'asset_identifier': ip,
                'hostname': hostname,
                'ip_address': ip,
                'port': int(portid),
                'service': service,
                'scanner_name': 'nmap',
                'scanner_category': 'network',
                'layer': 'network',
                'remediation_steps': ['Review port necessity', 'Apply firewall rules if needed'],
                'ai_analysis': f"Nmap found open port {portid} ({service}) on {hostname}"
            }
            vulnerabilities.append(vuln)
    
    return {
        'scanner': 'nmap',
        'vulnerabilities': vulnerabilities,
        'scan_metadata': {
            'file_type': 'nmap_xml',
            'total_hosts': len(root.findall('.//host')),
            'import_method': 'file_upload'
        }
    }


def parse_openvas_xml(file_path: str) -> dict:
    """Parse OpenVAS XML export (similar to Nessus format)"""
    # Similar implementation to parse_nessus_xml
    # OpenVAS uses similar XML structure
    return parse_nessus_xml(file_path)  # Can reuse for now


if __name__ == '__main__':
    main()

