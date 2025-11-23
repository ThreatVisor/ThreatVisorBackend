#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import json
import sys
import os
import uuid

def check_service_security(service, version, port, protocol):
    """
    Check for known security issues with exposed services
    Returns list of vulnerability findings
    """
    issues = []
    
    # Telnet (always insecure)
    if service == 'telnet':
        issues.append({
            'title': 'Insecure Telnet Service Exposed',
            'description': f'Telnet service detected on port {port}. Telnet transmits all data including credentials in cleartext, making it vulnerable to interception.',
            'severity': 'high',
            'risk_level': 8,
            'solution': 'Disable Telnet and use SSH instead for secure remote access',
            'remediation_steps': [
                'Install and configure SSH server',
                'Disable Telnet service',
                'Update firewall rules to block port 23',
                'Audit systems for SSH key-based authentication'
            ]
        })
    
    # FTP (insecure by default)
    if service == 'ftp':
        issues.append({
            'title': 'Insecure FTP Service Exposed',
            'description': f'FTP service detected on port {port}. FTP transmits credentials in cleartext.',
            'severity': 'medium',
            'risk_level': 6,
            'solution': 'Replace with SFTP or FTPS for encrypted file transfers',
            'remediation_steps': [
                'Deploy SFTP server',
                'Migrate users and data',
                'Disable FTP service',
                'Update firewall rules'
            ]
        })
    
    # SSH on non-standard port (security through obscurity - low risk)
    if service == 'ssh' and port != '22':
        issues.append({
            'title': 'SSH Running on Non-Standard Port',
            'description': f'SSH service detected on port {port} instead of default port 22. While this may provide some obscurity, it\'s not a security control.',
            'severity': 'info',
            'risk_level': 2,
            'solution': 'Consider moving back to port 22 with strong authentication',
            'remediation_steps': [
                'Ensure key-based authentication is enforced',
                'Disable password authentication',
                'Implement fail2ban or similar brute-force protection',
                'Monitor SSH logs for suspicious activity'
            ]
        })
    
    # RDP exposed to internet
    if service == 'ms-wbt-server' or service == 'rdp' or port == '3389':
        issues.append({
            'title': 'Remote Desktop Protocol (RDP) Exposed',
            'description': f'RDP service detected on port {port}. Exposed RDP is a common attack vector for ransomware and brute force attacks.',
            'severity': 'high',
            'risk_level': 8,
            'solution': 'Restrict RDP access via VPN, implement Network Level Authentication, use strong passwords',
            'remediation_steps': [
                'Restrict RDP access to VPN-only',
                'Enable Network Level Authentication (NLA)',
                'Implement account lockout policies',
                'Monitor RDP logs for failed login attempts',
                'Consider replacing with secure alternatives like Azure Bastion'
            ]
        })
    
    # SMB exposed
    if service == 'microsoft-ds' or port in ['445', '139']:
        issues.append({
            'title': 'SMB/CIFS Service Exposed',
            'description': f'SMB service detected on port {port}. Exposed SMB is vulnerable to various attacks including EternalBlue.',
            'severity': 'critical',
            'risk_level': 9,
            'solution': 'Block SMB ports at firewall, ensure latest patches applied',
            'remediation_steps': [
                'Block ports 139 and 445 at perimeter firewall',
                'Apply latest Windows security patches',
                'Disable SMBv1 protocol',
                'Enable SMB signing',
                'Restrict SMB to internal networks only'
            ]
        })
    
    # Database exposed directly
    if service in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis', 'elasticsearch']:
        issues.append({
            'title': f'{service.upper()} Database Exposed to Network',
            'description': f'{service.capitalize()} database service detected on port {port}. Databases should not be directly accessible from external networks.',
            'severity': 'critical',
            'risk_level': 9,
            'solution': 'Restrict database access to application servers only, implement firewall rules',
            'remediation_steps': [
                'Configure firewall to allow only application server IPs',
                'Disable public network interfaces on database server',
                'Use VPN or private network for database connections',
                'Implement strong authentication',
                'Enable database audit logging'
            ]
        })
    
    return issues

def run_nmap_scan(target, scan_type='quick', options=None):
    """
    Run Nmap network scan and return normalized results
    """
    if options is None:
        options = {}
    
    scan_type = options.get('scan_type', scan_type)
    
    # Build Nmap command
    if scan_type == 'quick':
        cmd = ['nmap', '-T4', '-F', target, '-oX', '/tmp/nmap_output.xml']
    elif scan_type == 'comprehensive':
        cmd = ['nmap', '-sS', '-sV', '-O', '-A', '-p-', target, '-oX', '/tmp/nmap_output.xml']
    elif scan_type == 'stealth':
        cmd = ['nmap', '-sS', '-T2', '-f', target, '-oX', '/tmp/nmap_output.xml']
    else:
        cmd = ['nmap', '-T4', '-F', target, '-oX', '/tmp/nmap_output.xml']
    
    print(f"🌐 Running Nmap scan: {' '.join(cmd)}")
    
    try:
        # Execute Nmap
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise Exception(f"Nmap scan failed: {result.stderr}")
        
        # Parse XML output
        tree = ET.parse('/tmp/nmap_output.xml')
        root = tree.getroot()
        
        vulnerabilities = []
        open_ports_count = 0
        
        for host in root.findall('.//host'):
            # Get host info
            ip_elem = host.find('.//address[@addrtype="ipv4"]')
            if ip_elem is None:
                continue
            ip = ip_elem.get('addr')
            
            hostname_elem = host.find('.//hostname')
            hostname = hostname_elem.get('name') if hostname_elem is not None else ip
            
            # Parse ports
            for port in host.findall('.//port'):
                portid = port.get('portid')
                protocol = port.get('protocol', 'tcp')
                
                state_elem = port.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue
                
                open_ports_count += 1
                
                # Get service info
                service_elem = port.find('service')
                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                service_product = service_elem.get('product', '') if service_elem is not None else ''
                service_version = service_elem.get('version', '') if service_elem is not None else ''
                
                # Check for security issues
                issues = check_service_security(service_name, service_version, portid, protocol)
                
                for issue in issues:
                    vulnerabilities.append({
                        'id': str(uuid.uuid4()),
                        'title': issue['title'],
                        'description': issue['description'],
                        'severity': issue['severity'],
                        'url': f"{protocol}://{ip}:{portid}",
                        'solution': issue.get('solution', 'Review service configuration and apply security patches'),
                        'confidence': 'medium',
                        'risk_level': issue.get('risk_level', 5),
                        
                        # Network-specific fields
                        'asset_type': 'ip_address',
                        'asset_identifier': ip,
                        'hostname': hostname,
                        'ip_address': ip,
                        'port': int(portid),
                        'service': f"{service_name} {service_product} {service_version}".strip(),
                        
                        # Scanner attribution
                        'scanner_name': 'nmap',
                        'scanner_category': 'network',
                        'layer': 'network',
                        
                        'remediation_steps': issue.get('remediation_steps', [
                            'Review service necessity',
                            'Apply security patches',
                            'Configure firewall rules',
                            'Implement access controls'
                        ])
                    })
        
        print(f"✅ Nmap scan completed: {open_ports_count} open ports, {len(vulnerabilities)} security issues")
        
        return {
            'scanner': 'nmap',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'open_ports': open_ports_count,
                'scan_type': scan_type,
                'hosts_scanned': len(root.findall('.//host'))
            }
        }
        
    except Exception as e:
        print(f"❌ Nmap scan error: {str(e)}")
        raise

if __name__ == "__main__":
    # Get target from command line or environment
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('TARGET', '')
    scan_type = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('SCAN_TYPE', 'quick')
    options = {'scan_type': scan_type}
    
    if not target:
        print("❌ Error: Target not provided")
        sys.exit(1)
    
    # Get output path from environment
    output_path = os.environ.get('OUTPUT_PATH', '/tmp/reports/nmap_report.json')
    
    try:
        result = run_nmap_scan(target, scan_type, options)
        
        # Write result to JSON file
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ Nmap scan results written to {output_path}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

