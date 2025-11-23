#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import uuid

def severity_to_risk_level(severity):
    """Convert Trivy severity to risk level (1-10)"""
    mapping = {
        'CRITICAL': 10,
        'HIGH': 8,
        'MEDIUM': 6,
        'LOW': 4,
        'UNKNOWN': 2
    }
    return mapping.get(severity.upper(), 5)

def map_trivy_severity(severity):
    """Map Trivy severity to standard severity"""
    mapping = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
        'UNKNOWN': 'low'
    }
    return mapping.get(severity.upper(), 'medium')

def run_trivy_scan(image, options=None):
    """
    Scan container image for vulnerabilities using Trivy
    """
    if options is None:
        options = {}
    
    severity = options.get('severity_filter', 'CRITICAL,HIGH,MEDIUM')
    scan_type = options.get('scan_type', 'vuln')
    
    # Build Trivy command
    cmd = ['trivy', 'image', '--format', 'json', '--severity', severity]
    
    if scan_type == 'all':
        cmd.extend(['--scanners', 'vuln,secret,config'])
    else:
        cmd.extend(['--scanners', scan_type])
    
    cmd.append(image)
    
    print(f"🐳 Running Trivy scan: {' '.join(cmd)}")
    
    try:
        # Execute Trivy
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0 and result.returncode != 1:  # Trivy returns 1 if vulns found
            raise Exception(f"Trivy scan failed: {result.stderr}")
        
        # Parse JSON output
        data = json.loads(result.stdout) if result.stdout else {}
        
        vulnerabilities = []
        
        for scan_result in data.get('Results', []):
            target_type = scan_result.get('Type', 'Unknown')
            
            # Process vulnerabilities
            for vuln in scan_result.get('Vulnerabilities', []):
                cve_id = vuln.get('VulnerabilityID')
                if cve_id and cve_id.startswith('CVE'):
                    cve_id_value = cve_id
                else:
                    cve_id_value = None
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'title': f"{vuln.get('PkgName', 'Unknown')} - {vuln.get('VulnerabilityID', 'UNKNOWN')}",
                    'description': vuln.get('Description', 'No description available')[:500],
                    'severity': map_trivy_severity(vuln.get('Severity', 'MEDIUM')),
                    'url': f"container://{image}",
                    'cve_id': cve_id_value,
                    'cve_ids': [cve_id_value] if cve_id_value else [],
                    'solution': f"Upgrade {vuln.get('PkgName')} from {vuln.get('InstalledVersion')} to {vuln.get('FixedVersion')}" if vuln.get('FixedVersion') else 'No fix available yet',
                    'confidence': 'high',
                    'risk_level': severity_to_risk_level(vuln.get('Severity', 'MEDIUM')),
                    
                    # Container-specific fields
                    'asset_type': 'container_image',
                    'asset_identifier': image,
                    'package_name': vuln.get('PkgName'),
                    'installed_version': vuln.get('InstalledVersion'),
                    'fixed_version': vuln.get('FixedVersion'),
                    
                    # Scanner attribution
                    'scanner_name': 'trivy',
                    'scanner_category': 'container',
                    'layer': 'container',
                    
                    'remediation_steps': [
                        f"Update {vuln.get('PkgName')} package to version {vuln.get('FixedVersion')}" if vuln.get('FixedVersion') else f"Monitor {vuln.get('PkgName')} for security updates",
                        'Rebuild container image with updated dependencies',
                        'Test updated image in staging environment',
                        'Deploy to production with rolling update',
                        'Verify vulnerability is resolved with follow-up scan'
                    ],
                    
                    'ai_analysis': f"Container image {image} contains vulnerable package {vuln.get('PkgName')} version {vuln.get('InstalledVersion')}. " + 
                                  (f"Update to version {vuln.get('FixedVersion')} is available." if vuln.get('FixedVersion') else "No fix is currently available.")
                })
            
            # Process secrets (if scanning for secrets)
            for secret in scan_result.get('Secrets', []):
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'title': f"Exposed Secret: {secret.get('Title', 'Unknown')}",
                    'description': f"Secret detected in {secret.get('Target', 'container')}: {secret.get('Match', '')[:100]}",
                    'severity': 'critical',
                    'url': f"container://{image}",
                    'solution': 'Remove hardcoded secrets, use environment variables or secret management systems',
                    'confidence': 'high',
                    'risk_level': 10,
                    
                    'asset_type': 'container_image',
                    'asset_identifier': image,
                    
                    'scanner_name': 'trivy',
                    'scanner_category': 'container',
                    'layer': 'container',
                    
                    'remediation_steps': [
                        'Remove hardcoded secrets from code/configuration',
                        'Use Azure Key Vault or similar secret management',
                        'Rotate compromised credentials immediately',
                        'Implement secret scanning in CI/CD pipeline',
                        'Audit code repository for historical secrets'
                    ]
                })
        
        print(f"✅ Trivy scan completed: {len(vulnerabilities)} issues found")
        
        return {
            'scanner': 'trivy',
            'target': image,
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'image': image,
                'total_vulnerabilities': len([v for v in vulnerabilities if v.get('cve_id')]),
                'total_secrets': len([v for v in vulnerabilities if 'Secret' in v.get('title', '')]),
                'scan_type': scan_type
            }
        }
        
    except Exception as e:
        print(f"❌ Trivy scan error: {str(e)}")
        raise

if __name__ == "__main__":
    # Get image from command line or environment
    image = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('IMAGE', '')
    
    if not image:
        print("❌ Error: Image name not provided")
        sys.exit(1)
    
    # Get options from environment
    severity = os.environ.get('SEVERITY_FILTER', 'CRITICAL,HIGH,MEDIUM')
    scan_type = os.environ.get('SCAN_TYPE', 'vuln')
    options = {
        'severity_filter': severity,
        'scan_type': scan_type
    }
    
    # Get output path from environment
    output_path = os.environ.get('OUTPUT_PATH', '/tmp/reports/trivy_report.json')
    
    try:
        result = run_trivy_scan(image, options)
        
        # Write result to JSON file
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ Trivy scan results written to {output_path}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

