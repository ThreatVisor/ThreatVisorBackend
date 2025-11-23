#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import uuid

def run_ssl_scan(target):
    """
    Scan SSL/TLS configuration using testssl.sh
    """
    # testssl.sh command with --fast flag for performance
    output_file = '/tmp/ssl_output.json'
    cmd = ['testssl.sh', '--fast', '--jsonfile', output_file, target]
    
    print(f"🔐 Running SSL/TLS scan: {target}")
    
    try:
        # Execute testssl.sh with 120-second timeout
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Note: testssl.sh may return non-zero exit codes even on success
        # Check if output file was created
        if not os.path.exists(output_file):
            raise Exception(f"testssl.sh did not produce output file: {result.stderr}")
        
        # Parse JSON output
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        
        # Process findings - filter for HIGH and CRITICAL severity only
        for finding in data:
            severity = finding.get('severity', '').upper()
            
            # Only include HIGH and CRITICAL findings to reduce noise
            if severity in ['HIGH', 'CRITICAL']:
                severity_map = {
                    'HIGH': 'high',
                    'CRITICAL': 'critical',
                    'MEDIUM': 'medium',
                    'LOW': 'low',
                    'INFO': 'info'
                }
                
                vulnerabilities.append({
                    'id': str(uuid.uuid4()),
                    'title': finding.get('id', 'SSL/TLS Issue'),
                    'description': finding.get('finding', ''),
                    'severity': severity_map.get(severity, 'info'),
                    'url': f"https://{target}",
                    'asset_type': 'hostname',
                    'asset_identifier': target,
                    'hostname': target,
                    'scanner_name': 'testssl',
                    'scanner_category': 'network',
                    'layer': 'network',
                    'solution': 'Update SSL/TLS configuration',
                    'confidence': 'high',
                    'risk_level': 7 if severity == 'HIGH' else 10 if severity == 'CRITICAL' else 5,
                    'remediation_steps': [
                        'Review SSL/TLS configuration',
                        'Update to latest TLS version (1.3 recommended)',
                        'Remove weak cipher suites',
                        'Ensure proper certificate chain',
                        'Test configuration with SSL Labs'
                    ]
                })
        
        print(f"✅ SSL/TLS scan completed: {len(vulnerabilities)} issues found")
        
        return {
            'scanner': 'testssl',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'total_checks': len(data),
                'high_severity_findings': len([v for v in vulnerabilities if v['severity'] == 'high']),
                'critical_severity_findings': len([v for v in vulnerabilities if v['severity'] == 'critical'])
            }
        }
        
    except subprocess.TimeoutExpired:
        print(f"❌ SSL scan timeout after 120 seconds")
        raise Exception("SSL scan timed out after 120 seconds")
    except Exception as e:
        print(f"❌ SSL scan error: {str(e)}")
        raise

if __name__ == "__main__":
    # Get target from command line or environment
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('TARGET', '')
    
    if not target:
        print("❌ Error: Target hostname not provided")
        sys.exit(1)
    
    # Get output path from environment
    output_path = os.environ.get('OUTPUT_PATH', '/tmp/reports/testssl_report.json')
    
    try:
        result = run_ssl_scan(target)
        
        # Write result to JSON file
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"✅ SSL/TLS scan results written to {output_path}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

