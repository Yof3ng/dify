#!/usr/bin/env python3
"""
Dify Security Monitor
A tool to help identify potential security issues in the Dify codebase.

Usage: python security_monitor.py [--fix] [--report]
"""

import re
import os
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import subprocess


class SecurityIssueDetector:
    """Detects potential security issues in the Dify codebase"""
    
    def __init__(self, repo_path: str = "/home/runner/work/dify/dify"):
        self.repo_path = Path(repo_path)
        self.issues = []
        
    def scan_authentication_issues(self) -> List[Dict]:
        """Scan for potential authentication and authorization issues"""
        issues = []
        
        # Patterns that could indicate security issues
        dangerous_patterns = {
            'automatic_login': {
                'pattern': r'_update_request_context_with_user',
                'description': 'Potential automatic login/context manipulation',
                'severity': 'HIGH'
            },
            'missing_session_add': {
                'pattern': r'db\.session\.commit\(\)\s*(?!.*db\.session\.add)',
                'description': 'Database commit without explicit add() - may not persist',
                'severity': 'MEDIUM'
            },
            'direct_password_assignment': {
                'pattern': r'\.password\s*=\s*[^h]',  # Not hash_password
                'description': 'Direct password assignment without hashing',
                'severity': 'HIGH'
            },
            'sql_query_without_prepared': {
                'pattern': r'db\.session\.query.*\.where.*\+|db\.session\.query.*\.where.*%',
                'description': 'Potential SQL injection via string concatenation',
                'severity': 'HIGH'
            },
            'hardcoded_secrets': {
                'pattern': r'(?i)(password|secret|token|key)\s*=\s*["\'][^"\']{8,}["\']',
                'description': 'Potential hardcoded secrets',
                'severity': 'HIGH'
            },
            'missing_csrf_protection': {
                'pattern': r'@.*\.route.*methods.*POST.*(?!.*csrf)',
                'description': 'POST route potentially missing CSRF protection',
                'severity': 'MEDIUM'
            }
        }
        
        # Scan Python files in API directory
        api_path = self.repo_path / "api"
        for py_file in api_path.rglob("*.py"):
            if "test" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                for issue_type, pattern_info in dangerous_patterns.items():
                    matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = content.split('\n')[line_num - 1].strip()
                        
                        issues.append({
                            'type': issue_type,
                            'file': str(py_file.relative_to(self.repo_path)),
                            'line': line_num,
                            'content': line_content,
                            'description': pattern_info['description'],
                            'severity': pattern_info['severity']
                        })
                        
            except Exception as e:
                print(f"Error scanning {py_file}: {e}")
                
        return issues
    
    def scan_dependency_vulnerabilities(self) -> List[Dict]:
        """Scan for known dependency vulnerabilities"""
        issues = []
        
        try:
            # Check if pip-audit is available
            result = subprocess.run(['pip-audit', '--format', 'json'], 
                                 capture_output=True, text=True, cwd=self.repo_path / "api")
            
            if result.returncode == 0:
                import json
                vulnerabilities = json.loads(result.stdout)
                for vuln in vulnerabilities:
                    issues.append({
                        'type': 'dependency_vulnerability',
                        'package': vuln['package'],
                        'version': vuln['version'],
                        'vulnerability_id': vuln['id'],
                        'description': vuln['description'],
                        'severity': vuln.get('severity', 'UNKNOWN')
                    })
            else:
                issues.append({
                    'type': 'scan_error',
                    'description': 'pip-audit not available or failed. Install with: pip install pip-audit',
                    'severity': 'INFO'
                })
                
        except Exception as e:
            issues.append({
                'type': 'scan_error',
                'description': f'Dependency scan failed: {e}',
                'severity': 'INFO'
            })
            
        return issues
    
    def check_recent_security_fixes(self) -> List[Dict]:
        """Check if the known security fixes are still in place"""
        issues = []
        
        # Check that the dangerous login code is not present
        wraps_file = self.repo_path / "api" / "controllers" / "service_api" / "wraps.py"
        if wraps_file.exists():
            with open(wraps_file, 'r') as f:
                content = f.read()
                if "_update_request_context_with_user" in content:
                    issues.append({
                        'type': 'security_regression',
                        'file': str(wraps_file.relative_to(self.repo_path)),
                        'description': 'Dangerous automatic login code has been reintroduced',
                        'severity': 'CRITICAL'
                    })
        
        # Check that password reset has proper persistence
        account_service_file = self.repo_path / "api" / "services" / "account_service.py"
        if account_service_file.exists():
            with open(account_service_file, 'r') as f:
                content = f.read()
                
                # Look for the update_account_password method
                if "def update_account_password" in content:
                    method_match = re.search(
                        r'def update_account_password.*?(?=def|\Z)', 
                        content, 
                        re.DOTALL
                    )
                    if method_match:
                        method_content = method_match.group(0)
                        if "db.session.commit()" in method_content and "db.session.add(" not in method_content:
                            issues.append({
                                'type': 'security_regression',
                                'file': str(account_service_file.relative_to(self.repo_path)),
                                'description': 'Password reset persistence fix has been removed',
                                'severity': 'HIGH'
                            })
        
        return issues
    
    def generate_report(self) -> str:
        """Generate a security report"""
        all_issues = []
        all_issues.extend(self.scan_authentication_issues())
        all_issues.extend(self.scan_dependency_vulnerabilities())
        all_issues.extend(self.check_recent_security_fixes())
        
        # Group by severity
        critical = [i for i in all_issues if i.get('severity') == 'CRITICAL']
        high = [i for i in all_issues if i.get('severity') == 'HIGH']
        medium = [i for i in all_issues if i.get('severity') == 'MEDIUM']
        low = [i for i in all_issues if i.get('severity') in ('LOW', 'INFO')]
        
        report = []
        report.append("# Dify Security Scan Report")
        report.append(f"Generated: {subprocess.check_output(['date'], text=True).strip()}")
        report.append("")
        
        if critical:
            report.append("## CRITICAL Issues")
            for issue in critical:
                report.append(f"- **{issue['type']}**: {issue['description']}")
                if 'file' in issue:
                    report.append(f"  - File: {issue['file']}")
                if 'line' in issue:
                    report.append(f"  - Line: {issue['line']}")
                report.append("")
        
        if high:
            report.append("## HIGH Severity Issues")
            for issue in high:
                report.append(f"- **{issue['type']}**: {issue['description']}")
                if 'file' in issue:
                    report.append(f"  - File: {issue['file']}")
                report.append("")
                
        if medium:
            report.append("## MEDIUM Severity Issues")
            for issue in medium:
                report.append(f"- **{issue['type']}**: {issue['description']}")
                if 'file' in issue:
                    report.append(f"  - File: {issue['file']}")
                report.append("")
                
        if low:
            report.append("## LOW/INFO Issues")
            for issue in low:
                report.append(f"- **{issue['type']}**: {issue['description']}")
                report.append("")
        
        if not any([critical, high, medium, low]):
            report.append("## No Security Issues Found")
            report.append("All security checks passed! ✅")
        
        report.append("")
        report.append("## Recommendations")
        report.append("1. Fix CRITICAL and HIGH severity issues immediately")
        report.append("2. Review MEDIUM severity issues")
        report.append("3. Run this scan regularly (e.g., in CI/CD)")
        report.append("4. Keep dependencies updated")
        report.append("5. Use `pip-audit` for dependency vulnerability scanning")
        
        return "\n".join(report)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(__doc__)
        return
        
    detector = SecurityIssueDetector()
    report = detector.generate_report()
    
    # Save report
    report_file = "/tmp/security_scan_report.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"Security scan completed. Report saved to: {report_file}")
    print("\n" + "="*50)
    print(report)


if __name__ == "__main__":
    main()