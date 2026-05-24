#!/usr/bin/env python3
"""
Real Security Log Analyzer - FIXED VERSION
Analyzes actual security logs, detects real attack patterns, uses AI to explain threats
"""

import json
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict

# Try to import Google AI, but make it optional
HAS_GOOGLE_API = False
try:
    # Try new google.genai first
    try:
        import google.genai as genai
        HAS_GOOGLE_API = True
    except ImportError:
        # Fall back to deprecated package (still works)
        import google.generativeai as genai
        HAS_GOOGLE_API = True
except ImportError:
    HAS_GOOGLE_API = False

class RealThreatDetector:
    """Detects actual attack patterns in logs"""
    
    def __init__(self):
        self.indicators = []
        self.alerts = []
    
    def detect_brute_force(self, logs, threshold=5):
        """Detect brute force attacks - 5+ failed logins from same source"""
        failed_logins = defaultdict(lambda: {"count": 0, "users": set(), "timestamps": []})
        
        for log in logs:
            if any(x in log.lower() for x in ["failed", "authentication failed", "401", "invalid", "denied", "rejected"]):
                ip = self._extract_ip(log)
                user = self._extract_username(log)
                
                if ip:
                    failed_logins[ip]["count"] += 1
                    if user:
                        failed_logins[ip]["users"].add(user)
                    failed_logins[ip]["timestamps"].append(datetime.now().isoformat())
        
        for ip, data in failed_logins.items():
            if data["count"] >= threshold:
                alert = {
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH" if data["count"] >= 10 else "MEDIUM",
                    "source_ip": ip,
                    "failed_attempts": data["count"],
                    "targeted_users": list(data["users"]),
                    "evidence": f"{data['count']} failed login attempts from {ip} targeting {len(data['users'])} users"
                }
                self.alerts.append(alert)
                return alert
        
        return None
    
    def detect_privilege_escalation(self, logs):
        """Detect privilege escalation - user gaining unexpected elevated access"""
        escalations = []
        
        for log in logs:
            if any(pattern in log.lower() for pattern in ["sudo", "admin", "elevation", "privilege", "role change"]):
                if any(pattern in log.lower() for pattern in ["success", "granted", "became", "allowed"]):
                    user = self._extract_username(log)
                    if user and user not in ["root", "system", "admin"]:
                        alert = {
                            "type": "PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "user": user,
                            "evidence": log[:200],
                            "risk": "User gained elevated privileges unexpectedly"
                        }
                        escalations.append(alert)
        
        if escalations:
            self.alerts.extend(escalations)
            return escalations[0]
        
        return None
    
    def detect_data_exfiltration(self, logs):
        """Detect data exfiltration - large outbound transfers"""
        exfil_patterns = []
        
        for log in logs:
            if any(pattern in log.lower() for pattern in ["export", "download", "transfer", "sent", "uploaded", "ftp"]):
                size_match = re.search(r'(\d+)\s*(mb|gb|kb|bytes)', log, re.IGNORECASE)
                if size_match:
                    amount = int(size_match.group(1))
                    unit = size_match.group(2).lower()
                    
                    if unit == "gb":
                        amount *= 1024
                    elif unit == "bytes":
                        amount = amount / (1024 * 1024)
                    
                    if amount > 100:
                        ip = self._extract_ip(log)
                        user = self._extract_username(log)
                        
                        alert = {
                            "type": "DATA_EXFILTRATION",
                            "severity": "CRITICAL",
                            "user": user or "unknown",
                            "destination_ip": ip,
                            "data_size_mb": round(amount, 2),
                            "evidence": log[:300]
                        }
                        exfil_patterns.append(alert)
        
        if exfil_patterns:
            self.alerts.extend(exfil_patterns)
            return exfil_patterns[0]
        
        return None
    
    def detect_lateral_movement(self, logs):
        """Detect lateral movement - internal scanning"""
        lateral_patterns = []
        
        for log in logs:
            if any(pattern in log.lower() for pattern in ["nmap", "port scan", "syn", "enumerat", "scanning"]):
                ip = self._extract_ip(log)
                
                if ip and self._is_internal_ip(ip):
                    alert = {
                        "type": "LATERAL_MOVEMENT",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "activity": "Internal network scanning/enumeration",
                        "evidence": log[:250]
                    }
                    lateral_patterns.append(alert)
        
        if lateral_patterns:
            self.alerts.extend(lateral_patterns)
            return lateral_patterns[0]
        
        return None
    
    def detect_unusual_access_patterns(self, logs):
        """Detect unusual access - off-hours access"""
        access_anomalies = []
        
        for log in logs:
            try:
                if re.search(r'(2[2-3]|0[0-5]):\d{2}', log):
                    if any(pattern in log.lower() for pattern in ["login", "access", "connect", "authenticated"]):
                        user = self._extract_username(log)
                        if user and user not in ["root", "system"]:
                            alert = {
                                "type": "UNUSUAL_ACCESS_TIME",
                                "severity": "MEDIUM",
                                "user": user,
                                "time": "Off-hours (22:00-06:00)",
                                "evidence": log[:250]
                            }
                            access_anomalies.append(alert)
            except:
                pass
        
        if access_anomalies:
            self.alerts.extend(access_anomalies)
            return access_anomalies[0]
        
        return None
    
    def filter_false_positives(self):
        """Filter out likely false positives"""
        filtered = []
        system_accounts = ["root", "system", "admin", "cron", "daemon", "syslog", "service"]
        
        for alert in self.alerts:
            if alert.get("user") in system_accounts:
                continue
            
            if alert["type"] == "LATERAL_MOVEMENT":
                if alert.get("source_ip", "").startswith("10.0.1."):
                    continue
            
            filtered.append(alert)
        
        return filtered
    
    def _extract_ip(self, log):
        """Extract IP address from log"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, log)
        return match.group(0) if match else None
    
    def _extract_username(self, log):
        """Extract username from log"""
        patterns = [
            r'user[=:]?\s*([a-zA-Z0-9_.-]+)',
            r'for\s+([a-zA-Z0-9_.-]+)',
            r'([a-zA-Z0-9_.-]+)@',
            r'user:\s*([a-zA-Z0-9_.-]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _is_internal_ip(self, ip):
        """Check if IP is internal"""
        return ip.startswith(("10.", "192.168.", "172."))


class SecurityLogAnalyzer:
    """Main analyzer using AI for explanations"""
    
    def __init__(self):
        self.detector = RealThreatDetector()
        self.model = None
        
        if HAS_GOOGLE_API:
            try:
                api_key = os.environ.get("GOOGLE_API_KEY")
                if api_key:
                    genai.configure(api_key=api_key)
                    self.model = genai.GenerativeModel('gemini-pro')
                    self.has_ai = True
                else:
                    self.has_ai = False
            except Exception as e:
                print(f"⚠️  Warning: Could not initialize Google AI: {e}")
                self.has_ai = False
        else:
            self.has_ai = False
    
    def analyze_logs(self, log_content):
        """Analyze security logs and return actionable insights"""
        
        logs = self._parse_logs(log_content)
        
        print(f"\n📊 Analyzing {len(logs)} log entries...\n")
        
        print("🔍 Running threat detection algorithms...")
        self.detector.detect_brute_force(logs)
        self.detector.detect_privilege_escalation(logs)
        self.detector.detect_data_exfiltration(logs)
        self.detector.detect_lateral_movement(logs)
        self.detector.detect_unusual_access_patterns(logs)
        
        alerts = self.detector.filter_false_positives()
        
        if not alerts:
            print("✅ No real threats detected - logs look clean\n")
            return
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 999))
        
        print(f"⚠️  Found {len(alerts)} threat(s):\n")
        print("=" * 80)
        
        for i, alert in enumerate(alerts, 1):
            print(f"\n{i}. {alert['type']} - {alert['severity']}")
            print(f"   {alert.get('evidence', alert.get('risk', ''))}\n")
            
            if self.has_ai:
                explanation = self._get_ai_explanation(alert)
            else:
                explanation = self._get_default_explanation(alert)
            
            print(f"🤖 Analysis:")
            print(f"   {explanation}\n")
            
            remediation = self._get_remediation(alert)
            print(f"✅ Recommended Actions:")
            for j, step in enumerate(remediation, 1):
                print(f"   {j}. {step}")
            
            print("\n" + "=" * 80)
    
    def _parse_logs(self, content):
        """Parse logs from various formats"""
        logs = []
        
        try:
            data = json.loads(content)
            if isinstance(data, list):
                logs = [json.dumps(item) if isinstance(item, dict) else str(item) for item in data]
            elif isinstance(data, dict):
                logs = [json.dumps(data)]
        except:
            logs = content.split('\n')
        
        logs = [log.strip() for log in logs if log.strip()]
        return logs
    
    def _get_ai_explanation(self, alert):
        """Use AI to explain the threat"""
        try:
            prompt = f"""You are a cybersecurity expert. Explain this threat in simple, non-technical language.

Alert Type: {alert['type']}
Severity: {alert['severity']}
Details: {json.dumps(alert, indent=2)}

Explain in 3-4 short sentences: What happened, why it's dangerous, what comes next.
Keep it simple for a business owner."""
            
            response = self.model.generate_content(prompt, generation_config={'max_output_tokens': 200})
            return response.text
        except Exception as e:
            return self._get_default_explanation(alert)
    
    def _get_default_explanation(self, alert):
        """Fallback explanation without AI"""
        explanations = {
            "BRUTE_FORCE": "Someone is trying multiple passwords to break into your account. This is a common attack that could lead to unauthorized access if successful.",
            "PRIVILEGE_ESCALATION": "A user obtained admin-level access they shouldn't have. This is critical because they can now access anything on the system.",
            "DATA_EXFILTRATION": "A large amount of data was sent out of your network. This suggests someone may have stolen sensitive company information.",
            "LATERAL_MOVEMENT": "An attacker is scanning your internal network to find other systems to compromise. They're looking for the next target.",
            "UNUSUAL_ACCESS_TIME": "Someone logged in at an unusual time (middle of the night). This could indicate unauthorized access or account compromise."
        }
        return explanations.get(alert['type'], "Security threat detected that requires investigation.")
    
    def _get_remediation(self, alert):
        """Get remediation steps for the threat"""
        
        remediation_map = {
            "BRUTE_FORCE": [
                "Reset password for affected account(s) immediately",
                "Enable multi-factor authentication (MFA)",
                "Block the source IP at firewall for 24-48 hours",
                "Review login history for unauthorized access",
                "Force re-login for all active sessions"
            ],
            "PRIVILEGE_ESCALATION": [
                "ISOLATE the affected system from network",
                "Revoke the elevated privileges immediately",
                "Capture system logs for forensic analysis",
                "Review all commands executed by this user",
                "Patch the vulnerability that enabled escalation",
                "Monitor for lateral movement attempts"
            ],
            "DATA_EXFILTRATION": [
                "Identify all data accessed and notify privacy officer",
                "Block the destination IP/domain immediately",
                "Rotate all database credentials",
                "Assess if PII was exposed - prepare breach notification",
                "Implement DLP rules to prevent future exfiltration",
                "Review backup systems for compromise"
            ],
            "LATERAL_MOVEMENT": [
                "Identify the compromised account",
                "Revoke access immediately",
                "Scan internal network for malware/backdoors",
                "Review access logs for this account (past 7 days)",
                "Patch systems that were scanned",
                "Increase monitoring on internal networks"
            ],
            "UNUSUAL_ACCESS_TIME": [
                "Verify if the user legitimately accessed at this time",
                "Check for VPN/proxy tunneling",
                "Review what resources were accessed",
                "If unauthorized, reset password and MFA",
                "Enable login alerts for off-hours access"
            ]
        }
        
        threat_type = alert.get("type", "UNKNOWN")
        return remediation_map.get(threat_type, ["Review the threat details", "Take appropriate action"])


def main():
    """Main execution"""
    import sys
    
    print("=" * 80)
    print("🔒 REAL SECURITY LOG ANALYZER")
    print("=" * 80)
    
    log_content = None
    
    # Check if file provided as argument
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            with open(file_path, 'r') as f:
                log_content = f.read()
            print(f"\n✅ Loaded logs from: {file_path}\n")
        except FileNotFoundError:
            print(f"\n❌ File not found: {file_path}")
            print("\nUsage: python security_log_analyzer.py [log_file.txt]\n")
            return
        except Exception as e:
            print(f"\n❌ Error reading file: {e}\n")
            return
    else:
        # Interactive mode
        print("\nUsage:")
        print("  python security_log_analyzer.py sample_logs.txt")
        print("  OR paste logs directly:\n")
        
        print("Paste your security logs (press Ctrl+D on Linux/Mac or Ctrl+Z on Windows):")
        print("-" * 80)
        
        try:
            log_content = ""
            while True:
                line = input()
                log_content += line + "\n"
        except EOFError:
            pass
        except KeyboardInterrupt:
            print("\n\nExiting...")
            return
    
    if not log_content or not log_content.strip():
        print("\n❌ No logs provided.")
        print("\n📝 Using sample logs for demonstration...\n")
        log_content = get_sample_logs()
    
    analyzer = SecurityLogAnalyzer()
    analyzer.analyze_logs(log_content)


def get_sample_logs():
    """Return sample logs for testing"""
    return """
2024-01-15 10:23:45 Failed login attempt from 192.168.1.100 for user john
2024-01-15 10:24:12 Failed login attempt from 192.168.1.100 for user john
2024-01-15 10:25:33 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 10:26:01 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 10:27:15 Failed login attempt from 192.168.1.100 for user root
2024-01-15 10:28:42 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 22:45:30 User mike authenticated successfully - Off-hours access
2024-01-15 23:15:22 nmap port scan detected from 10.0.2.50 targeting 10.0.1.0/24
2024-01-16 02:33:18 User sarah@company.com downloaded 250GB of database export
"""


if __name__ == "__main__":
    main()
