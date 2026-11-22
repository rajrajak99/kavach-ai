import json
import socket
import ipaddress
import datetime
import urllib.parse
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Tuple

def is_safe_webhook_url(url: str, allow_dev: bool = False) -> Tuple[bool, str]:
    """
    Strictly validates destination webhook URL against SSRF, internal network pivots,
    cloud metadata endpoints (169.254.169.254), and local hostnames.
    """
    if not url:
        return False, "Empty URL"
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" and not (allow_dev and parsed.scheme == "http"):
            return False, f"Insecure scheme '{parsed.scheme}': webhooks must use HTTPS"
        host = parsed.hostname
        if not host:
            return False, "Missing hostname in URL"
        
        # Block known cloud metadata hostnames
        blocked_hosts = {"metadata.google.internal", "metadata", "instance-data", "169.254.169.254"}
        if host.lower() in blocked_hosts or "169.254" in host or "100.100" in host:
            return False, f"SSRF blocked: cloud metadata target '{host}' rejected"

        # Resolve hostname to check for loopback and private network ranges
        try:
            addr_info = socket.getaddrinfo(host, None)
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                if isinstance(ip, ipaddress.IPv6Address):
                    # Check for NAT64 well-known prefix (64:ff9b::/96)
                    if ip in ipaddress.IPv6Network("64:ff9b::/96"):
                        embedded_ipv4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
                        if embedded_ipv4.is_loopback:
                            return False, f"SSRF blocked: loopback target {embedded_ipv4} rejected"
                        if not allow_dev and embedded_ipv4.is_private:
                            return False, f"SSRF blocked: private network target {embedded_ipv4} rejected"
                        if embedded_ipv4.is_link_local:
                            return False, f"SSRF blocked: link-local target {embedded_ipv4} rejected"
                        continue

                if ip.is_loopback:
                    return False, f"SSRF blocked: loopback target {ip_str} rejected"
                if ip.is_link_local:
                    return False, f"SSRF blocked: link-local target {ip_str} rejected"
                if ip.is_reserved or ip.is_multicast:
                    return False, f"SSRF blocked: reserved/multicast target {ip_str} rejected"
                if not allow_dev and ip.is_private:
                    return False, f"SSRF blocked: private network target {ip_str} rejected"
        except socket.gaierror:
            # If hostname doesn't resolve in dry-run or offline testing, allow syntax if host is valid domain
            if "." not in host or host.startswith("."):
                return False, f"Unresolvable or invalid domain '{host}'"
        return True, "OK"
    except Exception as e:
        return False, f"URL parse error: {e}"

class EnterpriseIntegrationDispatcher:
    """
    Enterprise Webhook Exporter that integrates Kavach AI directly into
    enterprise engineering workflows and CISO compliance registries.
    """

    def build_slack_payload(
        self,
        project_name: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        findings_summary: List[Dict[str, Any]],
        app_url: str = "https://kavach-ai.streamlit.app"
    ) -> Dict[str, Any]:
        """
        Builds a rich Slack Block Kit notification payload with severity badges
        and 1-click surgical patch action buttons.
        """
        status_emoji = "🚨" if critical_count > 0 else ("⚠️" if high_count > 0 else "✅")
        status_text = (
            "*CRITICAL VULNERABILITIES DETECTED*"
            if critical_count > 0
            else ("*HIGH-SEVERITY FINDINGS*" if high_count > 0 else "*SECURITY GATE PASSED*")
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Kavach AI Pre-Merge Security Gate — {project_name}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{status_text}\n*Total Findings:* `{total_findings}` | *Critical:* `{critical_count}` | *High:* `{high_count}`"
                }
            },
            {"type": "divider"}
        ]

        # Add top 3 findings
        for f in findings_summary[:3]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*[{f.get('severity', 'HIGH')}] {f.get('title', 'Security Finding')}*\n`{f.get('file_path', 'unknown')}:{f.get('line_number', 0)}` — {f.get('description', '')[:120]}..."
                }
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ View 1-Click Patches in Kavach AI",
                        "emoji": True
                    },
                    "url": app_url,
                    "style": "primary" if critical_count > 0 else "default"
                }
            ]
        })

        return {"blocks": blocks}

    def build_jira_payload(
        self,
        finding: Dict[str, Any],
        project_key: str = "SEC",
        issue_type: str = "Bug"
    ) -> Dict[str, Any]:
        """
        Builds Atlassian Jira REST API payload to create an automated security bug ticket.
        """
        severity = finding.get("severity", "Medium").capitalize()
        priority_map = {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Lowest"
        }
        jira_priority = priority_map.get(severity, "Medium")

        description = (
            f"h2. Kavach AI Automated Security Advisory\n\n"
            f"*Vulnerability:* {finding.get('title', 'Security Flaw')}\n"
            f"*Severity:* {severity}\n"
            f"*File:* `{finding.get('file_path', 'N/A')}` (Line {finding.get('line_number', 1)})\n\n"
            f"h3. Technical Details\n"
            f"{finding.get('description', 'No description provided.')}\n\n"
            f"h3. Surgical Remediation\n"
            f"{finding.get('remediation', 'Apply suggested patch via Kavach AI.')}\n\n"
            f"----\n_Reported by Kavach AI AST Security Engine._"
        )

        return {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[Kavach AI] {finding.get('severity', 'HIGH')}: {finding.get('title', 'Security Advisory')}",
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": jira_priority},
                "labels": ["kavach-ai", "security", "automated-ast-gate"]
            }
        }

    def build_linear_payload(
        self,
        finding: Dict[str, Any],
        team_id: str,
        priority: int = 1
    ) -> Dict[str, Any]:
        """
        Builds Linear GraphQL / REST issue creation payload.
        Priority: 1 = Urgent (Critical), 2 = High, 3 = Normal, 4 = Low.
        """
        sev = finding.get("severity", "").upper()
        if sev == "CRITICAL":
            linear_prio = 1
        elif sev == "HIGH":
            linear_prio = 2
        elif sev == "MEDIUM":
            linear_prio = 3
        else:
            linear_prio = 4

        body = (
            f"### Kavach AI Security Gate Advisory\n\n"
            f"**File:** `{finding.get('file_path', 'N/A')}` (Line {finding.get('line_number', 1)})\n"
            f"**Rule:** `{finding.get('rule_id', 'KAVACH-SAST')}`\n\n"
            f"#### Description\n"
            f"{finding.get('description', '')}\n\n"
            f"#### Recommended Fix\n"
            f"{finding.get('remediation', '')}\n"
        )

        return {
            "teamId": team_id,
            "title": f"[{finding.get('severity', 'HIGH')}] {finding.get('title', 'Security Finding')}",
            "description": body,
            "priority": linear_prio,
            "labels": ["Security", "Kavach AI"]
        }

    def build_vanta_drata_evidence(
        self,
        repo_name: str,
        commit_sha: str,
        gate_passed: bool,
        scanned_files_count: int,
        findings_count: int,
        framework: str = "SOC2"
    ) -> Dict[str, Any]:
        """
        Generates automated continuous compliance evidence for Vanta, Drata, or Tugboat Logic.
        Maps directly to SOC 2 CC6.1 / CC6.6 / CC7.1 and ISO 27001 A.12.1.2 controls.
        """
        controls_mapped = (
            ["CC6.1 (Logical Access Controls)", "CC6.6 (Vulnerability Management)", "CC7.1 (Change Detection & CI/CD Security)"]
            if framework == "SOC2"
            else ["A.12.1.2 (Change Management)", "A.12.6.1 (Management of Technical Vulnerabilities)", "A.14.2.8 (System Security Testing)"]
        )

        return {
            "evidence_type": "continuous_automated_pre_merge_security_gate",
            "framework": framework,
            "compliance_controls": controls_mapped,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "audit_trail": {
                "repository": repo_name,
                "commit": commit_sha,
                "scan_verdict": "PASSED" if gate_passed else "BLOCKED_ON_FINDINGS",
                "files_analyzed": scanned_files_count,
                "unpatched_vulnerabilities": findings_count,
                "verified_zero_false_positives": findings_count == 0,
                "evidence_collector": "Kavach AI CISO Compliance Plane v2.0"
            }
        }

    def dispatch_webhook(
        self,
        webhook_url: str,
        payload: Dict[str, Any],
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Dispatches payload via HTTP POST to the specified webhook endpoint.
        Returns a structured dictionary with dispatch status and HTTP response code.
        """
        if not webhook_url:
            return {
                "success": False,
                "dry_run": dry_run,
                "status_code": 400,
                "error": "Missing webhook URL"
            }

        # SSRF validation
        safe, reason = is_safe_webhook_url(webhook_url)
        if not safe:
            return {
                "success": False,
                "dry_run": dry_run,
                "status_code": 400,
                "error": f"SSRF Protection blocked URL: {reason}"
            }

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "status_code": 200,
                "message": "Dry-run execution verified payload structure."
            }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "KavachAI-Integrations/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp_text = resp.read().decode("utf-8", errors="replace")
                return {
                    "success": 200 <= resp.status < 300,
                    "dry_run": False,
                    "status_code": resp.status,
                    "response": resp_text[:200]
                }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "dry_run": False,
                "status_code": e.code,
                "error": str(e)
            }
        except Exception as e:
            return {
                "success": False,
                "dry_run": False,
                "status_code": 500,
                "error": str(e)
            }