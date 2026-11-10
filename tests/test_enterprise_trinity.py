"""
Unit tests for Kavach AI Enterprise Trinity:
1. SCA Go.mod & Reachability Scanner (core/sca_scanner.py)
2. Container & Cloud IaC Security Scanner (core/container_scanner.py)
3. Enterprise Webhook & Compliance Exporter (core/integrations.py)
"""

import pytest
from core.sca_scanner import SCAScanner
from core.container_scanner import ContainerSecurityScanner, ContainerFinding
from core.integrations import EnterpriseIntegrationDispatcher

# ==========================================
# 1. SCA Engine & Go.mod Reachability Tests
# ==========================================

def test_sca_go_mod_vulnerable_and_reachable():
    scanner = SCAScanner()
    
    go_mod = """
module my-enterprise-api

go 1.21

require (
    github.com/gin-gonic/gin v1.8.0
    golang.org/x/crypto v0.14.0
)
"""
    main_go = """
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "pong"})
    })
    r.Run()
}
"""
    findings = scanner.scan_dependencies_and_reachability(
        manifest_files={"go.mod": go_mod},
        code_files={"main.go": main_go}
    )

    assert len(findings) >= 2
    
    # gin should be reachable because it's imported in main.go
    gin_finding = next((f for f in findings if "gin" in f.package_name), None)
    assert gin_finding is not None
    assert gin_finding.is_reachable is True
    assert "Active Exploit Path" in gin_finding.reachability_status
    assert gin_finding.cve_id == "CVE-2023-29401"
    
    # crypto is NOT imported, so should be marked unreachable / dormant
    crypto_finding = next((f for f in findings if "crypto" in f.package_name), None)
    assert crypto_finding is not None
    assert crypto_finding.is_reachable is False
    assert "Dormant Library" in crypto_finding.reachability_status


def test_sca_osv_api_offline_fallback():
    scanner = SCAScanner()
    # Query with short timeout — should return empty list gracefully without throwing an exception
    vulns = scanner.query_osv_api("requests", "2.28.0", ecosystem="PyPI")
    assert isinstance(vulns, list)


# ==========================================
# 2. Container Security Scanner Tests
# ==========================================

def test_container_dockerfile_security_checks():
    scanner = ContainerSecurityScanner()
    
    insecure_dockerfile = """
FROM python:latest

ENV API_KEY="prod_secret_token_abcdef123456"

RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://get.docker.com | bash

COPY . /app
WORKDIR /app

USER root

CMD ["python", "app.py"]
"""
    findings = scanner.scan_dockerfile(insecure_dockerfile, "Dockerfile")
    
    assert len(findings) >= 4
    rule_ids = [f.rule_id for f in findings]
    
    assert "DOCKER-LATEST-TAG" in rule_ids
    assert "DOCKER-HARDCODED-SECRET" in rule_ids
    assert "DOCKER-INSECURE-PIPE" in rule_ids
    assert "DOCKER-EXPLICIT-ROOT" in rule_ids


def test_container_dockerfile_clean_compliant():
    scanner = ContainerSecurityScanner()
    
    clean_dockerfile = """
FROM python:3.11.8-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -u 1001 appuser
USER appuser

HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["python", "main.py"]
"""
    findings = scanner.scan_dockerfile(clean_dockerfile, "Dockerfile")
    
    # Clean container should have zero critical or high findings
    critical_or_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical_or_high) == 0


def test_container_docker_compose_security_checks():
    scanner = ContainerSecurityScanner()
    
    insecure_compose = """
version: '3.8'

services:
  database:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: mySuperSecretPassword123!
    ports:
      - "5432:5432"

  agent_runner:
    image: custom-agent:latest
    privileged: true
    network_mode: "host"
"""
    findings = scanner.scan_docker_compose(insecure_compose, "docker-compose.yml")
    
    assert len(findings) >= 3
    rule_ids = [f.rule_id for f in findings]
    
    assert "COMPOSE-PRIVILEGED-CONTAINER" in rule_ids
    assert "COMPOSE-HOST-NETWORK" in rule_ids
    assert "COMPOSE-EXPOSED-DATABASE-PORT" in rule_ids
    assert "COMPOSE-HARDCODED-SECRET" in rule_ids


# ==========================================
# 3. Enterprise Integration Dispatcher Tests
# ==========================================

def test_enterprise_slack_payload_formatting():
    dispatcher = EnterpriseIntegrationDispatcher()
    
    summary = [
        {"severity": "CRITICAL", "title": "SQL Injection in User Lookup", "file_path": "api/users.py", "line_number": 42, "description": "Raw string format in SQL execute sink"}
    ]
    payload = dispatcher.build_slack_payload(
        project_name="payment-service",
        total_findings=1,
        critical_count=1,
        high_count=0,
        findings_summary=summary
    )
    
    assert "blocks" in payload
    assert len(payload["blocks"]) >= 4
    header = payload["blocks"][0]["text"]["text"]
    assert "CRITICAL" in payload["blocks"][1]["text"]["text"] or "Kavach AI" in header


def test_enterprise_jira_and_linear_payloads():
    dispatcher = EnterpriseIntegrationDispatcher()
    
    finding = {
        "severity": "HIGH",
        "title": "Privileged Container Breakout",
        "file_path": "docker-compose.yml",
        "line_number": 12,
        "description": "Container running in privileged mode",
        "remediation": "Remove privileged: true flag."
    }
    
    jira = dispatcher.build_jira_payload(finding, project_key="PROD")
    assert jira["fields"]["project"]["key"] == "PROD"
    assert jira["fields"]["priority"]["name"] == "High"
    assert "kavach-ai" in jira["fields"]["labels"]
    
    linear = dispatcher.build_linear_payload(finding, team_id="team_engineering_123")
    assert linear["teamId"] == "team_engineering_123"
    assert linear["priority"] == 2
    assert "Security" in linear["labels"]


def test_enterprise_vanta_drata_evidence_mapping():
    dispatcher = EnterpriseIntegrationDispatcher()
    
    evidence = dispatcher.build_vanta_drata_evidence(
        repo_name="my-org/core-ledger",
        commit_sha="a1b2c3d4e5f6",
        gate_passed=True,
        scanned_files_count=142,
        findings_count=0,
        framework="SOC2"
    )
    
    assert evidence["framework"] == "SOC2"
    assert "CC6.1 (Logical Access Controls)" in evidence["compliance_controls"]
    assert evidence["audit_trail"]["scan_verdict"] == "PASSED"
    assert evidence["audit_trail"]["verified_zero_false_positives"] is True


def test_enterprise_dispatcher_dry_run():
    dispatcher = EnterpriseIntegrationDispatcher()
    result = dispatcher.dispatch_webhook("https://hooks.slack.com/services/TEST/MOCK", {"test": True}, dry_run=True)
    assert result["success"] is True
    assert result["status_code"] == 200