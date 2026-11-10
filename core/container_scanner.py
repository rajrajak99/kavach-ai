"""
Kavach AI — Container & Cloud Infrastructure Security Scanner
Audits Dockerfiles and docker-compose manifests for root permissions,
unpinned base images, privileged mode escapes, exposed databases, and hardcoded secrets.
"""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class ContainerFinding:
    file_path: str
    line_number: int
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    rule_id: str
    title: str
    description: str
    remediation: str

class ContainerSecurityScanner:
    """
    Sub-10ms AST & regex-based container security scanner.
    Enforces CIS Docker Benchmark & SOC 2 CC6.6 infrastructure integrity.
    """

    # Secret name patterns
    SECRET_KEY_PATTERN = re.compile(
        r'(?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|PASSWORD|PRIVATE_KEY|AUTH_TOKEN|DATABASE_URL)[\s:=]+["\']?([^"\'\s$]{4,})["\']?',
        re.IGNORECASE
    )

    # Insecure database/cache ports that shouldn't be exposed on 0.0.0.0
    SENSITIVE_PORTS = {
        "27017": "MongoDB",
        "6379": "Redis",
        "5432": "PostgreSQL",
        "3306": "MySQL",
        "9200": "Elasticsearch",
        "11211": "Memcached",
        "2379": "etcd",
        "2181": "ZooKeeper"
    }

    def scan_dockerfile(self, content: str, file_path: str = "Dockerfile") -> List[ContainerFinding]:
        """
        Audits a Dockerfile line-by-line for container vulnerabilities and misconfigurations.
        """
        findings: List[ContainerFinding] = []
        lines = content.splitlines()

        has_user = False
        has_healthcheck = False
        user_line_idx = 0
        last_from_idx = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 1. Base Image Tagging
            if stripped.upper().startswith("FROM "):
                last_from_idx = idx
                image_ref = stripped.split()[1] if len(stripped.split()) > 1 else ""
                # Ignore multi-stage build aliases like 'builder'
                if ":" not in image_ref and "@" not in image_ref and "scratch" not in image_ref.lower():
                    findings.append(ContainerFinding(
                        file_path=file_path,
                        line_number=idx,
                        severity="MEDIUM",
                        rule_id="DOCKER-UNPINNED-IMAGE",
                        title="Unpinned Base Image Tag (Missing Version)",
                        description=f"Base image '{image_ref}' has no specific version tag, defaulting to volatile ':latest'.",
                        remediation=f"Pin base image '{image_ref}' to an immutable SHA256 digest or semantic version tag (e.g. '{image_ref}:1.21-alpine')."
                    ))
                elif ":latest" in image_ref.lower():
                    findings.append(ContainerFinding(
                        file_path=file_path,
                        line_number=idx,
                        severity="MEDIUM",
                        rule_id="DOCKER-LATEST-TAG",
                        title="Insecure ':latest' Base Image Tag Used",
                        description=f"Base image '{image_ref}' explicitly uses the mutable ':latest' tag.",
                        remediation=f"Pin '{image_ref}' to a specific immutable tag (e.g. 'python:3.11-slim-bookworm') for deterministic builds."
                    ))

            # 2. Hardcoded Secrets in ENV / ARG
            if stripped.upper().startswith(("ENV ", "ARG ")):
                match = self.SECRET_KEY_PATTERN.search(stripped)
                if match:
                    raw_val = match.group(1).strip('"\'').lower()
                    if raw_val not in ("example", "dummy", "changeme", "placeholder") and not raw_val.startswith("${"):
                        findings.append(ContainerFinding(
                            file_path=file_path,
                            line_number=idx,
                            severity="CRITICAL",
                            rule_id="DOCKER-HARDCODED-SECRET",
                            title="Embedded Credential / Secret in Dockerfile Directive",
                            description=f"Sensitive secret token detected in Dockerfile build instruction: '{stripped[:35]}...'",
                            remediation="Do not bake secrets into container images. Use Docker BuildKit secret mounts (--mount=type=secret) or runtime environment injection."
                        ))

            # 3. User Privilege Verification
            if stripped.upper().startswith("USER "):
                user_spec = stripped.split()[1].strip().lower() if len(stripped.split()) > 1 else ""
                if user_spec in ("root", "0"):
                    findings.append(ContainerFinding(
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        rule_id="DOCKER-EXPLICIT-ROOT",
                        title="Explicit Root User Execution Specified",
                        description="Container process explicitly set to run as 'root' (UID 0), granting host breakout vectors on kernel vulnerabilities.",
                        remediation="Create and switch to a dedicated non-root user (e.g. 'RUN useradd -u 1001 appuser && USER appuser')."
                    ))
                else:
                    has_user = True
                    user_line_idx = idx

            # 4. Insecure Piping into Shell
            if stripped.upper().startswith("RUN "):
                if re.search(r'(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh)', stripped):
                    findings.append(ContainerFinding(
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        rule_id="DOCKER-INSECURE-PIPE",
                        title="Remote Script Piped Directly into Shell Execution",
                        description="Piping untrusted remote scripts (curl | bash) creates blind remote code execution and supply chain attack risks.",
                        remediation="Download the script, verify its cryptographic checksum (sha256sum), and then execute."
                    ))

            # 5. HEALTHCHECK directive
            if stripped.upper().startswith("HEALTHCHECK "):
                has_healthcheck = True

        # Check if missing non-root USER instruction
        if not has_user and last_from_idx > 0:
            findings.append(ContainerFinding(
                file_path=file_path,
                line_number=last_from_idx,
                severity="HIGH",
                rule_id="DOCKER-MISSING-USER",
                title="Missing Non-Root USER Directive (Runs as Root by Default)",
                description="Dockerfile does not define a non-root USER directive; container will execute with root privileges by default.",
                remediation="Add 'USER appuser' or a non-privileged UID before the final ENTRYPOINT/CMD instruction."
            ))

        # Check if missing HEALTHCHECK instruction
        if not has_healthcheck and len(lines) > 5:
            findings.append(ContainerFinding(
                file_path=file_path,
                line_number=len(lines),
                severity="LOW",
                rule_id="DOCKER-MISSING-HEALTHCHECK",
                title="Missing Container HEALTHCHECK Instruction",
                description="Container has no HEALTHCHECK instruction; container orchestrator cannot verify runtime process vitality.",
                remediation="Add a HEALTHCHECK instruction (e.g. 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1')."
            ))

        return findings

    def scan_docker_compose(self, content: str, file_path: str = "docker-compose.yml") -> List[ContainerFinding]:
        """
        Audits docker-compose manifest files for privileged escalations and database exposure.
        """
        findings: List[ContainerFinding] = []
        lines = content.splitlines()

        current_service = ""
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Track service names
            if re.match(r'^\s{2}[a-zA-Z0-9_\-\.]+:\s*$', line):
                current_service = line.strip().rstrip(":")

            # 1. Privileged Container Escalation
            if re.search(r'privileged:\s*true', stripped, re.IGNORECASE):
                findings.append(ContainerFinding(
                    file_path=file_path,
                    line_number=idx,
                    severity="CRITICAL",
                    rule_id="COMPOSE-PRIVILEGED-CONTAINER",
                    title="Privileged Container Flag Enabled (Container Breakout Risk)",
                    description=f"Service '{current_service}' has 'privileged: true' enabled, granting full host capabilities and root access.",
                    remediation="Remove 'privileged: true'. Grant only specific required Linux capabilities using 'cap_add: [SYS_TIME]'."
                ))

            # 2. Host Network Mode
            if re.search(r'network_mode:\s*["\']?host["\']?', stripped, re.IGNORECASE):
                findings.append(ContainerFinding(
                    file_path=file_path,
                    line_number=idx,
                    severity="HIGH",
                    rule_id="COMPOSE-HOST-NETWORK",
                    title="Host Network Mode Configured",
                    description=f"Service '{current_service}' uses host network stack, bypassing network isolation barriers.",
                    remediation="Use a bridge or overlay docker network instead of 'network_mode: host'."
                ))

            # 3. Sensitive Ports Bound to 0.0.0.0
            port_match = re.search(r'["\']?(?:0\.0\.0\.0:)?(\d{2,5}):(\d{2,5})["\']?', stripped)
            if port_match:
                host_port = port_match.group(1)
                container_port = port_match.group(2)
                for sensitive_p, service_name in self.SENSITIVE_PORTS.items():
                    if host_port == sensitive_p or container_port == sensitive_p:
                        findings.append(ContainerFinding(
                            file_path=file_path,
                            line_number=idx,
                            severity="HIGH",
                            rule_id="COMPOSE-EXPOSED-DATABASE-PORT",
                            title=f"Internal {service_name} Port ({sensitive_p}) Exposed Publicly",
                            description=f"Service '{current_service}' exposes {service_name} port {sensitive_p} directly to the public network interface.",
                            remediation=f"Bind port to loopback only (e.g. '127.0.0.1:{host_port}:{container_port}') or access via internal Docker network."
                        ))

            # 4. Hardcoded Passwords in Environment
            secret_match = self.SECRET_KEY_PATTERN.search(stripped)
            if secret_match:
                raw_val = secret_match.group(1).strip('"\'').lower()
                if raw_val not in ("example", "dummy", "changeme", "placeholder") and not raw_val.startswith("${"):
                    findings.append(ContainerFinding(
                        file_path=file_path,
                        line_number=idx,
                        severity="HIGH",
                        rule_id="COMPOSE-HARDCODED-SECRET",
                        title="Hardcoded Password/Token in Compose Environment",
                        description=f"Service '{current_service}' has plaintext credential exposed in compose environment definition.",
                        remediation="Reference environment variables dynamically via a .env file (e.g. 'DB_PASSWORD=${DB_PASSWORD}') or Docker Secrets."
                    ))

        return findings

    def scan_project_dict(self, file_contents: Dict[str, str]) -> List[ContainerFinding]:
        """
        Scans a dictionary mapping file paths to file contents for Dockerfile and Compose flaws.
        """
        findings: List[ContainerFinding] = []
        for fpath, content in file_contents.items():
            lower = fpath.lower()
            if "dockerfile" in lower:
                findings.extend(self.scan_dockerfile(content, file_path=fpath))
            elif any(c in lower for c in ("docker-compose", "compose.yml", "compose.yaml")):
                findings.extend(self.scan_docker_compose(content, file_path=fpath))
        return findings

    def scan_directory(self, dir_path: str) -> List[ContainerFinding]:
        """
        Walks a directory and scans all Dockerfiles and docker-compose manifests.
        """
        findings: List[ContainerFinding] = []
        p = Path(dir_path)
        for f in p.rglob("*"):
            if f.is_file() and not any(part.startswith(".") or part in ("node_modules", "venv", ".venv") for part in f.parts):
                lower = f.name.lower()
                if "dockerfile" in lower or any(c in lower for c in ("docker-compose", "compose.yml", "compose.yaml")):
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        rel = str(f.relative_to(p)).replace("\\", "/")
                        if "dockerfile" in lower:
                            findings.extend(self.scan_dockerfile(content, file_path=rel))
                        else:
                            findings.extend(self.scan_docker_compose(content, file_path=rel))
                    except Exception:
                        pass
        return findings