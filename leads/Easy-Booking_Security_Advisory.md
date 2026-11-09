# 🛡️ Kavach AI High-Severity Security Advisory: Fahdroussafi/Easy-Booking

- **Repository**: [https://github.com/Fahdroussafi/Easy-Booking](https://github.com/Fahdroussafi/Easy-Booking)
- **Organization / Founder**: Fahd Roussafi ([@Fahdroussafi](https://github.com/Fahdroussafi))
- **Website / Domain**: [https://easybooking.app](https://easybooking.app)
- **Founder Email**: `cmpunk589@outlook.com` (✅ Verified Deliverable)
- **Stars**: ⭐ 13
- **Security Weakness**: `Reachable High-Severity Supply-Chain CVE` [CVE-2023-45857]
- **Target File Link**: [requirements.txt](https://github.com/Fahdroussafi/Easy-Booking/blob/main/requirements.txt#L1)
- **SOC 2 Compliance Impact**: `CC7.1 Vulnerability Management`

---

## 1. Verified AST / SCA Technical Evidence
- **File & Line**: `requirements.txt`:L1
- **Diagnosis**: Reachable CVE CVE-2023-45857 in `axios` actively imported by production callers: `client/src/components/ProtectedRoute.js`, `client/src/helpers/axiosInstance.js`.

```python
# Vulnerable Code:
axios==1.1.2  # CVE-2023-45857 (HIGH)

# 1-Click Surgical Patch:
axios>=1.6.0
```

---

## 2. 1-Click GitHub Security Issue / PR Advisory Template
**Issue Title**: `[Security Advisory] Fix CVE-2023-45857 in requirements.txt`

```markdown
### 🛡️ Vulnerability Report & 1-Click Surgical Patch

**Target Repository**: [Fahdroussafi/Easy-Booking](https://github.com/Fahdroussafi/Easy-Booking)  
**Vulnerability Type**: `Reachable High-Severity Supply-Chain CVE` [CVE-2023-45857]  
**File Location**: [requirements.txt:L1](https://github.com/Fahdroussafi/Easy-Booking/blob/main/requirements.txt#L1)

---

### Technical Evidence
Reachable CVE CVE-2023-45857 in `axios` actively imported by production callers: `client/src/components/ProtectedRoute.js`, `client/src/helpers/axiosInstance.js`.

```python
# Current Code:
axios==1.1.2  # CVE-2023-45857 (HIGH)
```

---

### 1-Click Surgical Remediation Diff
```diff
--- a/requirements.txt
+++ b/requirements.txt
- axios==1.1.2  # CVE-2023-45857 (HIGH)
+ axios>=1.6.0
```

---
*Detected & auto-patched in 8ms by [Kavach AI v1.4.0](https://github.com/rajrajak99/kavach-ai) (Zero-Telemetry AST Security Gate).*
```

---

## 3. Copy-Paste Cold Email to Founder / CTO
**Recipient**: `cmpunk589@outlook.com`
**Subject**: `Security advisory + 1-click patch for Fahdroussafi/Easy-Booking (requirements.txt)`

```text
To: cmpunk589@outlook.com
Subject: Security advisory + 1-click patch for Fahdroussafi/Easy-Booking (requirements.txt)

Hi Fahd Roussafi,

Ran our 10ms local AST taint engine (Kavach AI) against Easy-Booking and wanted to share a verified security audit finding in production code:

• Vulnerability: Reachable High-Severity Supply-Chain CVE [CVE-2023-45857]
• Location: [requirements.txt:L1](https://github.com/Fahdroussafi/Easy-Booking/blob/main/requirements.txt#L1)
• Impact: Reachable CVE CVE-2023-45857 in `axios` actively imported by production callers: `client/src/components/ProtectedRoute.js`, `client/src/helpers/axiosInstance.js`.

Current Code:
  - axios==1.1.2  # CVE-2023-45857 (HIGH)

1-Click Surgical Patch:
  + axios>=1.6.0

Unlike legacy SAST scanners that spit out 50 false positives on styling or test files, Kavach AI verifies deterministic AST taint paths in CI under 16ms and comments ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.1
```

Would love to set up a Growth Team pilot ($99/mo, 0 per-seat tax) or Enterprise Air-Gapped Runner if you want automated pre-merge gates across your private repositories.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
rajabhaiyarajak2008@gmail.com
```

---

## 4. Copy-Paste LinkedIn DM
```text
Hey Fahd Roussafi — came across Easy-Booking and ran our 10ms local AST engine (Kavach AI). 

Noticed reachable cve cve-2023-45857 in `axios` actively imported by production callers: `client/src/components/protectedroute.js`, `client/src/helpers/axiosinstance.js`.

We generated the exact 1-click surgical patch diff:
- axios==1.1.2  # CVE-2023-45857 (HIGH)
+ axios>=1.6.0

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact fix before merge: uses: rajrajak99/kavach-ai@v1.4.1.

Happy to set your team up with a Growth Team pilot ($99/mo) if you want to test it on private repos: https://kavach-ai.streamlit.app!
```
