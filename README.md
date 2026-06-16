# Container Security Lab: Trivy Image Scanning + Falco Runtime Detection

**Author:** Mukesh Kumar · [github.com/MukeshKumarCloud](https://github.com/MukeshKumarCloud)  
**Environment:** Fedora 42 VM · Docker · Minikube  
**Tools:** Trivy · Falco · Docker · Minikube · kubectl  
**MITRE ATT&CK:** T1059.004 · T1552.001 · T1071.001 · T1048

---

## Objective

Implement and demonstrate two complementary layers of container security:

**Layer 1 — Shift-Left (Trivy):** Scan a known-vulnerable container image before deployment. Identify CVEs, detect hardcoded secrets, and flag Dockerfile and Kubernetes manifest misconfigurations.

**Layer 2 — Runtime Detection (Falco):** Monitor a running container in real time using kernel-level syscall inspection. Detect attacker behaviour via 3 custom rules mapped to MITRE ATT&CK.

---

## Security Coverage

| Layer | Tool | Detects | Phase |
|-------|------|---------|-------|
| Shift-Left | Trivy | OS/library CVEs | Pre-deploy |
| Shift-Left | Trivy | Hardcoded secrets in image layers | Pre-deploy |
| Shift-Left | Trivy | Dockerfile best-practice violations | Pre-deploy |
| Shift-Left | Trivy | Kubernetes manifest misconfigurations | Pre-deploy |
| Runtime | Falco | Shell spawned inside container | Runtime |
| Runtime | Falco | Sensitive file reads (/etc/shadow, /etc/passwd) | Runtime |
| Runtime | Falco | Unexpected outbound network connections | Runtime |

---

## Environment

- OS: Fedora 42 (VirtualBox VM)
- Docker CE 27.x
- Minikube 1.34.x (Docker driver)
- Trivy 0.58.x
- Falco 0.39.x

---

## Project Structure
```
trivy-falco-project/
├── config.env
├── Dockerfile
├── falco-rules
│   └── custom_rules.yaml
├── index.html
├── k8s-manifests
│   └── nginx-deployment.yaml
├── scripts
│   ├── run_trivy_scans.sh
│   └── trigger_falco_rules.sh
└── trivy-scans
    ├── 01_image_cve_scan.txt
    ├── 02_image_cve_scan.json
    ├── 03_secret_scan.txt
    ├── 04_dockerfile_misconfig.txt
    ├── 05_k8s_misconfig.txt
    ├── falco_alerts_raw.txt
    └── falco_alerts.txt
```

## Part 1 — Trivy: Shift-Left Scanning

### Target: nginx:1.21.0

Chosen because it is a real publicly documented vulnerable image with known CVEs across glibc, openssl, zlib, and nginx core — all verifiable in the NVD.

### Scan 1: CVE Scan

```bash
trivy image --severity HIGH,CRITICAL nginx:1.21.0
```

**Results:**

| Severity | Count | Key Packages Affected |
|----------|-------|-----------------------|
| CRITICAL | 85 | glibc, openssl, zlib, nginx |
| HIGH | 102 | curl, libc-bin, libpcre3, ncurses |
| **Total** | **187** | |

**Selected Critical CVEs:**

| CVE | Package | CVSS | Summary |
|-----|---------|------|---------|
| CVE-2021-23017 | nginx 1.21.0 | 9.4 | Off-by-one in DNS resolver — RCE potential |
| CVE-2021-3711 | openssl 1.1.1d | 9.8 | SM2 decryption buffer overflow |
| CVE-2022-37434 | zlib 1.2.11 | 9.8 | Heap buffer overflow in inflate() |
| CVE-2021-33574 | glibc 2.28 | 9.8 | mq_notify memory corruption |
| CVE-2022-23218 | glibc 2.28 | 9.8 | Stack buffer overflow in sunrpc |

**Full output:** `trivy-scans/01_image_cve_scan.txt`

**Remediation:** Update base image to `nginx:1.25.x` — all above CVEs are patched in current upstream.

---

### Scan 2: Secret Detection

```bash
trivy image --scanners secret mukesh-vuln-nginx:latest
```

**Results:** 2 secrets detected in image layer ENV instructions:

| Secret Type | Key | Layer |
|------------|-----|-------|
| Generic Password | DB_PASSWORD | ENV layer |
| Generic API Key | API_KEY | ENV layer |

**Full output:** `trivy-scans/03_secret_scan.txt`

**Finding:** Secrets embedded in `ENV` instructions are stored unencrypted in the image manifest and visible via `docker inspect`. Use AWS Secrets Manager or HashiCorp Vault instead.

---

### Scan 3: Dockerfile Misconfiguration

```bash
trivy config ./Dockerfile
```

**Key findings:**

| Check | Result | Severity |
|-------|--------|----------|
| No USER instruction — runs as root | FAIL | HIGH |
| Secrets in ENV variables | FAIL | CRITICAL |
| No HEALTHCHECK instruction | FAIL | LOW |

**Full output:** `trivy-scans/04_dockerfile_misconfig.txt`

---

### Scan 4: Kubernetes Manifest Misconfiguration

```bash
trivy config ./k8s-manifests/
```

**Key findings:**

| Check | Result | Severity |
|-------|--------|----------|
| runAsNonRoot: false — container runs as root | FAIL | HIGH |
| No readOnlyRootFilesystem | FAIL | MEDIUM |
| No seccomp profile set | FAIL | LOW |

**Full output:** `trivy-scans/05_k8s_misconfig.txt`

---

## Part 2 — Falco: Runtime Detection

### Custom Rules

Three rules written in Falco's YAML DSL, each targeting a different MITRE ATT&CK tactic.

**Rule 1 — Shell Spawned in Container**

```yaml
- rule: Shell Spawned in Container
  condition: spawned_process and container and shell_procs
  output: "WARNING: Shell spawned in container ..."
  priority: WARNING
  tags: [T1059.004]
```

- Tactic: Execution
- Technique: T1059.004 — Unix Shell
- Trigger: `docker exec <container> /bin/bash`

**Rule 2 — Sensitive File Read in Container**

```yaml
- rule: Sensitive File Read in Container
  condition: open_read and container and fd.name in (/etc/shadow, /etc/passwd ...)
  output: "CRITICAL: Sensitive file read inside container ..."
  priority: CRITICAL
  tags: [T1552.001]
```

- Tactic: Credential Access
- Technique: T1552.001 — Credentials In Files
- Trigger: `docker exec <container> cat /etc/passwd`

**Rule 3 — Unexpected Outbound Connection**

```yaml
- rule: Unexpected Outbound Connection from Container
  condition: outbound and container and not fd.sip in (rfc_1918_addresses)
  output: "WARNING: Unexpected outbound connection from container ..."
  priority: WARNING
  tags: [T1071.001, T1048]
```

- Tactic: Command and Control / Exfiltration
- Techniques: T1071.001 — Web Protocols, T1048 — Exfiltration
- Trigger: `docker exec <container> curl http://1.1.1.1`

**Full rules:** `falco-rules/custom_rules.yaml`

---

### Falco Alert Output

All 3 rules fired successfully.
**Full output:** `trivy-scans/falco_alerts.txt`

---

## Security Findings Summary

| # | Finding | Tool | Severity | Remediation |
|---|---------|------|----------|-------------|
| 1 | 85 CRITICAL CVEs in nginx:1.21.0 | Trivy | CRITICAL | Update to nginx:1.25.x |
| 2 | Hardcoded DB_PASSWORD and API_KEY in ENV | Trivy | CRITICAL | Use Secrets Manager / Vault |
| 3 | Container running as root | Trivy | HIGH | Add USER nonroot to Dockerfile |
| 4 | No readOnlyRootFilesystem in K8s | Trivy | MEDIUM | Set readOnlyRootFilesystem: true |
| 5 | Shell exec into running container detected | Falco | WARNING | Restrict exec via RBAC + alerting |
| 6 | /etc/passwd read inside container | Falco | CRITICAL | Alert on all sensitive file reads |
| 7 | Outbound connection to 1.1.1.1 from container | Falco | WARNING | Enforce K8s NetworkPolicy egress rules |

---

## Key Learnings

1. **Image age = CVE exposure.** nginx:1.21.0 is 3 years old and has 187 CVEs. Automated base image refresh in CI/CD is not optional.

2. **ENV secrets are visible to anyone with docker inspect access.** They appear in image layers, K8s pod specs, and cloud provider audit logs.

3. **Falco works at the kernel syscall level** — a container cannot hide malicious behaviour by modifying its own process list or network tools. eBPF probes run in kernel space, outside the container's control.

4. **Every Falco rule must be MITRE-mapped.** Random detection rules with no threat model are not security engineering — they are noise generation.

5. **Trivy and Falco are complementary, not alternatives.** Trivy catches what exists in the artifact before deployment. Falco catches what happens during execution. You need both.

---
---

## References

- [Trivy Documentation](https://aquasecurity.github.io/trivy)
- [Falco Documentation](https://falco.org/docs)
- [MITRE ATT&CK — Container Techniques](https://attack.mitre.org/matrices/enterprise/containers/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NVD CVE Database](https://nvd.nist.gov)
