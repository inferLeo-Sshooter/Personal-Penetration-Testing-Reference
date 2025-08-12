**Nuclei Template Decision Chart** 

## **Nuclei Template Decision Chart**

```
             ┌─────────────────────────┐
             │ Have a target list?      │
             │ (domains, IPs, URLs)     │
             └───────────┬─────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Do you know the tech stack?  │
          │ (CMS, server, framework)     │
          └───────┬───────────┬──────────┘
                  │ Yes       │ No
                  ▼           ▼
      ┌─────────────────┐  ┌─────────────────┐
      │ Run CVE-specific │  │ Run broad scan: │
      │ templates for    │  │ `exposure/`,    │
      │ that technology  │  │ `misconfig/`,   │
      │ + `misconfig/`   │  │ `technologies/` │
      └───────┬──────────┘  └───────┬────────┘
              ▼                      ▼
     ┌─────────────────┐    ┌──────────────────┐
     │ Found open ports │    │ Tech detected    │
     │ other than HTTP? │    │ via scan results │
     └───────┬──────────┘    └───────┬──────────┘
             │ Yes                   │ Yes
             ▼                        ▼
  ┌─────────────────────┐  ┌─────────────────────┐
  │ Run `network/` for  │  │ Run tech-specific    │
  │ SSH, FTP, SMB, etc. │  │ CVEs + misconfigs    │
  └─────────────────────┘  └─────────────────────┘
```

---

## **Quick Reference Table**

| Recon Finding (Sign)          | Recommended Nuclei Tags/Templates              |
| ----------------------------- | ---------------------------------------------- |
| Just domain list              | `-tags exposure,misconfig,takeover`            |
| Discovered tech stack         | `-tags cve,misconfig` + relevant CVE folder    |
| CMS (e.g., WordPress, Joomla) | `cves/cms-name/`, `misconfiguration/cms-name/` |
| API endpoints                 | `-tags api,exposure`                           |
| Sensitive file leaks          | `exposures/`, `misconfiguration/`              |
| Open non-HTTP ports           | `network/` templates for each service          |
| Suspect outdated software     | `-tags cve` filtered by product/version        |
| Subdomains                    | `-tags takeover,misconfig,exposure`            |

---

## **Example Command Patterns**

**Broad sweep for high-value findings**

```bash
nuclei -l targets.txt -tags exposure,misconfig,takeover -severity high,critical
```

**Tech-specific scan**

```bash
nuclei -l targets.txt -t cves/tomcat/ -t misconfiguration/tomcat/
```

**API deep dive**

```bash
nuclei -l api_targets.txt -tags api,exposure
```

**Non-HTTP service scan**

```bash
nuclei -l ports.txt -tags network
```

---

💡 **Pro Tip:** Keep a **custom curated template list** instead of running all default ones — this keeps scans fast and relevant.

---

## **Nuclei Tag + Template Map for Recon**

### **1. Starting Point — You Just Got Targets**

From: `assetfinder`, `amass`, `subfinder`, `httpx` (without tech details yet)
Run **broad exposure & takeover checks**:

```bash
nuclei -l targets.txt -tags exposure,misconfig,takeover -severity high,critical
```

**Why:** Quick win scan to catch public leaks, takeover opportunities, and dangerous configs before deeper scans.

---

### **2. After Tech Fingerprinting**

From: `wappalyzer`, `webanalyze`, `httpx -tech-detect`, `whatweb`

| Tech Detected | Nuclei Templates to Run                            | Example                                 |
| ------------- | -------------------------------------------------- | --------------------------------------- |
| Apache        | `cves/apache/`, `misconfiguration/apache/`         | `nuclei -l targets.txt -t cves/apache/` |
| Nginx         | `cves/nginx/`, `misconfiguration/nginx/`           |                                         |
| WordPress     | `cves/wordpress/`, `misconfiguration/wordpress/`   |                                         |
| Joomla        | `cves/joomla/`, `misconfiguration/joomla/`         |                                         |
| Tomcat        | `cves/tomcat/`, `misconfiguration/tomcat/`         |                                         |
| Drupal        | `cves/drupal/`, `misconfiguration/drupal/`         |                                         |
| PHPMyAdmin    | `cves/phpmyadmin/`, `misconfiguration/phpmyadmin/` |                                         |

---

### **3. After Service Enumeration**

From: `naabu`, `nmap`, `rustscan`

| Service       | Templates to Run                      | Example                                               |
| ------------- | ------------------------------------- | ----------------------------------------------------- |
| FTP (21)      | `network/ftp/`, `default-logins/ftp/` | `nuclei -l ftp_hosts.txt -tags network,default-login` |
| SSH (22)      | `network/ssh/`                        |                                                       |
| SMB (139/445) | `network/smb/`                        |                                                       |
| RDP (3389)    | `network/rdp/`                        |                                                       |

---

### **4. After Finding APIs**

From: `gau`, `waybackurls`, `hakrawler`, manual discovery

Run **API-specific checks**:

```bash
nuclei -l api_targets.txt -tags api,exposure
```

**Why:** Finds open API docs, keys, CORS misconfigs, and common API vulns.

---

### **5. After Suspecting Outdated Software**

From: `nmap -sV`, `httpx -tech-detect`, CMS fingerprinting

```bash
nuclei -l outdated_targets.txt -tags cve -severity critical,high
```

**Why:** Targets known vulnerabilities matched to detected versions.

---

### **6. Subdomain Takeover Check**

From: `subfinder`, `amass`, DNS recon

```bash
nuclei -l subs.txt -tags takeover
```

**Why:** Detects dangling CNAMEs or services ready for takeover.

---

## **Quick Tag Reference**

| Tag             | Purpose                   |
| --------------- | ------------------------- |
| `cve`           | Known vulnerabilities     |
| `exposure`      | Sensitive file/data leaks |
| `misconfig`     | Bad configurations        |
| `takeover`      | Subdomain takeover        |
| `api`           | API security issues       |
| `network`       | Non-HTTP protocols        |
| `default-login` | Weak default credentials  |

---

