# Security Assessments

Vulnerability assessments vs penetration tests
Vulnerability assessements look for vulnerablities in networks without simulating cyber attacks. All companies should perform vulnerabiliity assessments every so often. Compliance with GDPR and OWASP for example. 

During a vulnerability assessment, the assessor will typically run a vulnerability scan and then perform validation on critical, high, and medium-risk vulnerabilities. This means that they will show evidence that the vulnerability exists and is not a false positive, often using other tools, but will not seek to perform privilege escalation, lateral movement, post-exploitation, etc., if they validate, for example, a remote code execution vulnerability.

A pentest simulates a cyber attacker attacking the organization. An organization may benefiit more from vulnerability asessment over a pentest. 

# Vulnerability assessment
    1. Conduct risk identification and analysis
    2. Develop vulnerability scanning policies
    3. Identify the type of scans
    4. configure the scan
    5. perform the scan
    6. Evaluate and consider possible risks 
    7. Interpret the scan results
    8. Create a remediation and mitigation plan

Common exploit websites:
- [Exploit DB](https://www.exploit-db.com/)
- [Rapid7](https://www.rapid7.com/db/)

Common compliance standards:
    PCI
    HIPPA
    FISMA
    ISO 27001
    PCI DSS - Payment Card Industry Data Security Standard

OWASP

OWASP stands for the Open Web Application Security Project. They're typically the go-to organization for defining testing standards and classifying risks to web applications.

OWASP maintains a few different standards and helpful guides for assessment various technologies:

    [Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
    [Mobile Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
    [Firmware Security Testing Methodology](https://github.com/scriptingxss/owasp-fstm)

# CVSS - Common Vulnerability Scoring System
### Exploitability Metrics

The Exploitability metrics are a way to evaluate the technical means needed to exploit the issue using the metrics below:

    Attack Vector
    Attack Complexity
    Privileges Required
    User Interaction

![Image Description](./images/cia_triad.png)
Confidentiality Impact relates to securing information and ensuring only authorized individuals have access. For example, a high severity value would be in the case of an attacker stealing passwords or encryption keys. A low severity value would relate to an attacker taking information that may not be a vital asset to an organization.

Integrity Impact relates to information not being changed or tampered with to maintain accuracy. For example, a high severity would be if an attacker modified crucial business files in an organization's environment. A low severity value would be if an attacker could not specifically control the number of changed or modified files.

Availability Impact relates to having information readily attainable for business requirements. For example, a high value would be if an attacker caused an environment to be completely unavailable for business. A low value would be if an attacker could not entirely deny access to business assets and users could still access some organization assets.

# OVAL

    `OVAL Vulnerability Definitions`: Identifies system vulnerabilities
    `OVAL Compliance Definitions`: Identifies if current system configurations meet system policy requirements
   ` OVAL Inventory Definitions`: Evaluates a system to see if a specific software is present
    `OVAL Patch Definitions`: Identifies if a system has the appropriate patch

# Vulnerability Scanning Overview
[Nessus Essentials](https://community.tenable.com/s/article/Nessus-Essentials) by Tenable is the free version of the official Nessus Vulnerability Scanner. Individuals can access Nessus Essentials to get started understanding Tenable's vulnerability scanner. The caveat is that it can only be used for up to 16 hosts. The features in the free version are limited but are perfect for someone looking to get started with Nessus. The free scanner will attempt to identify vulnerabilities in an environment.

### OpenVAS Overview

[OpenVAS](https://www.openvas.org/) by Greenbone Networks is a publicly available open-source vulnerability scanner. OpenVAS can perform network scans, including authenticated and unauthenticated testing.

# Nessus
`sudo systemctl start nessusd.service`
`https://localhost:8834`

If we want to monitor the bandwidth expence on the network due to scans, we can use`vnstat`
`sudo vnstat -l -i eth0`

We can compare this result with the result we get when monitoring the same interface during a Nessus scan against just one host:
`sudo vnstat -l -i eth0`

    Note: The VM provided at the Nessus Skills Assessment section has Nessus pre-installed and the targets running. You can go to that section and start the VM and use Nessus throughout the module, which can be accessed at https:// < IP >:8834. The Nessus credentials are: htb-student:HTB_@cademy_student!. You may also use these credentials to SSH into the target VM to configure Nessus.

# OpenVAS

Installing:
```bash
sudo apt-get update && apt-get -y full-upgrade
sudo apt-get install gvm && openva

gvm-setup

gvm-start
```

Note: The VM provided in the OpenVAS Skills Assessment section has OpenVAS pre-installed and the targets running. You can go to that section and start the VM and use OpenVAS throughout the module, which can be accessed at https://< IP >:8080. The OpenVAS credentials are: htb-student:HTB_@cademy_student!. You may also use these credentials to SSH into the target VM to configure OpenVAS.



