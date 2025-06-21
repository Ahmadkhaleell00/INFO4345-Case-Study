# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-05-28  
**Scanned By:** Ahmad Khaleel (1927975)  
**Target Application:** http://irep.iium.edu.my  
**Scan Type:** Manual Explore + Active Scan  
**Scan Duration:** 21:30 – 22:13

---

## 1. Executive Summary

| Metric                         | Value |
|-------------------------------|--------|
| Total Issues Identified       | 12     |
| Critical Issues               | 0      |
| High-Risk Issues              | 0      |
| Medium-Risk Issues            | 4      |
| Low-Risk/Informational Issues | 8      |
| Remediation Status            | Pending |

Medium-Risk Issues – Explained in Detail
Missing Content Security Policy (CSP) Header
A CSP header helps protect users from attacks such as cross-site scripting (XSS). Without this header, browsers do not restrict where scripts or other resources load from. This makes it easier for attackers to inject malicious JavaScript into the page and compromise users.

Missing Anti-Clickjacking Header
Clickjacking occurs when a site is loaded within a hidden frame on a malicious website. Without the X-Frame-Options or CSP frame-ancestors directive, an attacker can trick users into clicking something they didn’t intend, potentially changing settings or submitting forms on iREP.

Weak Authentication Method
The login form does not use strong protection mechanisms such as two-factor authentication (2FA), CAPTCHA, or rate limiting. This allows brute-force attacks, where attackers repeatedly guess login credentials until they succeed.

Absence of Anti-CSRF Tokens
Forms on the site do not include CSRF tokens. These tokens ensure that requests come from real users and not from external malicious sites. Without CSRF protection, attackers can trick logged-in users into performing unintended actions, such as submitting forms or changing account data.

🔹 Low-Risk & Informational Issues
Server Leaks Version Information
The HTTP response headers (like “Server” or “X-Powered-By”) reveal the software and version used. This gives attackers useful information to target known vulnerabilities in those versions.

X-Content-Type-Options Header Missing
Without this header (X-Content-Type-Options: nosniff), some browsers may try to guess the type of a file. This behavior can be abused to execute unexpected or harmful content.

Cross-Domain JavaScript Source File Inclusion
JavaScript files are loaded from external sources (e.g., CDNs). If those sources are compromised, attackers can inject malicious code that runs on your website.

Timestamp Disclosure (Unix)
Some pages show Unix timestamps, which may give attackers clues about server structure, response timing, or development cycles. While not dangerous alone, it helps in more advanced attacks.

Big Redirect Detected (Sensitive Info Leak)
A very long redirect URL with many query parameters can expose search data, user input, or other private fields. This could be exploited in phishing or logging attacks.

Suspicious Comments in HTML Source Code
Some HTML pages contain developer comments like <!-- TODO: remove before production -->. These might reveal logic, passwords, or hidden functions that attackers could use.

Modern Web Application Detected
This indicates the site uses modern frameworks like Angular, Vue, or React. This is informational but means additional security practices are needed for frontend apps.

User-Controllable HTML Attribute (Potential XSS)
Some form inputs or URL parameters are reflected in the page without proper sanitization. If attackers insert HTML or JavaScript in these inputs, it could lead to XSS.



---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | 0                | -                              |
| High       | 0                | -                              |
| Medium     | 4                | Missing CSP, Clickjacking, CSRF|
| Low        | 5                | Version Leak, Missing Headers  |
| Info       | 3                | Suspicious Comments, XSS       |

---

## 3. Detailed Findings

### 🛡️ Content Security Policy Header Not Set
- **Severity:** Medium  
- **Affected URL:** `http://irep.iium.edu.my`  
- **CWE ID:** 693  
- **Recommendation:** Implement strict CSP rules  
- **OWASP:** [CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

### 🛡️ Missing Anti-Clickjacking Header
- **Severity:** Medium  
- **URL:** `http://irep.iium.edu.my`  
- **CWE ID:** 1021  
- **Recommendation:** Add `X-Frame-Options: DENY`

### 🛡️ Weak Authentication Method
- **Severity:** Medium  
- **URL:** `/cgi/users/home`  
- **CWE ID:** 326  
- **Recommendation:** Use stronger authentication (e.g., 2FA)

### 🛡️ Absence of Anti-CSRF Tokens
- **Severity:** Medium  
- **URL:** `/cgi/register`  
- **CWE ID:** 352  
- **Recommendation:** Implement CSRF tokens for all forms

---

## 4. Recommendations

- Implement HTTP security headers (CSP, X-Frame-Options)
- Use 2FA and strong password policy
- Add CSRF tokens
- Remove version disclosure headers
- Sanitize all input (XSS prevention)

---

## 5. Appendix

- ZAP Version: 2.16.1  
- Total URLs Scanned: ~10  
- Additional Tools Used: None  
- Report Generated By: Ahmad Khaleel  
