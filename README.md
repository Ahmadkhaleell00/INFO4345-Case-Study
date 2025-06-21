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


- Medium-Risk Issues 
1- Missing Content Security Policy (CSP) Header
A CSP header helps protect users from attacks such as cross-site scripting (XSS). Without this header, browsers do not restrict where scripts or other resources load from. This makes it easier for attackers to inject malicious JavaScript into the page and compromise users.

2- Missing Anti-Clickjacking Header
Clickjacking occurs when a site is loaded within a hidden frame on a malicious website. Without the X-Frame-Options or CSP frame-ancestors directive, an attacker can trick users into clicking something they didn’t intend, potentially changing settings or submitting forms on iREP.

3- Weak Authentication Method
The login form does not use strong protection mechanisms such as two-factor authentication (2FA), CAPTCHA, or rate limiting. This allows brute-force attacks, where attackers repeatedly guess login credentials until they succeed.

4- Absence of Anti-CSRF Tokens
Forms on the site do not include CSRF tokens. These tokens ensure that requests come from real users and not from external malicious sites. Without CSRF protection, attackers can trick logged-in users into performing unintended actions, such as submitting forms or changing account data.



 - Low-Risk & Informational Issues
1- Server Leaks Version Information
The HTTP response headers (like “Server” or “X-Powered-By”) reveal the software and version used. This gives attackers useful information to target known vulnerabilities in those versions.

2= X-Content-Type-Options Header Missing
Without this header (X-Content-Type-Options: nosniff), some browsers may try to guess the type of a file. This behavior can be abused to execute unexpected or harmful content.

3- Cross-Domain JavaScript Source File Inclusion
JavaScript files are loaded from external sources (e.g., CDNs). If those sources are compromised, attackers can inject malicious code that runs on your website.

4- Timestamp Disclosure (Unix)
Some pages show Unix timestamps, which may give attackers clues about server structure, response timing, or development cycles. While not dangerous alone, it helps in more advanced attacks.

5- Big Redirect Detected (Sensitive Info Leak)
A very long redirect URL with many query parameters can expose search data, user input, or other private fields. This could be exploited in phishing or logging attacks.

6- Suspicious Comments in HTML Source Code
Some HTML pages contain developer comments like <!-- TODO: remove before production -->. These might reveal logic, passwords, or hidden functions that attackers could use.

7- Modern Web Application Detected
This indicates the site uses modern frameworks like Angular, Vue, or React. This is informational but means additional security practices are needed for frontend apps.

8- User-Controllable HTML Attribute (Potential XSS)
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

🔸 Medium-Risk Issues (4 Total)

1- Missing Content Security Policy (CSP) Header
Without a CSP, the browser has no rule for where scripts or styles are allowed to come from. This increases the risk of cross-site scripting (XSS), where an attacker can inject malicious code into the website.

2- Missing Anti-Clickjacking Header
The website lacks the X-Frame-Options header, which means it can be loaded inside another site’s iframe. An attacker could trick users into clicking buttons on the iREP site without their knowledge.

3- Weak Authentication Method
The login system lacks strong protection mechanisms like rate limiting, CAPTCHA, or 2FA. This makes it easier for attackers to try guessing passwords (brute-force attack).

4- Absence of Anti-CSRF Tokens
Forms don’t have CSRF tokens. That means a malicious website could trick a logged-in user into submitting a request on the iREP site, like updating their profile or submitting a document, without knowing.

🔹 Low-Risk Issues (5 Total)

1- Server Leaks Version Information
The HTTP headers reveal which server software is being used (e.g., Apache, Nginx), which helps attackers know what version or technology to target.

2- X-Content-Type-Options Header Missing
This header prevents browsers from interpreting files as something else (e.g., executing a plain text file as JavaScript). Without it, there's a small chance of unexpected behavior.

3- Cross-Domain JavaScript Source File Inclusion
The site loads JS files from external sources (like CDNs or third-party sites). If these are compromised, the attacker could run scripts on your site.

4- Timestamp Disclosure (Unix)
Some pages show server timestamps, which may help attackers understand server behavior or plan time-based attacks.

5- Big Redirect Detected (Potential Sensitive Info Leak)
Long redirect URLs with too many query parameters may leak sensitive data (like search filters, email addresses, etc.).

🔹 Informational Issues (3 Total)

1- Information Disclosure – Suspicious Comments
Some HTML comments in the code might contain hints about the backend, unfinished features, or internal logic. If attackers read this, they might find a way in.

2- Modern Web Application
This is just informational. It means the application uses modern front-end frameworks, which could have their own risks if not managed properly.

3- Potential XSS (User Controllable HTML Element)
There’s a field where user input directly affects an HTML element. If not sanitized properly, it can lead to XSS.


---

## 3. Detailed Findings

### 🛡️ Content Security Policy Header Not Set
- **Severity:** Medium  
- **Affected URL:** `http://irep.iium.edu.my`  
- **CWE ID:** 693  
- **Recommendation:** Implement strict CSP rules  
- **OWASP:** [CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

CWE-693 – Missing Content Security Policy Header
Definition: The application fails to define a Content Security Policy, leaving it open to content injection from untrusted sources.

Risk: Without CSP, attackers can inject scripts and access cookies or deface the UI.

Real-World Impact: Leads to XSS attacks — user data theft, account hijacking.

### 🛡️ Missing Anti-Clickjacking Header
- **Severity:** Medium  
- **URL:** `http://irep.iium.edu.my`  
- **CWE ID:** 1021  
- **Recommendation:** Add `X-Frame-Options: DENY`

  CWE-1021 – Missing Anti-Clickjacking Protection
Definition: The app does not prevent itself from being loaded in an iframe.

Risk: Users may be tricked into interacting with invisible elements.

Real-World Impact: Account changes or transactions done unknowingly by user clicks.

### 🛡️ Weak Authentication Method
- **Severity:** Medium  
- **URL:** `/cgi/users/home`  
- **CWE ID:** 326  
- **Recommendation:** Use stronger authentication (e.g., 2FA)

  CWE-326 – Weak Authentication
Definition: Login system doesn’t enforce proper security like password strength or 2FA.

Risk: Allows automated bots to guess passwords.

Real-World Impact: Attacker gains access to sensitive academic files or user profiles.



### 🛡️ Absence of Anti-CSRF Tokens
- **Severity:** Medium  
- **URL:** `/cgi/register`  
- **CWE ID:** 352  
- **Recommendation:** Implement CSRF tokens for all forms

   CWE-352 – No CSRF Tokens
Definition: Forms lack a unique token to verify the request is from a real user session.

Risk: Malicious links or scripts can perform actions using your session.

Real-World Impact: Email updates, submissions, or edits can be made without consent.

---

## 4. Recommendations

- Implement HTTP security headers (CSP, X-Frame-Options)
- Use 2FA and strong password policy
- Add CSRF tokens
- Remove version disclosure headers
- Sanitize all input (XSS prevention)
- Add Content-Security-Policy headers to control script loading.
- Implement X-Frame-Options: DENY or frame-ancestors 'none' to prevent clickjacking.
- Add CSRF tokens to every form and verify them server-side.
- Improve authentication:
  1- Enforce strong passwords
  2- Add CAPTCHA
- Enable Two-Factor Authentication (2FA)
- Remove or anonymize server information from HTTP headers.
- Add X-Content-Type-Options: nosniff header to avoid content type guessing.
- Host critical JavaScript files locally or use trusted, integrity-checked CDNs.
- Avoid exposing timestamps unless absolutely necessary.
- Minimize query parameters in redirect URLs and avoid exposing user data.
- Remove all developer or debug comments from HTML before deployment.
- Sanitize all user input, especially inputs shown in the page, to prevent XSS.
- Regularly scan the application using ZAP or other tools to catch new issues.

- my Opinion :

  
  As a student enrolled in the Web Application Security course, conducting this scan was a very practical and eye-opening experience. While learning about web vulnerabilities in theory is important, actually applying the tools—like OWASP ZAP—to a real university system made me better understand how even small configuration issues can lead to serious risks.

I was surprised to see that the iREP system, which is used by hundreds or even thousands of IIUM users, is still missing several basic protections like CSP headers, CSRF tokens, and clickjacking defenses. These are not advanced or expensive features — they are simple settings that can be enabled at the server level. Yet, not having them opens the door to attacks that can affect users’ safety and trust in the system.

- my Recommendations

  
As a student and future developer or security analyst, here are my honest recommendations for improving not just iREP, but any university system:

Make security part of the design — not an afterthought.
Many of the problems found could have been avoided if security headers and form protections were considered during development.

Train developers and web admins about OWASP Top 10.
Understanding these risks should be a basic requirement before launching any web app.

Automate security scanning.
Tools like ZAP or Burp Suite should be run monthly — even just passively — to catch misconfigurations early.

Improve user authentication and privacy.
Adding 2FA, strong password rules, and masking server info protects both users and the system.

Encourage a security mindset at the university.
Security is not just the responsibility of the IT department. Students, staff, and developers should all know the basics of safe application usage and development.



---

## 5. Appendix

- ZAP Version: 2.16.1  
- Total URLs Scanned: ~10  
- Additional Tools Used: None  
- Report Generated By: Ahmad Khaleel
- Report link: file:///C:/my-project/ZAP%20by%20Checkmarx%20Scanning%20Report.pdf
