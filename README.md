# Web Security and Vulnerabilities

![Web Security and Vulnerabilities](images/What-is-a-Website-Vulnerability-and-How-Can-it-be-Exploited.png)
# Table of Contents

1. [Introduction to OWASP](#introduction-to-owasp)
2. [Types of Web Vulnerabilities](#types-of-web-vulnerabilities)
    - [SQL Injection (SQLi)](#sql-injection-sqli)
    - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
    - [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
    - [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
    - [Security Misconfiguration](#security-misconfiguration)
    - [Sensitive Data Exposure](#sensitive-data-exposure)
    - [Broken Authentication and Session Management](#broken-authentication-and-session-management)
    - [XML External Entities (XXE)](#xml-external-entities-xxe)
    - [Broken Access Control](#broken-access-control)
    - [Using Components with Known Vulnerabilities](#using-components-with-known-vulnerabilities)
    - [Insufficient Logging and Monitoring](#insufficient-logging-and-monitoring)
    - [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
    - [Remote Code Execution (RCE)](#remote-code-execution-rce)
    - [File Upload Vulnerabilities](#file-upload-vulnerabilities)
    - [Command Injection](#command-injection)
    - [Path Traversal](#path-traversal)
3. [Bug Bounty](#bug-bounty)
    - [Bug Bounty ](#bug-bounty)
    - [Bug Bounty Programs](#bug-bounty-programs)
    - [Articles for Starting in Bug Bounty Hunting](#articles-for-starting-in-bug-bounty-hunting)

4. [Resources](#resources)
    - [Documentation and References](#documentation-and-references)
    - [Security Labs and Resources](#security-labs-and-resources)
    - [Recommended Books](#recommended-books)
    - [YouTube Channels](#youtube-channels)
5. [Conclusion](#conclusion)

# Introduction to OWASP

The Open Web Application Security Project (OWASP) is a worldwide not-for-profit charitable organization focused on improving the security of software. OWASP provides impartial, practical information about application security and aims to help organizations build secure software.

## OWASP Top Ten

The OWASP Top Ten is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications. The list is updated regularly to reflect the evolving landscape of web application security threats.
![OWASP Top Ten](images/owasp.png)

### OWASP References
- [OWASP Official Website](https://owasp.org/)
- [OWASP Top Ten Project](https://owasp.org/www-project-top-ten/)

# Types of Web Vulnerabilities

Web vulnerabilities are security weaknesses in web applications that can be exploited by attackers to gain unauthorized access, manipulate data, or disrupt services. Understanding these vulnerabilities is crucial for developers, administrators, and security professionals to protect web applications from potential threats.

## SQL Injection (SQLi)
   - **Description**: SQL Injection occurs when an attacker inserts malicious SQL queries into an input field, allowing them to manipulate the database.
   - **Example**: An attacker enters `' OR '1'='1` in a login field to bypass authentication.
   - **Prevention**: Use parameterized queries and prepared statements.
   - **Cheat Sheet**: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## Cross-Site Scripting (XSS)
   - **Description**: XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.
   - **Example**: An attacker injects a `<script>` tag in a comment section, which steals session cookies when other users view the comment.
   - **Prevention**: Validate and sanitize user inputs, and use Content Security Policy (CSP).
   - **Cheat Sheet**: [Cross-Site Scripting (XSS) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html)
   
   ### Types of XSS
   - **Stored XSS**: The malicious script is stored on the server (e.g., in a database) and is displayed to users when they access the infected content.
     - **Example**: A comment field where an attacker posts a script that runs when others view the comment.
   - **Reflected XSS**: The malicious script is reflected off a web server, such as in an error message, search result, or any other response that includes input from the user.
     - **Example**: A search query where an attacker includes a script that runs in the search results page.
   - **DOM-based XSS**: The vulnerability exists in the client-side code rather than the server-side code.
     - **Example**: An attacker manipulates the DOM environment in the user's browser to execute malicious scripts.
   - **Cheat Sheet**: [DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

## Cross-Site Request Forgery (CSRF)
   - **Description**: CSRF tricks a user into performing actions on a web application without their consent.
   - **Example**: An attacker sends a link to a user that, when clicked, makes a request to transfer funds from the user's account.
   - **Prevention**: Use anti-CSRF tokens and validate the origin of requests.
   - **Cheat Sheet**: [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## Insecure Direct Object References (IDOR)
   - **Description**: IDOR occurs when an application exposes a reference to an internal object, allowing attackers to access unauthorized data.
   - **Example**: An attacker changes the URL from `/user/123` to `/user/124` to access another user's data.
   - **Prevention**: Implement proper access controls and validate user permissions.
   - **Cheat Sheet**: [Insecure Direct Object References Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

## Security Misconfiguration
   - **Description**: Security misconfiguration arises from improper configuration of security settings in applications or servers.
   - **Example**: Leaving default passwords unchanged or enabling directory listing on a web server.
   - **Prevention**: Regularly review and update configurations, disable unnecessary features, and use secure defaults.
   - **Cheat Sheet**: [Security Misconfiguration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html)

## Sensitive Data Exposure
   - **Description**: Sensitive data exposure happens when applications fail to adequately protect sensitive information such as passwords, credit card numbers, or personal data.
   - **Example**: Storing passwords in plain text or transmitting sensitive data over unencrypted connections.
   - **Prevention**: Use strong encryption, secure storage mechanisms, and enforce HTTPS.
   - **Cheat Sheet**: [Sensitive Data Exposure Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Sensitive_Data_Exposure_Prevention_Cheat_Sheet.html)

## Broken Authentication and Session Management
   - **Description**: Flaws in authentication and session management can allow attackers to compromise user accounts.
   - **Example**: Session IDs exposed in URLs or insufficient password policies.
   - **Prevention**: Implement multi-factor authentication, use secure session management, and enforce strong password policies.
   - **Cheat Sheet**: [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## XML External Entities (XXE)
   - **Description**: XXE attacks exploit vulnerabilities in XML parsers to access or manipulate data and resources.
   - **Example**: An attacker includes an external entity in an XML file to retrieve sensitive files from the server.
   - **Prevention**: Disable external entities in XML parsers and use less complex data formats such as JSON.
   - **Cheat Sheet**: [XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

## Broken Access Control
   - **Description**: Broken access control vulnerabilities occur when applications do not properly restrict user permissions, allowing unauthorized actions.
   - **Example**: An attacker accesses admin functionality by changing their user role in the request.
   - **Prevention**: Implement proper role-based access controls and regularly audit permissions.
   - **Cheat Sheet**: [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

## Using Components with Known Vulnerabilities
- **Description**: This occurs when applications use libraries, frameworks, or other software modules with known security vulnerabilities.
- **Example**: Using an outdated version of a third-party library with a known vulnerability.
- **Prevention**: Regularly update and patch software components and use tools to identify known vulnerabilities.
- **Cheat Sheet**: [Using Components with Known Vulnerabilities](https://cheatsheetseries.owasp.org/cheatsheets/Using_Components_with_Known_Vulnerabilities.html)

## Insufficient Logging and Monitoring
- **Description**: Insufficient logging and monitoring allow attackers to exploit systems without detection, hindering the response to security incidents.
- **Example**: A breach goes unnoticed due to lack of logs and alert mechanisms.
- **Prevention**: Implement comprehensive logging and monitoring solutions and regularly review logs.
- **Cheat Sheet**: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

## Server-Side Request Forgery (SSRF)
- **Description**: SSRF allows attackers to send crafted requests from the server, potentially accessing internal resources.
- **Example**: An attacker manipulates a server-side request to access internal APIs or resources.
- **Prevention**: Validate and restrict server-side requests, use whitelists for allowed domains, and apply network segmentation.
- **Cheat Sheet**: [Server-Side Request Forgery (SSRF) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## Remote Code Execution (RCE)
- **Description**: RCE vulnerabilities allow attackers to execute arbitrary code on a server or system.
- **Example**: An attacker exploits a vulnerable application to execute commands on the server.
- **Prevention**: Implement input validation and sanitization, apply least privilege principles, and use secure coding practices.
- **Cheat Sheet**: [Remote Code Execution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Remote_Code_Execution_Prevention_Cheat_Sheet.html)

## File Upload Vulnerabilities
- **Description**: File upload vulnerabilities allow attackers to upload malicious files, leading to remote code execution or unauthorized access.
- **Example**: Uploading a file with a disguised executable payload.
- **Prevention**: Validate file types and extensions, store uploads outside the web root, and scan files for malware.
- **Cheat Sheet**: [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## Command Injection
- **Description**: Command injection vulnerabilities occur when an application executes commands provided by an attacker.
- **Example**: An attacker injects `; rm -rf /` in a command execution parameter.
- **Prevention**: Use parameterized commands, avoid using shell commands with user input, and sanitize inputs.
- **Cheat Sheet**: [Command Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Prevention_Cheat_Sheet.html)

## Path Traversal
- **Description**: Path traversal vulnerabilities allow attackers to access files and directories outside the web root.
- **Example**: Modifying a URL path to access sensitive files like `../../etc/passwd`.
- **Prevention**: Use input validation and restrict file system access, employ whitelists for allowed file paths.
- **Cheat Sheet**: [Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)

# Bug Bounty 

Bug bounty programs are initiatives run by organizations that invite security researchers to find and report vulnerabilities in their systems in exchange for rewards. This approach helps companies identify and fix security issues before they can be exploited maliciously.

## Bug Bounty Programs

- [HackerOne](https://www.hackerone.com/): Platform for running bug bounty programs and vulnerability coordination.
- [Bugcrowd](https://www.bugcrowd.com/): Crowdsourced security platform that connects organizations with cybersecurity researchers.
- [Synack](https://www.synack.com/): Security platform that leverages a crowdsourced network for penetration testing and vulnerability discovery.
- [Intigriti](https://www.intigriti.com/): Ethical hacking and bug bounty platform connecting businesses with security researchers.
- [YesWeHack](https://www.yeswehack.com/): European bug bounty and vulnerability disclosure platform.
- [Open Bug Bounty](https://www.openbugbounty.org/): Open community bug bounty platform that allows anyone to report vulnerabilities.

## Articles for Starting in Bug Bounty Hunting

- [How to Get Started in Bug Bounty](https://infosecwriteups.com/how-to-get-started-into-bug-bounty-1be52b3064e0): Guide on entering the bug bounty hunting field and getting your first bounty.
- [Beginner Bug Bounty Guide](https://takshilp.medium.com/beginner-bug-bounty-guide-365e4c00d730): Step-by-step guide for beginners interested in bug bounty hunting.
- [Bug Bounty Beginner Roadmap](https://github.com/bittentech/Bug-Bounty-Beginner-Roadmap): Roadmap and resources for starting a career in bug bounty hunting.
- [How to Start in Bug Bounty Hunting: My Personal Experience](https://riccardomalatesta.com/how-to-start-in-bug-bounty-hunting-my-personal-experience/): Personal insights and tips from an experienced bug bounty hunter.
- [My Experience for 2 Years in Bug Bounty Hunting](https://ahmdhalabi.medium.com/my-experience-for-2-years-in-bug-bounty-hunting-b22d03f98ed3): Two-year journey of learning and earning through bug bounty hunting.
- [Found Bugs, Got Paid, Stayed Poor: Making a Living with Bug Bounties](https://medium.com/@slava-moskvin/found-bugs-got-paid-stayed-poor-making-a-living-with-bug-bounties-04ba1fbbab73): Insights into the financial aspects and challenges of bug bounty hunting.

## Documentation and References

- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/): Comprehensive cheat sheets for various web application security topics, including XSS, SQLi, and more.
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/): Detailed guidelines for performing effective web application security testing.
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/): List of the top 10 critical security risks in web applications, updated periodically.
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/): Best practices and techniques for conducting secure code reviews to identify vulnerabilities.
- [OWASP API Security Project](https://owasp.org/www-project-api-security/): Resources and guidelines for securing APIs against common security threats and risks.

## Security Labs and Resources

- [TryHackMe](https://tryhackme.com/): Online platform that teaches cybersecurity through hands-on virtual labs.
- [Hack The Box](https://www.hackthebox.eu/): Penetration testing labs that simulate real-world scenarios for practicing hacking skills.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security): Free online web security training resources from the creators of Burp Suite.
- [PentesterLab](https://pentesterlab.com/): Hands-on exercises and labs for learning web penetration testing techniques.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/): Vulnerable web application for practicing web security testing and exploitation techniques.
- [DVWA - Damn Vulnerable Web Application](http://www.dvwa.co.uk/): Deliberately vulnerable web application for security testing purposes.
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/): Free online course that covers the basics of using Metasploit for penetration testing.
- [Exploit-DB](https://www.exploit-db.com/): Archive of exploits and shellcode for vulnerability research and exploitation.

## Recommended Books {#recommended-books}

For further reading on web security and bug bounty hunting, consider these books:

- *The Web Application Hacker’s Handbook*
- *OWASP Testing Guide*
- *The Tangled Web: A Guide to Securing Modern Web Applications*
- *Web Hacking 101*
- *Breaking into Information Security*
- *Mastering Modern Web Penetration Testing*
- *The Mobile Application Hacker's Handbook*
- *OWASP Mobile Security Testing Guide (MSTG)*

## YouTube Channels

- [NahamSec](https://www.youtube.com/channel/UC9Qa_gXarSmObPX3ooIQZrg): Tutorials and discussions on ethical hacking and bug bounty hunting.
- [CyberWings Security](https://www.youtube.com/cyberwingssecurity): Educational content on cybersecurity topics.
- [Metasploitation](https://www.youtube.com/channel/UC9Qa_gXarSmObPX3ooIQZrg): Videos focusing on Metasploit tutorials and demonstrations.
- [Bug Bounty Reports Explained](https://www.youtube.com/c/BugBountyReportsExplained): Analyzes and explains bug bounty reports and findings.
- [Ryan - PHDsec](https://www.youtube.com/c/ryanphdsec): Security research and tutorials on penetration testing and bug hunting.

## Conclusion

Understanding and mitigating web vulnerabilities is crucial for securing applications against potential threats. By familiarizing yourself with common vulnerabilities like SQL Injection, XSS, CSRF, and others listed in this document, and by utilizing resources such as OWASP guides, bug bounty programs, and educational platforms like TryHackMe, you can develop robust security practices. Continuously staying updated on emerging threats and best practices ensures that your applications remain resilient in the face of evolving cybersecurity challenges.
