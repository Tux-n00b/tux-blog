
# 90-Day Remote Code Execution (RCE) Learning Plan

**Schedule:** 3 days/week (about 1–2 hours each session)  
**Tools you'll need installed by Week 1:**  
- VirtualBox or VMware  
- Kali Linux VM  
- DVWA (Damn Vulnerable Web App) or bWAPP in a local lab  
- Burp Suite Community Edition  

---

## Weeks 1–2 — Foundations
**Goal:** Learn HTTP, basic scripting, and set up your lab.

### Week 1
- **Session 1:** HTTP basics — methods, headers, request/response cycle. ([MDN HTTP Overview](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview))  
- **Session 2:** Linux command line basics (`cd`, `ls`, `cat`, `grep`, `find`, `whoami`).  
- **Session 3:** Install VirtualBox, Kali Linux, and DVWA in a local VM.

### Week 2
- **Session 1:** Python basics (variables, loops, functions) for payload scripting.  
- **Session 2:** Install and explore Burp Suite (set up browser proxy, intercept requests).  
- **Session 3:** Do [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) levels 0–6.

---

## Weeks 3–4 — Intro to RCE
**Goal:** Understand what RCE is and exploit your first basic case.

### Week 3
- **Session 1:** Read [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection) and [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection).  
- **Session 2:** In DVWA (security low), find and exploit the Command Injection vulnerability with payloads like `whoami` and `id`.  
- **Session 3:** Try fuzzing DVWA parameters with `ffuf` or `Burp Intruder`.

### Week 4
- **Session 1:** Study common RCE payloads from [HackTricks OS Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection).  
- **Session 2:** Practice filtering bypasses in DVWA (security medium/high).  
- **Session 3:** Do TryHackMe “Command Injection” room.

---

## Weeks 5–6 — Intermediate Skills
**Goal:** Learn more realistic RCE scenarios and testing methods.

### Week 5
- **Session 1:** Learn about **file uploads → webshell → RCE**.  
- **Session 2:** Try DVWA’s File Upload lab and upload a PHP reverse shell (PentestMonkey).  
- **Session 3:** Set up and exploit **bWAPP** for RCE.

### Week 6
- **Session 1:** Do TryHackMe “Vulnversity” (focus on RCE steps).  
- **Session 2:** Practice enumeration after getting RCE (`uname -a`, `cat /etc/passwd`).  
- **Session 3:** Study 1–2 public RCE write-ups from [HackerOne reports](https://hackerone.com/hacktivity).

---

## Weeks 7–8 — Vulnerability Chains
**Goal:** Learn how RCE happens through indirect vulnerabilities.

### Week 7
- **Session 1:** Study **LFI to RCE** (log poisoning, upload bypass).  
- **Session 2:** Practice on a VulnHub machine with LFI → RCE (e.g., “Mr Robot”).  
- **Session 3:** Document your steps in a “pentest diary”.

### Week 8
- **Session 1:** Study **Server-Side Template Injection (SSTI)** → RCE.  
- **Session 2:** Do PortSwigger SSTI labs.  
- **Session 3:** Do a HackTheBox “Starting Point” machine with RCE.

---

## Weeks 9–10 — Advanced Exploitation
**Goal:** Handle obfuscated input and privilege escalation.

### Week 9
- **Session 1:** Learn about **deserialization RCE** (PHP unserialize, Java gadgets).  
- **Session 2:** Practice on a TryHackMe deserialization lab.  
- **Session 3:** Read an advanced bug bounty RCE report.

### Week 10
- **Session 1:** Learn privilege escalation after RCE (Linux basics).  
- **Session 2:** Practice escalating from a webshell to root on a lab VM.  
- **Session 3:** Explore automated exploitation with Metasploit (use only in lab).

---

## Weeks 11–12 — Real-World Practice
**Goal:** Simulate real pentesting and bug bounty RCE hunting.

### Week 11
- **Session 1:** Pick a VulnHub machine with unknown RCE vector and solve it.  
- **Session 2:** Write a professional-style vulnerability report for your exploit.  
- **Session 3:** Read 2–3 CVE case studies involving RCE.

### Week 12
- **Session 1:** Try a HackTheBox medium-difficulty machine with RCE.  
- **Session 2:** Review all notes, payloads, and tools.  
- **Session 3:** Plan your next steps — possibly joining HackerOne/Bugcrowd for legal RCE testing.
