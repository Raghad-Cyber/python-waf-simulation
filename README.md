# Python Web Application Firewall (WAF) Simulation

## Overview
This project is a Python-based Web Application Firewall (WAF) simulation developed as part of a cybersecurity laboratory assignment.  
It demonstrates how basic WAF logic can detect, log, and respond to common web attacks using rule-based inspection.

The project focuses on defensive security, threat detection, and logging, aligning with Blue Team and SOC fundamentals.

---

## Features
- Detection of common web attacks:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
- Rule-based HTTP request inspection
- Logging of malicious requests with timestamps
- Simple and readable Python implementation
- Log file generation for security analysis

---

## Project Structure
python-waf-simulation/
│
├── waf.py              # Main WAF implementation
├── waf.log             # Log file capturing detected attacks
├── WAF_Project.pdf     # Full documentation, analysis, and screenshots
└── README.md

---

## How It Works
- Incoming HTTP requests are inspected against predefined attack patterns.
- If a malicious pattern is detected:
  - The request is blocked or flagged
  - The event is logged into waf.log
- Legitimate requests are allowed to pass through normally.

---

## Technologies Used
- Python 3
- Regular Expressions (Regex)
- File-based Logging
- Web Security Concepts

---

## Documentation
Detailed implementation steps, attack scenarios, results, and screenshots are included in the `WAF_Project.pdf` report.

---

## Educational Context & Contribution
This project was completed as part of a group-based cybersecurity laboratory assignment.

My contribution focused on:
- Understanding and implementing WAF detection logic
- Analyzing attack patterns and malicious payloads
- Reviewing and validating log outputs
- Contributing to documentation and security analysis

The project provided hands-on experience in defensive security, monitoring, and Blue Team concepts.

---

## Disclaimer
This project is for educational purposes only and is not intended for production use.
