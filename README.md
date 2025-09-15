# Khit's Bookshop: A Vulnerable Web Application (Medium Level)

This project is a simple, **intentionally vulnerable** e-commerce web application built with **Python Flask** and **SQLite**. It's designed as a hands-on lab environment for learning about a common and critical web security flaw: **SQL Injection**.

**Disclaimer:** This application is for educational purposes only. Do not use this code in a production environment. The vulnerabilities are deliberate to allow for safe, legal practice.

---

### Project Goal

The primary goal is to provide a practical scenario where you can identify and exploit a SQL injection vulnerability. By exploring this application, you can gain a deeper understanding of:

* How SQL injection works in a real-world context.
* The severe impact of insecure coding practices.
* The principles of secure coding to prevent such attacks.

---

## Challenge Info
- Category: Web
- Difficulty: Medium


## Setup Instructions
1. Clone the repository
```bash
git clone https://github.com/KhitMinnyo/bookshop-m
cd bookshop-m
```
2. Install the required dependencies:
```bash
pip3 install flask
#if you use Kali linux, use virtualEnvironment to install flask
```

2. Run the application:
```bash
python3 app.py
```

3. Access the application at `http://localhost:5005`

## Objective
Find the SQL injection vulnerability in the bookshop app and extract the admin's credentials, which contains the flag.

## Hint
Flag Format: CTF{...}
