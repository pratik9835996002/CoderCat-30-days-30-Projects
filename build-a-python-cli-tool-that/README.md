# 🔐 Password Strength Checker

> Day 02 of 30 · Python · CLI Tool

A Python CLI tool that checks the strength of your password, suggests a stronger one if it's weak, and checks if your password has ever appeared in a known data breach using the **HaveIBeenPwned API**.

---

## 🚀 Features

- ✅ Checks password strength (Weak / Medium / Strong)
- 💡 Suggests a strong password if yours is weak
- 🔍 Checks if your password has been seen in a real data breach
- 🔒 Uses **k-anonymity** — your full password is never sent over the internet

---

## 🛠️ How It Works

**Strength Check looks for:**
- Minimum length (8+ characters)
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters (`!@#$%^&*`)

**Breach Check:**
- Takes a SHA-1 hash of your password
- Sends only the **first 5 characters** of the hash to the HaveIBeenPwned API
- Checks the returned list locally — your actual password never leaves your machine

---

## ⚙️ Setup

```bash
# Clone the repo
git clone https://github.com/pratik9835996002/CoderCat-30-days-30-Projects.git
cd CoderCat-30-days-30-Projects/build-a-python-cli-tool-that

# Install dependencies
pip install requests

# Run
python password_strength_checker.py
```

---

## 📸 Demo

```
Enter your password: hello123

Strength  : ⚠️  Weak
Reasons   : No uppercase · No special characters

Suggested : X7#mK$p2@Lq!

Breach Check...
❌ This password has been seen 52,301 times in data breaches.
   Do NOT use this password.
```

```
Enter your password: X7#mK$p2@Lq!

Strength  : ✅ Strong

Breach Check...
✅ This password has not been found in any known breach.
   Looks good!
```

---

## 📦 Built With

| Tool | Purpose |
|---|---|
| Python 3.10+ | Core language |
| `hashlib` | SHA-1 hashing for breach check |
| `requests` | API calls to HaveIBeenPwned |
| `re` | Regex for strength analysis |
| `secrets` / `string` | Secure password suggestion |

---

## 🔗 API Used

[HaveIBeenPwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) — free, no key required.

---

## ⚠️ Disclaimer

This tool is built for **educational purposes** as part of the 30 Days 30 Projects challenge. Test only on passwords you own.

---

## 👤 Author

**Pratik Singh** · CoderCat 🐱

[![Twitter](https://img.shields.io/badge/Twitter-@PratikS94864459-1DA1F2?style=flat-square&logo=twitter)](https://twitter.com/PratikS94864459)
[![GitHub](https://img.shields.io/badge/GitHub-pratik9835996002-181717?style=flat-square&logo=github)](https://github.com/pratik9835996002)

---

<p align="center">Part of <a href="https://github.com/pratik9835996002/CoderCat-30-days-30-Projects">30 Days · 30 Projects</a> · No shortcuts 🐱</p>
