# 🔐 ChromePasswordDumper

**⚠️ DISCLAIMER: This tool is for EDUCATIONAL PURPOSES and AUTHORIZED security testing ONLY!**  
**🚫 Never use it to access passwords without explicit permission from the account owner.**  
**⚖️ Misuse may violate laws - You are responsible for your actions!**

---

## 📊 Overview

ChromePasswordDumper is a 🔧 utility that extracts saved login credentials from Google Chrome's local database. It demonstrates how browsers store sensitive data and why 🔒 system security matters!

## ✨ Features

- 🔍 Extracts usernames, passwords, and associated URLs
- 👥 Supports multiple Chrome profiles
- 🛡️ Works with Chrome's encrypted password storage
- ⌨️ Command-line interface for easy integration
- 📁 Multiple output formats: JSON, CSV, or plain text
- 🎯 Cross-platform support

## 📋 Prerequisites

- 🐍 Python 3.7+
- 🌐 Chrome browser installed
- 👤 User must be logged into their system account
- 🔑 Access to user's Chrome profile directory

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ChromePasswordDumper.git

# Navigate to directory
cd ChromePasswordDumper

# Install dependencies
pip install -r requirements.txt
```

## 💻 Usage

### 🎯 Basic extraction:
```bash
python ChromePasswordDumper.py
```

### 📊 Specify output format:
```bash
python ChromePasswordDumper.py --format json    # 📄 JSON format
python ChromePasswordDumper.py --format csv     # 📊 CSV format  
python ChromePasswordDumper.py --format txt     # 📝 Text format
```

### 💾 Save to file:
```bash
python ChromePasswordDumper.py --output passwords.json
```

### 👤 Target specific Chrome profile:
```bash
python ChromePasswordDumper.py --profile "Profile 1"
```

### 🖥️ Show available profiles:
```bash
python ChromePasswordDumper.py --list-profiles
```

## 🔧 How It Works

```
📂 Chrome Profile → 🔒 Login Data → 🔑 System Encryption → 🗝️ Decryption → 📊 Extraction
```

Chrome stores passwords in an SQLite database (`Login Data` 📁) located in:
- **Windows:** `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- **macOS:** `~/Library/Application Support/Google/Chrome/Default/`
- **Linux:** `~/.config/google-chrome/Default/`

Passwords are 🔒 encrypted using:
- 🪟 Windows: DPAPI (Data Protection API)
- 🍎 macOS: Keychain Services  
- 🐧 Linux: libsecret/gnome-keyring

## ⚠️ Security Implications

This tool demonstrates:

1. 🗄️ How browsers store sensitive data locally
2. 🔓 Why full-disk encryption is CRITICAL
3. 🔑 Importance of master passwords
4. 🚪 Risks of leaving computers unlocked
5. 🛡️ Need for endpoint security

## ⚖️ Legal & Ethical Use

### ✅ **YOU MUST:**
- 💻 Only run on YOUR OWN computer
- 📝 Have EXPLICIT written permission for testing
- ⚖️ Comply with ALL applicable laws
- 🔒 Respect privacy regulations (GDPR, CCPA, etc.)

### ❌ **NEVER:**
- 🚫 Use on others' computers without permission
- 🏴‍☠️ Extract passwords maliciously
- 📤 Distribute extracted credentials
- ⚔️ Violate computer fraud laws

## 🛡️ Protection Tips

To protect against unauthorized access:

1. 🔐 Use full-disk encryption (BitLocker, FileVault, LUKS)
2. 🔑 Set strong system passwords & enable auto-lock
3. 🗝️ Enable Chrome sync passphrase
4. 🏦 Use dedicated password managers (Bitwarden, 1Password)
5. 👋 Always log out when away
6. 🧹 Regularly clear saved passwords
7. 🚨 Enable antivirus & endpoint protection

## 📬 Responsible Disclosure

Found vulnerabilities? Report them through:

- 🐛 Browser vendor bug bounty programs
- 🔒 Responsible disclosure programs
- 🏛️ Proper security channels

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

PRs welcome for **educational improvements only**! 📚  
Please ensure code changes maintain ethical guidelines.

## 🙏 Acknowledgments

- 🎓 For educational purposes only
- 🛡️ Security awareness & authorized pentesting
- 📜 Always get proper authorization
- ⚠️ Use responsibly!

---

## ⭐ Support

If you find this educational, give it a ⭐ on GitHub!

## 🔗 Quick Links

- 📖 [Documentation](#)
- 🐛 [Issue Tracker](#)
- 💬 [Discussions](#)
- 📦 [Releases](#)

---

**⚡ Remember: With great power comes great responsibility!**  
**🦸 Always be a security hero, not a villain!**  
**🔒 Stay safe, stay ethical!**
