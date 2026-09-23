# 🔐 Password Strength Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6%2B-F7DF1E?logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)
[![Security](https://img.shields.io/badge/Security-k--Anonymity-brightgreen)](https://haveibeenpwned.com/API/v3#PwnedPasswords)

A modern, responsive, and secure web application designed to evaluate password strength in real time. The **Password Strength Visualizer** goes beyond basic length checks by incorporating real-time criteria verification, repeated character detection, built-in strong password generation, and breach detection via the **Have I Been Pwned (HIBP)** API using privacy-preserving *k-Anonymity*.

---

## ✨ Features

- **⚡ Real-Time Strength Meter:** Dynamically calculates password strength scores (*Weak*, *Medium*, *Strong*, *Very Strong*) with smooth visual feedback.
- **📋 Criteria Validation Checklist:** Live updates checking for:
  - Minimum 8 characters
  - At least one uppercase letter (`A-Z`)
  - At least one lowercase letter (`a-z`)
  - At least one number (`0-9`)
  - At least one special character (`!@#$%^&*` etc.)
- **🔍 Breach Detection (HIBP Integration):** Uses SHA-1 hashing and the **Have I Been Pwned API** with **k-Anonymity** to alert users if their entered password has appeared in known data breaches without ever sending the plaintext password or full hash over the network.
- **🎲 Custom Password Generator:** Generates cryptographically varied passwords with customizable length (8–32 characters).
- **👁️ Mask / Unmask Toggle:** Convenient show/hide eye icon to reveal or hide the password input.
- **📋 Copy to Clipboard:** One-click copy action for generated or verified passwords.
- **🛡️ Repeated Pattern Detection:** Penalty scoring for repeating character patterns (e.g., `aaa`, `111`) to ensure true complexity.

---

## 🛠️ Tech Stack

- **HTML5:** Semantic markup and structure.
- **CSS3:** Custom styles, dynamic strength status colors, smooth transitions, and responsive card layout.
- **Vanilla JavaScript (ES6+):** Asynchronous API handling (`crypto.subtle`, `fetch`), debounced input listeners, and interactive UI logic.
- **Have I Been Pwned API v3:** Privacy-preserving breach checking.

---

## 🔒 How Breach Checking Works (Privacy First)

Security and privacy are paramount when dealing with passwords:

1. **Local SHA-1 Hashing:** The password is transformed into a SHA-1 hash strictly inside your browser using `crypto.subtle.digest`.
2. **k-Anonymity Protocol:** Only the first **5 characters** (prefix) of the hash are sent to `https://api.pwnedpasswords.com/range/{prefix}`.
3. **Local Comparison:** The API returns a list of suffix hashes matching the prefix. The application checks locally if the remaining 35 characters match any known breached suffix.
4. **Zero Exposure:** Your actual password **never leaves your device**.

---

## 🚀 Quick Start

### Option 1: Direct Usage in Browser
Simply clone the repository and open `index.html` in your web browser.

```bash
git clone https://github.com/P-Sushanth/Password-Strength-Visualizer.git
cd Password-Strength-Visualizer
```
Double click `index.html` or open it with your browser of choice.

### Option 2: Local Web Server (VS Code Live Server)
1. Open the project folder in VS Code.
2. Install the **Live Server** extension.
3. Right-click `index.html` and choose **Open with Live Server**.

---

## 📁 Project Structure

```
Password-Strength-Visualizer/
├── index.html       # Application HTML structure and container layout
├── style.css        # Visual styles, strength bar colors, and criteria list styling
├── script.js        # Strength scoring, generator, HIBP lookup & UI event handling
└── README.md        # Comprehensive documentation
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [Issues page](https://github.com/P-Sushanth/Password-Strength-Visualizer/issues).

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

## 👤 Author

**P. Sushanth**
- GitHub: [@P-Sushanth](https://github.com/P-Sushanth)
