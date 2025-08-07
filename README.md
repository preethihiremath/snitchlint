# 🕵️‍♀️ SnitchLint: The Code Snitch You’ll Love

SnitchLint is your extra pair of 👀 inside VS Code that catches shady security stuff in your JavaScript and TypeScript files — before production says “oops 💀”.

Whether it’s SQL injection, XSS, secret leaks, or cookie sins 🍪, we gotchu.  

> 💬 *"Write code like no one's watching. SnitchLint is."*

---

## ✨ Features

🚨 **11 Powerful Security Analyzers**  
All built with TypeScript AST wizardry + taint-flow logic:

| Vulnerability Type           | Detection Style |
|-----------------------------|-----------------|
| 💉 SQL Injection             | Taint-flow → SQL sinks |
| 🔐 Secrets in Code           | Regex & naming patterns |
| 🦠 Cross-Site Scripting (XSS) | DOM sinks + user input |
| 💣 Command Injection         | `exec`, `spawn`, etc. |
| 🧙‍♂️ Insecure `eval()` / `Function()` | Static calls on user input |
| 📦 Insecure Deserialization | `JSON.parse` + input checks |
| 🧊 Weak Crypto Usage         | Deprecated or insecure algos |
| 🖼️ Unrestricted File Uploads | `req.files`, `fs.write`, etc. |
| 🍪 Insecure Cookie Flags     | Missing `Secure` / `HttpOnly` |
| 🛡️ No CSRF Protection        | Middleware missing or unchecked |
| 🌐 Open Redirects            | `res.redirect(req.query)` vibes |

🧠 **AST-based Analysis** – No regex hacks. We walk your syntax tree like it owes us money.  
🧬 **Taint Tracking** – Follows tainted data like a chismosa (gossip queen).  
🧪 **Real-Time VS Code Diagnostics** – Squiggles that actually mean something.  
📎 **No setup required** – Just install, run, and boom 💥 – security insights on the fly.

---

## 🧑‍💻 Getting Started

### 🔧 Prereqs

- [Node.js](https://nodejs.org/) (LTS)
- [VS Code](https://code.visualstudio.com/)
- Basic fear of getting hacked 😅

### ⚙️ Installation

```bash
git clone https://github.com/your_username/snitchlint.git
cd snitchlint
npm install
code .
```

Then hit `F5` in VS Code to launch the **Extension Development Host** window 🚀

---

## 💻 How to Use

 Install the VS code extension snitchlint, and look out for for squiggly lines & warnings in the **Problems** panel
 SnitchLint auto-scans your code for risky business 🔍.

### 🧪 Example:

```ts
const userId = req.body.id; // Tainted
const query = `SELECT * FROM users WHERE id = '${userId}'`; // 💉 flagged!
db.query(query);
```

---

## 📜 Roadmap (Manifesto, but chill)

- [x] SQL Injection detection
- [x] XSS analyzer
- [x] Secrets-in-code analyzer
- [x] OWASP Top 10 coverage (see above 🔼)
- [ ] Security report export (JSON / Markdown)
- [ ] Confidence score system (like vibes, but coded)
- [ ] Snitchy UI inside VS Code

---

## 🧠 Who's This For?

- ✨ Devs who love security but hate writing it from scratch
- 🧑‍🎓 Students learning secure coding
- 🧑‍💼 Professionals tired of post-deploy fire drills

---

## 🤝 Contribute?

Absolutely. Fork it, test it, snitch on code with us.

---

## 🐍 Want to know how it works?

Refer to the howOfItAll.txt file in my repository (I'll do it soon)

## 🐞 How did I publish this ? 

- Sign in to https://dev.azure.com
- Create a publisher
- Create a persoanl access token (https://dev.azure.com)
- install VS extensions npm install -g vsce
- vsce login your-publisher-name
- vsce package
- vsce publish