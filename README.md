# SnitchLint: SQL Injection Linter

SnitchLint is a Visual Studio Code extension designed to help developers identify potential SQL Injection vulnerabilities in their JavaScript and TypeScript code. It analyzes your code for user-controlled input flowing into SQL query-executing functions, helping you prevent common security flaws.

---

## Features

* **AST-based Analysis:** Utilizes TypeScript's Abstract Syntax Tree (AST) to understand code structure.
* **Taint Tracking:** Identifies user-controlled data sources (e.g., `req.body`, `req.query`, `process.env`).
* **Taint Propagation:** Tracks tainted data through variable assignments, concatenations, and template literals.
* **SQL Sink Detection:** Recognizes common database query execution methods (e.g., `db.query`, `db.execute`).
* **VS Code Diagnostics:** Highlights potential vulnerabilities directly in your editor with warnings.

---

## Getting Started

### Prerequisites

* [Node.js](https://nodejs.org/) (LTS recommended)
* [npm](https://www.npmjs.com/) (usually comes with Node.js)
* [Visual Studio Code](https://code.visualstudio.com/)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your_username/snitchlint.git](https://github.com/your_username/snitchlint.git)
    cd snitchlint
    ```
2.  **Install dependencies:**
    ```bash
    npm install
    ```
3.  **Open in VS Code:**
    ```bash
    code .
    ```
4.  **Run the Extension:** Press `F5` to open a new VS Code Extension Development Host window. Your linter will be active in this new window.

---

## Usage

1.  Open any JavaScript (`.js`) or TypeScript (`.ts`) file in the **Extension Development Host** window.
2.  SnitchLint will automatically analyze the code.
3.  Look for **squiggly underlines** indicating potential issues. Detailed warnings will appear in the **Problems panel** (View > Problems or `Ctrl+Shift+M`/`Cmd+Shift+M`).

**Example:**

```typescript
// Example: src/test/vulnerable.ts
const userId = req.body.id; // Tainted source
const query = `SELECT * FROM users WHERE id = '${userId}'`;
db.query(query); // <-- SnitchLint highlights this as a potential SQL Injection

