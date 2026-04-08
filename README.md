## passcheck.sh

This script is a comprehensive security tool designed to evaluate password strength, verify compliance against major regulatory frameworks, and check for known data breaches. It provides a color-coded report to help users or administrators identify weak credentials before they are deployed.

---

### Features

* **Complexity Analysis:** Validates passwords for essential traits:
    * Uppercase and Lowercase letters.
    * Numerical characters.
    * Special characters/symbols.
* **Regulatory Compliance Mapping:** Checks the password against specific length and complexity requirements for:
    * **HIPAA / SOC 2 / SOX / ISO 27001:** Standard high-security baselines.
    * **FedRAMP:** Stringent 12-character minimum requirement.
    * **PCI DSS:** Financial industry standard (7-character minimum).
* **Leak Detection (Have I Been Pwned):** Uses k-Anonymity to securely check the password's SHA-1 hash against the *Have I Been Pwned* API. This identifies if the password has appeared in historical data breaches without ever sending the actual password to the server.
* **Pattern Identification:** Includes pre-defined regex patterns to catch weak sequences like `123`, `abc`, or keyboard rows like `qwerty`.
* **Input Sanitization:** Automatically detects and rejects empty inputs or passwords containing whitespace.

---

### Prerequisites

* **Environment:** Linux/Unix with `bash`.
* **Tools:** * `openssl`: To generate SHA-1 hashes for breach checking.
    * `curl`: To communicate with the *Have I Been Pwned* API.
    * `awk`: For string manipulation and formatting.

---

### Usage

1.  **Grant Execution Permissions:**
    ```bash
    chmod +x password_audit.sh
    ```

2.  **Run the script:**
    ```bash
    ./password_audit.sh
    ```

3.  **Follow the prompt:** Enter the password when requested. The input is masked (hidden) for security.

---

### How the Breach Check Works (k-Anonymity)

To maintain privacy, the script utilizes a "range-based" query, ensuring your actual password never leaves your machine:

1.  **Local Hashing:** It hashes your password locally using **SHA-1**.
2.  **Prefixing:** It sends only the **first 5 characters** of that hash to the API.
3.  **Range Retrieval:** The API returns a list of all leaked hash suffixes that start with those same 5 characters.
4.  **Local Match:** The script checks the returned list locally for your specific suffix.



---

### Compliance Summary Table

| Framework | Min Length | Required Complexity |
| :--- | :--- | :--- |
| **FedRAMP** | 12 | Upper, Lower, Number, Special |
| **HIPAA / SOC 2** | 8 | Upper, Lower, Number, Special |
| **PCI DSS** | 7 | Upper, Lower, Number, Special |

---

> [!IMPORTANT]
> This tool is intended for security auditing and educational purposes. While it checks for "known" breaches, a "YES" result from the breach checker does not guarantee a password is unhackable; it simply means it hasn't been found in a public leak yet.
