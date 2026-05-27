# passcheck.sh

A personal security utility for generating and evaluating passwords. Provides compliance reporting against major regulatory frameworks and breach detection via the Have I Been Pwned API.

---

## Features

- **Password Generation:** Generates a cryptographically random password using `/dev/urandom` via the `tr` utility. Pre-selects one character from each required class (uppercase, lowercase, number, special) before filling the remainder, then shuffles the result — guaranteeing class coverage on every generation. Defaults to 16 characters.
- **Complexity Analysis:** Validates passwords for essential traits:
  - Uppercase and lowercase letters
  - Numerical characters
  - Special characters/symbols
- **Regulatory Compliance Mapping:** Checks length and complexity requirements for:
  - **HIPAA / SOC 2 / SOX / ISO 27001:** 8-character minimum, all complexity classes required
  - **FedRAMP:** 12-character minimum, all complexity classes required
  - **PCI DSS v4.0:** 12-character minimum, all complexity classes required
  - **NIST SP 800-63B:** 8-character minimum, no mandatory complexity requirements
- **Breach Detection:** Uses k-Anonymity to check the password's SHA-1 hash against the Have I Been Pwned API without ever transmitting the actual password.
- **Input Sanitization:** Rejects empty inputs and passwords containing whitespace.
- **Columnar Output:** Color-coded, aligned report output for readability.

---

## Prerequisites

- **Environment:** Linux/Unix with `bash`
- **Tools:**
  - `openssl` — SHA-1 hashing for breach detection
  - `curl` — Have I Been Pwned API communication
  - `cut` — hash prefix/suffix extraction
  - `shuf` — password shuffle after generation

---

## Usage

Grant execution permissions:

```bash
chmod +x passcheck.sh
```

Run the script:

```
./passcheck.sh [OPTION]

Options:
  --check         Assess a password against compliance frameworks and known breaches
  --generate [N]  Generate a secure password of N characters (default: 16)
  --help          Display help message

Examples:
  ./passcheck.sh --check
  ./passcheck.sh --generate
  ./passcheck.sh --generate 20
```

---

## How Breach Detection Works (k-Anonymity)

1. **Local hashing:** The password is hashed locally using SHA-1
2. **Prefixing:** Only the first 5 characters of the hash are sent to the API
3. **Range retrieval:** The API returns all leaked hash suffixes matching that prefix
4. **Local match:** The script checks the returned list locally for your specific suffix

Your actual password never leaves your machine.

---

## Compliance Summary

| Framework | Min Length | Complexity Required |
| :--- | :--- | :--- |
| NIST SP 800-63B | 8 | None |
| HIPAA / SOC 2 / SOX / ISO 27001 | 8 | Upper, lower, number, special |
| FedRAMP | 12 | Upper, lower, number, special |
| PCI DSS v4.0 | 12 | Upper, lower, number, special |

---

> [!IMPORTANT]
> Intended for personal use and educational purposes only. Do not assess production credentials. A negative breach result means the password was not found in known public leaks — it does not guarantee the password is secure.
