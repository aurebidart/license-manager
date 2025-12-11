# **License Manager – Token-Based License Generation (JWT + RSA-PSS)**

A lightweight and secure licensing system that generates and verifies license tokens using **JWT (PS256)** and **RSA 4096-bit key pairs**.

## 🚀 Features

* Generates RSA 4096-bit private/public key pairs
* Creates or loads license metadata (client name, start timestamp, end timestamp)
* Produces a **signed JWT license token** using **PS256 (RSA-PSS + SHA256)**
* Verifies tokens using the public key
* CLI-based workflow for automation and CI/CD
* Clean file structure suitable for production use

---

## 📂 Project Structure

```
license-manager/
│
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── license_manager/
│   │   ├── __init__.py
│   │   ├── token_generator.py
│   │   └── token_verifier.py
│   ├── keys/               # auto-generated, not committed
│   └── licenses/           # auto-generated, not committed
└── scripts/
    ├── generate_token.sh
    └── verify_token.sh
```

---

## 🔧 Installation

```bash
git clone https://github.com/aurebidart/license-manager.git
cd license-manager
pip install -r requirements.txt
```

---

## 📝 Usage

### **Generate a token**

```bash
python src/license_manager/token_generator.py \
    --name "ClientX" \
    --start 1736530000 \
    --end 1768066000
```

If no license file exists, the script will ask for the values interactively.

### **Verify a token**

```bash
python src/license_manager/token_verifier.py
```

---

## 🔒 Security Notes

* RSA keys are **not** committed thanks to `.gitignore`.
* JWT uses **PS256**, which is more secure than RS256.
* Timestamps must be UNIX epoch (seconds).
* Never share your private key.

---

## 📜 License

MIT License