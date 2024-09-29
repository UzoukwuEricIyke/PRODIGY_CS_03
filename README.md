This project was developed as part of my work at **Prodigy InfoTech** for my **Cybersecurity Internship**.

### Features
- **Password Strength Checker**: Assesses password strength based on length, character variety, and complexity.
- **Entropy Calculation**: Calculates the entropy of a password and estimates the time it would take to crack.
- **Password Breach Check**: Utilizes the "Have I Been Pwned" API to check if a password has been involved in a data breach.
- **Password Policy Compliance**: Customizable password policies to ensure compliance.
- **Password History Tracking**: Prevents the reuse of old passwords by tracking password history.
- **Password Expiration Reminder**: Notifies users when their password is older than 90 days.
- **Password Vault Encryption**: Encrypts stored passwords using strong encryption (Fernet).
- **2FA Recommendations**: Recommends enabling Two-Factor Authentication (2FA) for better security.
- **Customizable Password Generator**: Generate strong, secure passwords based on user preferences.
- **UI (Tkinter)**: Includes a graphical interface with live feedback, a progress bar, and a "Show Password" checkbox.

### Technologies Used
- **Python** (Core Programming Language)
- **Tkinter** (For GUI)
- **Hashlib** (For secure hashing and checking breached passwords)
- **Fernet** (For password vault encryption)
- **Requests** (For API interaction with Have I Been Pwned)

## Installation

### Prerequisites
Make sure you have **Python 3.7+** installed on your system. You will also need to install the following dependencies:
```bash
pip install requests
pip install cryptography
pip install pyotp
```

### Clone the Repository
You can clone the repository using the following command:
```bash
git clone https://github.com/UzoukwuEricIyke/PRODIGY_CS_03.git
```

### Running the Tool
Once the repository is cloned and dependencies installed, run the following command:
```bash
python PasswordCheker.py
```

This will launch the GUI of the password checker tool.

## Usage
1. **Password Strength Checking**: Input a password in the field, and the tool will give you live feedback on its strength.
2. **Password Generation**: Use the password generator to create secure, random passwords.
3. **Two-Factor Authentication**: The tool recommends enabling 2FA based on the account type and password strength.
4. **Breach Checking**: The tool will notify you if your password has been exposed in any breaches.
5. **Progress Bar**: The strength of your password is shown in real-time using the progress bar.
6. **Show Password Checkbox**: Allows you to see the password while typing.

## Contact
**EMail**: uzoukwuericiyke@yahoo.com
**LinkedIn**: https://www.linkedin.com/in/uzoukwu-eric-ikenna/
## Contribution
Feel free to fork this repository and contribute by submitting pull requests. Any suggestions or bug reports are welcome!
