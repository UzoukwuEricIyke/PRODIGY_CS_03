import re
import string
import random
import hashlib
import requests
import math
from datetime import datetime, timedelta
from tkinter import *
from tkinter import ttk
from tkinter.messagebox import showinfo
from cryptography.fernet import Fernet

# Password History Tracking
password_history = []

# Function to generate a password based on policy
def generate_custom_password(length=16, exclude_ambiguous=True, avoid_repeating=True):
    characters = string.ascii_letters + string.digits + string.punctuation
    if exclude_ambiguous:
        characters = characters.replace('l', '').replace('1', '').replace('O', '').replace('0', '')

    password = ''.join(random.choice(characters) for i in range(length))
    
    if avoid_repeating:
        while re.search(r'(.)\1', password):  # Avoid repeating characters
            password = ''.join(random.choice(characters) for i in range(length))
    
    return password

# Check if the password has been breached using Have I Been Pwned API
def check_breached_password(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if suffix in response.text:
        return True
    return False

# Calculate the entropy of a password
def calculate_entropy(password):
    charset_size = 0
    if re.search("[a-z]", password):
        charset_size += 26
    if re.search("[A-Z]", password):
        charset_size += 26
    if re.search("[0-9]", password):
        charset_size += 10
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += len("!@#$%^&*(),.?\":{}|<>")
    
    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return entropy

# Estimate the cracking time based on entropy
def estimate_cracking_time(entropy):
    attempts_per_second = 1e9  # 1 billion guesses per second
    possible_combinations = 2 ** entropy
    cracking_time_seconds = possible_combinations / attempts_per_second
    cracking_time_hours = cracking_time_seconds / 3600
    return f"Estimated time to crack: {cracking_time_hours:.2f} hours"

# Check password compliance with policies (e.g., NIST)
def password_policy_compliance(password):
    nist_compliant = len(password) >= 12 and bool(re.search("[A-Z]", password)) and bool(re.search("[a-z]", password)) and bool(re.search("[0-9]", password)) and bool(re.search("[!@#$%^&*(),.?\":{}|<>]", password))
    if not nist_compliant:
        return "Your password does not comply with NIST standards (minimum 12 characters, mixed case, digits, special characters)."
    return "Your password complies with NIST standards."

# Password strength checker
def password_strength_checker(password):
    feedback = []
    strength = 0

    if len(password) >= 12:
        strength += 1
    else:
        feedback.append("Password should be at least 12 characters long.")
    
    if re.search("[a-z]", password) and re.search("[A-Z]", password):
        strength += 1
    else:
        feedback.append("Password should contain both uppercase and lowercase letters.")
    
    if re.search("[0-9]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one digit.")
    
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one special character.")
    
    if strength >= 4:
        return "Strong password", strength, feedback
    elif strength == 3:
        return "Moderately strong password", strength, feedback
    else:
        return "Weak password", strength, feedback

# Password history tracker to avoid reusing old passwords
def check_password_history(password, old_passwords):
    if password in old_passwords:
        return "This password was used before. Please choose a new one."
    return ""

# Password expiration reminder
def password_age_reminder(last_changed_date):
    current_date = datetime.now()
    if last_changed_date:
        days_elapsed = (current_date - last_changed_date).days
        if days_elapsed > 90:
            return f"Your password is {days_elapsed} days old. Please consider changing it."
    return ""

# Store password in an encrypted vault
def store_password_in_vault(password):
    key = Fernet.generate_key()  # Securely persist this key
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password.encode())
    return encrypted_password

# Two-Factor Authentication (2FA) Suggestion
def suggest_2fa():
    return "For enhanced security, it's highly recommended to enable Two-Factor Authentication (2FA)."

# UI Setup using Tkinter
def create_password_tool():
    def update_password_strength(event=None):
        password = password_entry.get()
        result, strength, feedback = password_strength_checker(password)
        progress['value'] = strength * 25
        strength_label.config(text=result)
        feedback_label.config(text="\n".join(feedback))

    def toggle_password():
        if show_password_var.get():
            password_entry.config(show='')
        else:
            password_entry.config(show='*')

    def generate_password():
        password = generate_custom_password()
        password_entry.delete(0, END)
        password_entry.insert(0, password)
        update_password_strength()

    def check_password():
        password = password_entry.get()
        policy_feedback = password_policy_compliance(password)
        breach_check = check_breached_password(password)
        breach_feedback = "Your password was found in a breach!" if breach_check else "Your password has not been found in any breach."
        entropy = calculate_entropy(password)
        crack_time = estimate_cracking_time(entropy)
        history_feedback = check_password_history(password, password_history)
        expiration_feedback = password_age_reminder(datetime.now() - timedelta(days=198))
        password_history.append(password)
        
        # Combine all feedback
        full_feedback = "\n".join([policy_feedback, breach_feedback, crack_time, history_feedback, expiration_feedback])
        result_label.config(text=full_feedback)

    # Window Setup
    window = Tk()
    window.title("Advanced Password Tool")
    
    # Password Entry
    Label(window, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
    password_entry = Entry(window, show='*', width=30)
    password_entry.grid(row=0, column=1)
    password_entry.bind('<KeyRelease>', update_password_strength)

    # Show Password Checkbox
    show_password_var = IntVar()
    show_password_check = Checkbutton(window, text="Show Password", variable=show_password_var, command=toggle_password)
    show_password_check.grid(row=1, column=1, padx=10, pady=5)

    # Strength Label
    strength_label = Label(window, text="Strength: ", fg="black")
    strength_label.grid(row=2, column=1, padx=10, pady=5)

    # Feedback Label
    feedback_label = Label(window, text="", fg="red")
    feedback_label.grid(row=3, column=1, padx=10, pady=5)

    # Progress Bar
    progress = ttk.Progressbar(window, orient=HORIZONTAL, length=200, mode='determinate')
    progress.grid(row=4, column=1, padx=10, pady=5)

    # Buttons
    generate_button = Button(window, text="Generate Password", command=generate_password)
    generate_button.grid(row=5, column=0, padx=10, pady=10)

    check_button = Button(window, text="Check Password", command=check_password)
    check_button.grid(row=5, column=1, padx=10, pady=10)

    # 2FA Suggestion
    twofa_label = Label(window, text=suggest_2fa(), fg="blue")
    twofa_label.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

    # Feedback Result
    result_label = Label(window, text="", fg="green", wraplength=400)
    result_label.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    window.mainloop()

# Initialize the password tool
create_password_tool()
