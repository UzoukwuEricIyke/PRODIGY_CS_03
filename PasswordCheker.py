import re
import math
import random
import string
from datetime import datetime
import hashlib
import requests

# Basic password checks
def password_strength_checker(password, personal_info=[], last_changed_date=None, account_type=None, old_passwords=[]):
    strength = 0
    feedback = []
    
    # Check length of the password
    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Password should be at least 8 characters long.")
    
    # Check for both uppercase and lowercase characters
    if re.search("[a-z]", password) and re.search("[A-Z]", password):
        strength += 1
    else:
        feedback.append("Password should contain both uppercase and lowercase letters.")
    
    # Check for digits
    if re.search("[0-9]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one digit.")
    
    # Check for special characters
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        feedback.append("Password should contain at least one special character.")
    
    # Check common passwords
    if check_common_passwords(password):
        feedback.append("Avoid using common passwords.")
    
    # Check repeated or sequential characters
    if check_repeated_or_sequential(password):
        feedback.append("Avoid repeated or sequential characters.")
    
    # Check keyboard patterns
    if check_keyboard_patterns(password):
        feedback.append("Avoid keyboard patterns (e.g., 'qwerty').")
    
    # Check personal information
    if check_personal_info(password, personal_info):
        feedback.append("Avoid using personal information in your password.")
    
    # Check password history
    if check_password_history(password, old_passwords):
        feedback.append("Avoid reusing old passwords.")
    
    # Check phonetic words
    if check_phonetic_password(password):
        feedback.append("Avoid easy-to-remember words in your password.")
    
    # Check geographical names
    if check_geographical_password(password):
        feedback.append("Avoid geographical names in your password.")
    
    # Check for visual similarity
    if check_visual_similarity(password):
        feedback.append("Avoid using visually similar characters (e.g., '1' and 'l').")
    
    # Check if password has been breached
    if check_breached_password(password):
        feedback.append("This password has been exposed in a data breach, please avoid using it.")
    
    # Check password age
    if last_changed_date:
        age_feedback = check_password_age(last_changed_date)
        if age_feedback:
            feedback.append(age_feedback)
    
    # Check entropy
    entropy = calculate_entropy(password)
    
    # Recommend password rotation
    rotation_feedback = recommend_password_rotation(entropy)
    
    # Recommend based on account type
    if account_type:
        policy_feedback = password_policy_recommendation(account_type)
        feedback.append(policy_feedback)
    
    # Determine password strength
    if strength == 4 and entropy > 60 and not feedback:
        return "Strong password!", feedback, rotation_feedback
    elif strength == 3:
        return "Moderately strong password.", feedback, rotation_feedback
    elif strength == 2:
        return "Weak password. Consider improving it.", feedback, rotation_feedback
    else:
        return "Very weak password. Please make significant improvements.", feedback, rotation_feedback


# Additional check functions for password strength checker

def check_common_passwords(password):
    common_passwords = ['123456', 'password', '123456789', 'qwerty', 'abc123', '111111', 'letmein']
    if password in common_passwords:
        return True
    return False

def check_repeated_or_sequential(password):
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):  # Three or more repeated characters
        return True
    
    # Check for sequential characters (e.g., 'abc', '123')
    sequences = 'abcdefghijklmnopqrstuvwxyz0123456789'
    for i in range(len(sequences) - 2):
        seq = sequences[i:i + 3]
        if seq in password or seq[::-1] in password:
            return True
    return False

def check_keyboard_patterns(password):
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '12345']
    for pattern in keyboard_patterns:
        if pattern in password:
            return True
    return False

def check_personal_info(password, personal_info):
    for info in personal_info:
        if info.lower() in password.lower():
            return True
    return False

def check_password_history(password, password_history):
    if password in password_history:
        return True
    return False

def check_phonetic_password(password):
    phonetic_words = ['apple', 'banana', 'tiger', 'lion']  # Common simple words
    if any(word in password.lower() for word in phonetic_words):
        return True
    return False

def check_geographical_password(password):
    geographic_names = ['paris', 'london', 'tokyo', 'newyork']
    if any(city in password.lower() for city in geographic_names):
        return True
    return False

def check_visual_similarity(password):
    visual_pairs = [('0', 'O'), ('1', 'l'), ('I', 'l'), ('5', 'S')]
    for char1, char2 in visual_pairs:
        if char1 in password and char2 in password:
            return True
    return False

def check_breached_password(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if suffix in response.text:
        return True
    return False

def check_password_age(last_changed_date):
    current_date = datetime.now()
    days_elapsed = (current_date - last_changed_date).days
    if days_elapsed > 180:  # 6 months
        return "Your password is older than 6 months. Please consider updating it."
    return ""

def calculate_entropy(password):
    charset_size = 0
    if re.search("[a-z]", password):
        charset_size += 26  # lowercase letters
    if re.search("[A-Z]", password):
        charset_size += 26  # uppercase letters
    if re.search("[0-9]", password):
        charset_size += 10  # digits
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += len("!@#$%^&*(),.?\":{}|<>")  # special characters
    
    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return entropy

def recommend_password_rotation(entropy):
    if entropy < 40:
        return "Consider changing your password every 30 days."
    elif entropy < 60:
        return "Consider changing your password every 90 days."
    else:
        return "This password is strong; you can change it every 6 months."

def password_policy_recommendation(account_type):
    if account_type == "banking":
        return "Your banking password should be changed every 90 days and be at least 12 characters long."
    elif account_type == "email":
        return "Your email password should include 2FA and be changed every 180 days."
    return "Consider rotating passwords based on account sensitivity."

# Password generation function
def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))


# Example usage:
personal_info = ['username123', 'email@example.com', '1990']
old_passwords = ['Password123', 'Qwerty456!', 'Password2021']
last_changed_date = datetime(2023, 1, 1)
password = input("Enter your password: ")
account_type = "banking"

strength, feedback, rotation_recommendation = password_strength_checker(password, personal_info, last_changed_date, account_type, old_passwords)

print("\nPassword strength assessment:")
print(strength)
if feedback:
    print("Suggestions for improvement:")
    for suggestion in feedback:
        print(f"- {suggestion}")

print(rotation_recommendation)
