import re
import hashlib
import requests

def check_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return "Password is strong."

def check_pwned(password):
    # Hash password with SHA1 and split into prefix and suffix
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    # Send only the first 5 characters of the hash to the API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking breach status."

    # Check if suffix appears in response
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return f"⚠️ This password has been seen {count} times in data breaches."
    return "✅ This password has not been found in any known breaches."

# Example usage
import tkinter as tk
from tkinter import messagebox

window = tk.Tk()
window.title("Password Checker")
window.geometry("400x250")

label = tk.Label(window, text="Enter your password:", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(window, show="*", width=30)
entry.pack(pady=5)

def on_check_click():
    password = entry.get()
    strength = check_password_strength(password)
    if strength != "Password is strong.":
        messagebox.showwarning("Strength Result", strength)
    else:
        breach = check_pwned(password)
        messagebox.showinfo("Password Check", f"{strength}\n{breach}")

        entry.delete(0, tk.END)

button = tk.Button(window, text="Check Password", command=on_check_click)
button.pack(pady=15)

window.mainloop()

