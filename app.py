from flask import Flask, render_template, request
import re
import hashlib
import requests

app = Flask(__name__)

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
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking breach status."

    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return f"⚠️ Found in {count} breaches."
    return "✅ No known breaches."

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    breach = ""
    if request.method == "POST":
        password = request.form["password"]
        result = check_password_strength(password)
        if result == "Password is strong.":
            breach = check_pwned(password)
    return render_template("index.html", result=result, breach=breach)

if __name__ == "__main__":
    app.run(debug=True)
  