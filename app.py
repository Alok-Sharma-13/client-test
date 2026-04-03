from flask import Flask, render_template, request, redirect, session
from nidra_sdk import NidraSDK

app = Flask(__name__)
app.secret_key = "super_secret_demo_key"

sdk = NidraSDK()


# ---------------- GLOBAL NIDRA PROTECTION ----------------
@app.before_request
def nidra_global_sniffer():
    result = sdk.capture_request(request)
    if result:
        return result


# ---------------- HOME ----------------
@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin":
            session["user"] = username
            return redirect("/home")

        return "Invalid Credentials"

    return render_template("login.html")


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":
        return "User registered successfully"

    return render_template("signup.html")


# ---------------- SEARCH (SQL + XSS demo) ----------------
@app.route("/search")
def search():

    query = request.args.get("q")
    return f"<h3>Search Results For: {query}</h3>"


# ---------------- IDOR ----------------
@app.route("/user/<user_id>")
def user(user_id):

    return f"User Profile ID: {user_id}"


# ---------------- RCE demo ----------------
@app.route("/run", methods=["POST"])
def run():

    command = request.form.get("command")
    return f"Command Executed: {command}"


# ---------------- FILE UPLOAD ----------------
@app.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        file = request.files.get("file")

        if file:
            return f"Uploaded: {file.filename}"

        return "No file uploaded"

    return render_template("upload.html")


# ---------------- START SERVER ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5090, debug=True)