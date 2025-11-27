import os
import hashlib
import base64
from threading import Thread
from time import sleep
from flask import Flask, render_template, request, send_file, session
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect

# Create app and configure
app = Flask(__name__)
# add this line (use a real secret in production)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# optional: keep CSRF disabled for local testing (or remove this if you want CSRF)
app.config["WTF_CSRF_ENABLED"] = False
csrf = CSRFProtect(app)

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB
ALLOWED_EXTENSIONS = {"txt", "pdf", "jpg", "jpeg", "png", "zip", "csv", "docx"}


def generate_key_from_password(password: str) -> bytes:
    """Derive a 32-byte key from password for Fernet."""
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _cleanup_later(paths: list[str], delay: int = 30) -> None:
    """Remove files after delay in background."""
    def _worker():
        sleep(delay)
        for p in paths:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
    Thread(target=_worker, daemon=True).start()


@app.route("/")
def home():
    # Ensure templates/index.html exists and includes a form posting to /process
    return render_template("index.html", message=None)


@app.route("/process", methods=["POST"])
def process():
    # validation
    if "file" not in request.files:
        return render_template("index.html", message="Error: No file uploaded.")
    file = request.files["file"]
    if file.filename == "":
        return render_template("index.html", message="Error: Empty filename.")
    if not allowed_file(file.filename):
        return render_template("index.html", message="Error: File type not allowed.")

    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(upload_path)

    password = request.form.get("password", "")
    mode = request.form.get("mode", "encrypt").lower()

    if len(password) < 4:
        return render_template("index.html", message="Error: Password must be at least 4 characters.")

    session.setdefault("attempts", 0)
    if session.get("attempts", 0) > 5:
        return render_template("index.html", message="Too many attempts. Try later.")

    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)

        if mode == "encrypt":
            with open(upload_path, "rb") as f:
                data = f.read()
            out_path = upload_path + ".enc"
            with open(out_path, "wb") as f:
                f.write(fernet.encrypt(data))

            # schedule cleanup of both files after sending
            _cleanup_later([upload_path, out_path], delay=30)
            return send_file(out_path, as_attachment=True)

        elif mode == "decrypt":
            with open(upload_path, "rb") as f:
                encrypted = f.read()
            try:
                decrypted = fernet.decrypt(encrypted)
            except Exception:
                session["attempts"] = session.get("attempts", 0) + 1
                return render_template("index.html", message="Decryption failed: invalid password or file.")
            out_path = upload_path + ".dec"
            with open(out_path, "wb") as f:
                f.write(decrypted)

            _cleanup_later([upload_path, out_path], delay=30)
            session["attempts"] = 0
            return send_file(out_path, as_attachment=True)

        else:
            return render_template("index.html", message="Invalid mode selected.")

    except Exception as e:
        return render_template("index.html", message=f"Processing failed: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
