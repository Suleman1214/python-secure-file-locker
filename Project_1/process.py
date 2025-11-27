import os
import base64
from typing import Optional
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

DEFAULT_ALLOWED_EXT = {"txt", "pdf", "jpg", "jpeg", "png", "zip", "csv", "docx"}

def generate_key_from_password(password: str) -> bytes:
    """Create a 32-byte key from password and return a urlsafe base64-encoded key for Fernet."""
    password_bytes = password.encode()
    # truncate or pad to 32 bytes then base64-encode -> valid Fernet key
    padded = password_bytes[:32].ljust(32, b"0")
    return base64.urlsafe_b64encode(padded)

def allowed_file(filename: str, allowed_extensions: Optional[set] = None) -> bool:
    """Return True if filename has an allowed extension."""
    if not filename or "." not in filename:
        return False
    if allowed_extensions is None:
        allowed_extensions = DEFAULT_ALLOWED_EXT
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions

def encrypt_file(filepath: str, password: str) -> str:
    """Encrypt file at filepath using password-derived key. Returns encrypted file path."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    output_path = filepath + ".encrypted"
    with open(output_path, "wb") as f:
        f.write(encrypted)
    return output_path

def decrypt_file(filepath: str, password: str) -> Optional[str]:
    """Decrypt a .encrypted file with the provided password. Returns output path or None on failure."""
    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        decrypted = fernet.decrypt(encrypted_data)
        output_path = filepath.replace(".encrypted", "")
        with open(output_path, "wb") as f:
            f.write(decrypted)
        return output_path
    except Exception:
        return None

def cleanup_files(*paths: str) -> None:
    """Remove files if they exist; swallow errors."""
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

