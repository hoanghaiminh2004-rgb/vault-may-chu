# -*- coding: utf-8 -*-
"""
Vault Server - HTTP server chay ở may chu mày.

API:
  GET  /health                    -> 'OK'
  GET  /vault?email=X&password=Y  -> tra vault bytes neu user/pass dung
                                     (server re-encrypt bang SHA-256(salt+pass_user)
                                      de user tu unlock ở may minh)
  POST /admin/user                -> admin them user (X-Admin-Token header)
  POST /admin/assign-vault        -> admin gan vault cho user

Server luu:
  - users.json  : { email: { password_hash, vault_file } }
  - vaults/     : cac vault.bin (mỗi user có thể có vault riêng)
  - salt_per_vault.bin : mapping user -> salt de server re-encrypt

Flow user:
  1. User mo app, nhap email + pass
  2. App goi GET /vault?email=X&password=Y
  3. Server check user ton tai + pass hash khop
  4. Server doc vault của user, RE-ENCRYPT bang SHA-256(salt_user + pass_user)
  5. Tra vault bytes cho app
  6. App ghi vault.bin local, chay vault_unlocker voi pass user vua nhap
  7. App import cookie -> ready

Luư y bao mat:
  - Server KHONG gui plain vault; luon re-encrypt bang pass cua user.
  - User khong biet master pass cua admin, chi biet pass cua minh.
  - Pass user duoc hash SHA-256 voi salt rieng de so sanh.
  - Neu attacker intercept HTTP request -> van khong giai ma duoc vault
    vi pass user chi co user biet (qua HTTPS la tot nhat).

Deploy:
  python vault_server.py --port 7777
  # Hoac deploy len Render/Railway/Heroku mien phi
"""
import os
import sys
import json
import time
import hashlib
import secrets
import argparse
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Crypto
from cookie_vault import _aes_encrypt, _aes_decrypt, _derive_key


# Production: doc data dir tu env (Render disk mount tai /data, local dung BASE)
DATA_DIR = os.environ.get("VAULT_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(DATA_DIR, "users.json")
VAULTS_DIR = os.path.join(DATA_DIR, "vaults")
SESSIONS_FILE = os.path.join(DATA_DIR, "active_sessions.json")
ADMIN_TOKEN = os.environ.get("VAULT_ADMIN_TOKEN", "admin-secret-token-change-me")
HOST = os.environ.get("VAULT_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("VAULT_PORT", "7777")))

# Session timeout: 1h (neu user app tat dot ngot, session stale sau 1h)
SESSION_TTL = int(os.environ.get("VAULT_SESSION_TTL", "3600"))

# Storage backend: neu co GITHUB_TOKEN → luu tren GitHub (free, persistent)
# Nếu không → dùng local disk
try:
    import github_storage
    if github_storage.is_enabled():
        USE_GITHUB = True
        print("[storage] Using GitHub repo for data persistence (FREE, no disk needed)")
    else:
        USE_GITHUB = False
        print("[storage] Using local disk (no GITHUB_TOKEN set)")
except ImportError:
    USE_GITHUB = False
    print("[storage] github_storage.py not found, using local disk")


def _hash_password(password: str, salt: bytes) -> str:
    """Hash user password voi salt rieng de luu trong users.json."""
    h = hashlib.sha256()
    h.update(salt)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def _apply_user_license(vault_json: bytes, user_exp: float, user_days: int) -> bytes:
    """Ghi hạn THẬT của user vào mọi acc trong vault trước khi phát.

    Vault do admin build chung cho nhiều user nên expires_at bên trong là ngày
    build + active_days của admin (vd 30 ngày). Không sửa thì user được cấp 1
    ngày vẫn hiện "Còn: 29 ngày" và acc hết hạn theo license không bị loại.
    Dùng min(hạn acc, hạn user): acc chết do cookie hết hiệu lực vẫn bị loại đúng.
    """
    if not user_exp:
        return vault_json
    try:
        payload = json.loads(vault_json.decode("utf-8"))
    except Exception:
        return vault_json          # không phải JSON (vault lạ) -> giữ nguyên
    try:
        accounts = payload.get("accounts") or {}
        for _svc, accs in accounts.items():
            for acc in accs:
                acc_exp = float(acc.get("expires_at", 0) or 0)
                acc["expires_at"] = min(acc_exp, user_exp) if acc_exp > 0 else user_exp
                acc["active_days"] = user_days
        payload["active_days_default"] = user_days
        payload["license_expires_at"] = user_exp
        return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception as e:
        print(f"[license] inject skip: {e}")
        return vault_json


def _ensure_dirs():
    if USE_GITHUB:
        return  # GitHub auto tao file
    os.makedirs(VAULTS_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)
    if not os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)


def _load_users() -> dict:
    _ensure_dirs()
    if USE_GITHUB:
        try:
            content = github_storage.read_file("data/users.json")
            return json.loads(content) if content else {}
        except Exception as e:
            print(f"[load_users] GitHub err: {e}")
            return {}
    else:
        with open(USERS_FILE, encoding="utf-8") as f:
            return json.load(f)


def _save_users(users: dict):
    if USE_GITHUB:
        try:
            github_storage.write_file("data/users.json",
                json.dumps(users, ensure_ascii=False, indent=2),
                commit_msg=f"update users.json ({len(users)} users)")
        except Exception as e:
            print(f"[save_users] GitHub err: {e}")
    else:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)


def _load_sessions() -> dict:
    """{email: {session_id, started_at, last_heartbeat, ip}}.
    Cleanup session stale (last_heartbeat + SESSION_TTL < now) truoc khi return."""
    _ensure_dirs()
    if USE_GITHUB:
        try:
            content = github_storage.read_file("data/active_sessions.json")
            sessions = json.loads(content) if content else {}
        except Exception:
            sessions = {}
    else:
        try:
            with open(SESSIONS_FILE, encoding="utf-8") as f:
                sessions = json.load(f)
        except Exception:
            sessions = {}
    now = time.time()
    cleaned = {}
    for email, s in sessions.items():
        if now - s.get("last_heartbeat", 0) < SESSION_TTL:
            cleaned[email] = s
    if len(cleaned) != len(sessions):
        _save_sessions(cleaned)
    return cleaned


def _save_sessions(sessions: dict):
    if USE_GITHUB:
        try:
            github_storage.write_file("data/active_sessions.json",
                json.dumps(sessions, ensure_ascii=False, indent=2),
                commit_msg=f"update sessions ({len(sessions)} active)")
        except Exception as e:
            print(f"[save_sessions] GitHub err: {e}")
    else:
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(sessions, f, ensure_ascii=False, indent=2)


def _vault_path(filename: str) -> str:
    """Tra ve path tuong doi (GitHub) hoac tuyet doi (local)."""
    if USE_GITHUB:
        return f"data/vaults/{filename}"
    return os.path.join(VAULTS_DIR, filename)


def _read_vault(filename: str) -> bytes:
    if USE_GITHUB:
        return github_storage.read_bytes(_vault_path(filename))
    with open(os.path.join(VAULTS_DIR, filename), "rb") as f:
        return f.read()


def _write_vault(filename: str, data: bytes):
    if USE_GITHUB:
        github_storage.write_bytes(_vault_path(filename), data,
                                     commit_msg=f"vault {filename}")
    else:
        with open(os.path.join(VAULTS_DIR, filename), "wb") as f:
            f.write(data)


def _delete_vault(filename: str):
    if USE_GITHUB:
        github_storage.delete_file(_vault_path(filename),
                                     commit_msg=f"delete vault {filename}")
    else:
        vf = os.path.join(VAULTS_DIR, filename)
        if os.path.exists(vf):
            os.unlink(vf)


def _get_active_session(email: str):
    """Tra ve session info neu user dang login, neu stale/khong co -> None."""
    sessions = _load_sessions()
    s = sessions.get(email)
    if not s:
        return None
    if time.time() - s.get("last_heartbeat", 0) > SESSION_TTL:
        return None
    return s


def _register_session(email: str, session_id: str, ip: str = ""):
    """Tao/cap nhat session cho user. Replace session cu (force login)."""
    sessions = _load_sessions()
    sessions[email] = {
        "session_id": session_id,
        "started_at": time.time(),
        "last_heartbeat": time.time(),
        "ip": ip,
    }
    _save_sessions(sessions)


def _clear_session(email: str):
    sessions = _load_sessions()
    sessions.pop(email, None)
    _save_sessions(sessions)


def _heartbeat_session(email: str, session_id: str):
    """Cap nhat last_heartbeat neu session_id khop. Neu khong khop -> raise ValueError."""
    sessions = _load_sessions()
    s = sessions.get(email)
    if not s or s.get("session_id") != session_id:
        raise ValueError("session_id invalid or expired")
    s["last_heartbeat"] = time.time()
    _save_sessions(sessions)


# ============================================================ #
#  HTTP Request Handler                                         #
# ============================================================ #
class VaultHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quiet log
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}\n")

    def _send(self, code, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            content_type = "application/json"
        elif isinstance(body, str):
            body = body.encode("utf-8")
        elif isinstance(body, bytes):
            pass
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- GET ----- #

    def do_DELETE(self):
        u = urlparse(self.path)
        # User logout: khong can admin token, can session_id
        if u.path.startswith("/vault/") and len(u.path) > len("/vault/"):
            return self._handle_logout(parse_qs(u.query),
                                         u.path[len("/vault/"):])
        # Admin: DELETE /admin/user/{email} can admin token
        if u.path.startswith("/admin/user/"):
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                return self._send(403, {"error": "admin token required"})
            return self._handle_delete_user(u.path[len("/admin/user/"):])
        # Admin: DELETE /admin/session/{email} can admin token (force kick)
        if u.path.startswith("/admin/session/"):
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                return self._send(403, {"error": "admin token required"})
            return self._handle_kick_session(u.path[len("/admin/session/"):])
        return self._send(404, {"error": "not found"})

    def _handle_kick_session(self, path_email):
        """Admin force logout 1 user (kick session)."""
        email = path_email.lower().strip()
        from urllib.parse import unquote
        email = unquote(email)
        sessions = _load_sessions()
        if email not in sessions:
            return self._send(404, {"error": "no active session for this user"})
        _clear_session(email)
        return self._send(200, {"ok": True, "email": email, "kicked": True})

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"ok": True, "time": time.time()})
        if u.path == "/vault":
            return self._handle_get_vault(parse_qs(u.query))
        if u.path == "/heartbeat":
            return self._handle_heartbeat(parse_qs(u.query))
        if u.path == "/admin/sessions":
            token = self.headers.get("X-Admin-Token", "")
            if token != ADMIN_TOKEN:
                return self._send(403, {"error": "admin token required"})
            sessions = _load_sessions()
            return self._send(200, {"sessions": sessions, "count": len(sessions)})
        return self._send(404, {"error": "not found"})

    def _handle_heartbeat(self, qs):
        """User app goi dinh ky 5-10p de giu session alive."""
        email = (qs.get("email", [""])[0] or "").lower().strip()
        session_id = qs.get("session_id", [""])[0]
        if not email or not session_id:
            return self._send(400, {"error": "email + session_id required"})
        try:
            _heartbeat_session(email, session_id)
        except ValueError as e:
            return self._send(401, {"error": str(e), "acc_in_use": True})
        return self._send(200, {"ok": True, "heartbeat": time.time()})

    def _handle_logout(self, qs, path_email):
        """User app close -> goi DELETE /vault/{email}?session_id=X de free slot."""
        email = path_email.lower().strip()
        session_id = qs.get("session_id", [""])[0]
        sessions = _load_sessions()
        s = sessions.get(email)
        if not s:
            return self._send(200, {"ok": True, "message": "no active session"})
        if session_id and s.get("session_id") != session_id:
            return self._send(401, {"error": "session_id mismatch"})
        _clear_session(email)
        return self._send(200, {"ok": True, "message": "logged out"})

    def _handle_get_vault(self, qs):
        email = (qs.get("email", [""])[0] or "").lower().strip()
        password = qs.get("password", [""])[0]
        kick = qs.get("kick", ["0"])[0] in ("1", "true", "yes")
        client_session = qs.get("session_id", [""])[0] or None
        if not email or not password:
            return self._send(400, {"error": "email + password required"})
        users = _load_users()
        # 10-09: Check expires_at — hết hạn → từ chối + xóa session
        if email in users:
            u_check = users[email]
            exp = u_check.get("expires_at", 0)
            if exp and exp < time.time():
                # Hết hạn → xóa user, vault, session
                old_vault = u_check.get("vault_file", "")
                if old_vault:
                    try:
                        os.remove(os.path.join(VAULTS_DIR, old_vault))
                    except Exception:
                        pass
                _clear_session(email)
                del users[email]
                _save_users(users)
                return self._send(401, {
                    "error": "expired",
                    "message": f"Acc '{email}' đã hết hạn. Liên hệ admin gia hạn hoặc tạo acc mới."
                })
        if email not in users:
            return self._send(401, {"error": "user not found"})
        u = users[email]
        # Verify password
        user_salt = bytes.fromhex(u["salt_hex"])
        expected = u["password_hash"]
        actual = _hash_password(password, user_salt)
        if actual != expected:
            return self._send(401, {"error": "wrong password"})
        # Check session conflict (1 acc = 1 user dang login)
        active = _get_active_session(email)
        if active and active.get("session_id") != client_session:
            # Co nguoi khac dang login acc nay
            if not kick:
                return self._send(409, {
                    "error": "acc_in_use",
                    "message": f"Acc '{email}' đang được sử dụng trên thiết bị khác "
                                f"(từ {active.get('ip', '?')}, "
                                f"vào lúc {time.strftime('%H:%M:%S', time.localtime(active.get('started_at', 0)))}). "
                                f"Đăng nhập sẽ đăng xuất thiết bị cũ.",
                    "started_at": active.get("started_at", 0),
                    "ip": active.get("ip", ""),
                })
            # Force: clear session cu, cho phep login moi
        # Read vault file
        vf = u.get("vault_file", "")
        if not vf:
            return self._send(404, {"error": "vault not assigned - admin chưa gán vault cho user này"})
        try:
            stored = _read_vault(vf)
        except FileNotFoundError:
            return self._send(404, {"error": "vault file missing - admin cần gán lại vault"})
        except Exception as e:
            return self._send(500, {"error": f"vault read error: {str(e)[:100]}"})
        if not stored:
            return self._send(404, {"error": "vault empty"})
        # Giai ma admin layer
        try:
            admin_salt = stored[:16]
            admin_ct = stored[16:]
            admin_key = _derive_key("admin123", admin_salt)
            vault_bytes = _aes_decrypt(admin_ct, admin_key)
        except Exception:
            vault_bytes = stored
        # 10-09: ép hạn của USER vào từng acc (trước đây user được cấp 1 ngày
        # vẫn thấy "Còn: 29 ngày" vì dùng expires_at lúc admin build vault).
        vault_bytes = _apply_user_license(vault_bytes,
                                          u.get("expires_at", 0),
                                          u.get("active_days", 30))
        # Re-encrypt vault bang pass user
        new_salt = secrets.token_bytes(16)
        key = _derive_key(password, new_salt)
        re_encrypted = new_salt + _aes_encrypt(vault_bytes, key)
        # Cap nhat session (replace neu force, hoac tao moi)
        new_session_id = secrets.token_urlsafe(24)
        _register_session(email, new_session_id, self.address_string())
        return self._send(200, {
            "email": email,
            "vault_b64": base64.b64encode(re_encrypted).decode("ascii"),
            "expires_at": u.get("expires_at", 0),
            "active_days": u.get("active_days", 30),
            "size": len(re_encrypted),
            "session_id": new_session_id,
            "force_kicked": bool(active and active.get("session_id") != client_session),
        })

    # ----- POST ----- #
    def do_POST(self):
        u = urlparse(self.path)
        # Admin auth qua header
        token = self.headers.get("X-Admin-Token", "")
        if token != ADMIN_TOKEN:
            return self._send(403, {"error": "admin token required"})
        if u.path == "/admin/user":
            return self._handle_create_user()
        if u.path.startswith("/admin/user/"):
            return self._handle_delete_user(u.path[len("/admin/user/"):])
        if u.path == "/admin/assign-vault":
            return self._handle_assign_vault()
        return self._send(404, {"error": "not found"})

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {}

    def _handle_create_user(self):
        body = self._read_body()
        email = (body.get("email", "") or "").lower().strip()
        password = body.get("password", "")
        active_days = int(body.get("active_days", 30))
        force = body.get("force", False) in (True, "true", "1", 1)
        if not email or not password:
            return self._send(400, {"error": "email + password required"})
        users = _load_users()
        if email in users:
            old = users[email]
            old_exp = old.get("expires_at", 0)
            now = time.time()
            if old_exp > now and not force:
                # Còn hạn + không force → từ chối
                days_left = int((old_exp - now) / 86400) + 1
                return self._send(409, {
                    "error": "user already exists",
                    "active": True,
                    "expires_at": old_exp,
                    "days_left": days_left,
                    "message": f"User còn {days_left} ngày. Đợi hết hạn hoặc bấm 'Xóa User cũ' trước."
                })
            # Hết hạn HOẶC force → xóa user cũ + vault cũ + session cũ
            old_vault = old.get("vault_file", "")
            if old_vault:
                try:
                    os.remove(os.path.join(VAULTS_DIR, old_vault))
                except Exception:
                    pass
            _clear_session(email)
            del users[email]
            _save_users(users)
        salt = secrets.token_bytes(16)
        users[email] = {
            "password_hash": _hash_password(password, salt),
            "salt_hex": salt.hex(),
            "active_days": active_days,
            "created_at": time.time(),
            "expires_at": time.time() + active_days * 86400,
            "vault_file": "",  # gan sau
        }
        _save_users(users)
        return self._send(200, {
            "ok": True,
            "email": email,
            "active_days": active_days,
            "replaced": email in users and users[email].get("created_at", 0) < 5,  # just created
        })

    def _handle_assign_vault(self):
        body = self._read_body()
        email = (body.get("email", "") or "").lower().strip()
        vault_b64 = body.get("vault_b64", "")
        if not email or not vault_b64:
            return self._send(400, {"error": "email + vault_b64 required"})
        users = _load_users()
        if email not in users:
            return self._send(404, {"error": "user not found"})
        try:
            # vault_b64 co the la vault encrypted (tu build_vault) HOAC plain JSON
            # Neu plain JSON -> server encrypt bang admin master key de luu (bao mat)
            vault_bytes = base64.b64decode(vault_b64)
            try:
                # Thu giai ma voi admin master de xem co phai vault encrypted
                from cookie_vault import unlock_vault as _uv
                import tempfile as _tf
                with _tf.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
                    tmp.write(vault_bytes)
                    tmp_path = tmp.name
                try:
                    _uv(tmp_path, "admin@company.com", "admin123")
                finally:
                    try: os.unlink(tmp_path)
                    except: pass
                # La vault encrypted -> luu nguyen xi
                final_bytes = vault_bytes
            except Exception:
                # Plain JSON -> server ma hoa bang admin master de luu
                admin_salt = os.urandom(16)
                admin_key = _derive_key("admin123", admin_salt)
                final_bytes = admin_salt + _aes_encrypt(vault_bytes, admin_key)
        except Exception:
            return self._send(400, {"error": "vault_b64 invalid"})
        # Save vault riêng cho user
        vault_filename = f"{email.replace('@','_at_')}.bin"
        _write_vault(vault_filename, final_bytes)
        users[email]["vault_file"] = vault_filename
        _save_users(users)
        return self._send(200, {"ok": True, "email": email,
                                 "vault_size": len(final_bytes),
                                 "vault_file": vault_filename})


# ============================================================ #
#  CLI                                                         #
# ============================================================ #
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=None,
                         help="Override port (default: env PORT or 7777)")
    parser.add_argument("--host", default=None,
                         help="Override host (default: env VAULT_HOST or 0.0.0.0)")
    args = parser.parse_args()
    port = args.port or PORT
    host = args.host or HOST

    _ensure_dirs()
    server = ThreadingHTTPServer((host, port), VaultHandler)
    print(f"🔒 Vault server chay ở http://{host}:{port}")
    print(f"  Data dir: {DATA_DIR}")
    print(f"  Admin token: {'***' + ADMIN_TOKEN[-8:] if len(ADMIN_TOKEN) > 8 else ADMIN_TOKEN}")
    print(f"  Health: GET /health")
    print(f"  Get vault: GET /vault?email=X&password=Y")
    print(f"  Add user: POST /admin/user + X-Admin-Token")
    print(f"  Assign vault: POST /admin/assign-vault + X-Admin-Token")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
