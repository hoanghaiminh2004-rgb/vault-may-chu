# -*- coding: utf-8 -*-
"""
Cookie Vault - Dong goi cookie 3 engine vao 1 file duy nhat, khoa bang AES.

Admin (mày) dung build_vault() de tao vault.bin chua 8 acc Flow + 8 acc ChatGPT
+ 8 acc Gemini + 1 master account. User khi download .exe, nhap email/pass
do mày cung cap -> tool unlock_vault() giai ma, dump cookie vao Chrome profile
local cua user, app san sang chay.

Format vault.bin (binary):
  [16 byte salt][16 byte iv][N byte ciphertext]

Ciphertext = AES-256-CBC (key = SHA-256(salt + master_password))
JSON ben trong:
  {
    "version": 1,
    "created": "2024-...",
    "master_email": "admin@company.com",
    "accounts": {
        "flow":    [{"id": "f01", "label": "Flow Acc 1", "cookies": [...]}, ...],
        "chatgpt": [{"id": "c01", "label": "ChatGPT Acc 1", "cookies": [...]}, ...],
        "gemini":  [{"id": "g01", "label": "Gemini Acc 1", "cookies": [...]}, ...]
    }
  }
"""
import os
import json
import time
import base64
import hashlib
import datetime
from typing import List, Dict, Optional


# ------------------------------------------------------------------ #
#  Crypto: AES-256-CBC qua pycryptodome (fallback cryptography lib)   #
# ------------------------------------------------------------------ #
def _aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt. key = 32 bytes, iv random 16 bytes prefix."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as _pad
        iv = os.urandom(16)
        padder = _pad.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
        return iv + ct
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ct


def _aes_decrypt(blob: bytes, key: bytes) -> bytes:
    """AES-256-CBC decrypt. First 16 bytes of blob = IV."""
    iv = blob[:16]
    ct = blob[16:]
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as _pad
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        unpadder = _pad.PKCS7(128).unpadder()
        return unpadder.update(pt) + unpadder.finalize()


def _derive_key(master_password: str, salt: bytes) -> bytes:
    """Key = SHA-256(salt + master_password) — đơn giản, đủ dùng cho offline tool."""
    h = hashlib.sha256()
    h.update(salt)
    h.update(master_password.encode("utf-8"))
    return h.digest()


# ------------------------------------------------------------------ #
#  Vault API                                                          #
# ------------------------------------------------------------------ #
DEFAULT_MASTER_EMAIL = "admin@company.com"
DEFAULT_MASTER_PASS  = "admin123"


def build_vault(accounts: Dict[str, List[Dict]],
                master_email: str = DEFAULT_MASTER_EMAIL,
                master_password: str = DEFAULT_MASTER_PASS,
                output_path: str = "vault.bin",
                active_days: int = 30) -> str:
    """Đóng gói accounts (dict service -> list cookie) thành vault.bin.
    Admin goi ham nay 1 lan de tao file ship cho user.

    accounts = {
        "flow":    [{"id": "f01", "label": "Flow 1", "cookies": [...]}, ...],
        "chatgpt": [...],
        "gemini":  [...],
    }
    active_days: so ngay acc song sau khi user unlock (mac dinh 30).
                expires_at = unlocked_at + active_days*86400.
                User app check expires_at -> neu qua han -> bao 'het han'.
    """
    now = time.time()
    expires_at = now + active_days * 86400
    # Gan expires_at cho tung acc neu chua co
    enriched = {}
    for svc, accs in accounts.items():
        enriched[svc] = []
        for acc in accs:
            acc2 = dict(acc)
            if "expires_at" not in acc2:
                acc2["expires_at"] = expires_at
            if "active_days" not in acc2:
                acc2["active_days"] = active_days
            enriched[svc].append(acc2)
    payload = {
        "version": 1,
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "active_days_default": active_days,
        "master_email": master_email,
        "accounts": enriched,
    }
    pt = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    ct = _aes_encrypt(pt, key)
    blob = salt + ct
    with open(output_path, "wb") as f:
        f.write(blob)
    return output_path


def unlock_vault(vault_path: str, master_email: str, master_password: str,
                 check_email: bool = True) -> Dict:
    """User goi ham nay khi dang nhap. Tra ve dict (hoac raise PermissionError).

    check_email: Neu False (vd khi unlock qua server), bo qua check master_email
                 de user co the nhap email/pass rieng ma van giai ma duoc vault.
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Khong tim thay vault: {vault_path}")
    with open(vault_path, "rb") as f:
        blob = f.read()
    if len(blob) < 32:
        raise ValueError("Vault file khong hop le (qua ngan)")
    salt = blob[:16]
    ct = blob[16:]
    key = _derive_key(master_password, salt)
    try:
        pt = _aes_decrypt(ct, key)
    except Exception as e:
        raise PermissionError(f"Sai mat khau hoac vault bi hong: {e}")
    payload = json.loads(pt.decode("utf-8"))
    if check_email and payload.get("master_email", "").lower() != master_email.lower():
        raise PermissionError("Email khong khop. Lien he admin de cap email/pass dung.")
    return payload


def list_accounts(payload: Dict) -> Dict[str, int]:
    """Tra ve so acc moi service trong vault."""
    return {svc: len(accs) for svc, accs in payload.get("accounts", {}).items()}


def is_acc_alive(acc: Dict, now: Optional[float] = None) -> bool:
    """Check acc con song (cookie still live AND now < expires_at)."""
    if now is None:
        now = time.time()
    exp = acc.get("expires_at", 0)
    return bool(exp) and now < exp


def acc_remaining_days(acc: Dict, now: Optional[float] = None) -> int:
    """So ngay con lai (lam tron len)."""
    if now is None:
        now = time.time()
    exp = acc.get("expires_at", 0)
    if not exp or now >= exp:
        return 0
    return max(0, int((exp - now) / 86400) + 1)


def filter_alive(payload: Dict, now: Optional[float] = None) -> Dict:
    """Tra ve payload chi chua acc con song (user app se goi de loai dead)."""
    if now is None:
        now = time.time()
    out = dict(payload)
    out["accounts"] = {}
    n_total = 0
    n_alive = 0
    for svc, accs in payload.get("accounts", {}).items():
        alive = [a for a in accs if is_acc_alive(a, now)]
        out["accounts"][svc] = alive
        n_total += len(accs)
        n_alive += len(alive)
    out["_stats"] = {"total": n_total, "alive": n_alive,
                      "checked_at": now}
    return out


# ------------------------------------------------------------------ #
#  Admin helper: build tu folder cookies/ hien co                     #
# ------------------------------------------------------------------ #
def build_from_cookies_dir(cookies_dir: str,
                            master_email: str = DEFAULT_MASTER_EMAIL,
                            master_password: str = DEFAULT_MASTER_PASS,
                            output_path: str = "vault.bin",
                            max_per_service: int = 8) -> str:
    """Quet cookies/<site>_acc_*.json, dong goi thanh vault.

    Vi du: cookies/flow_acc_01.json, flow_acc_02.json, ...
          -> vault.accounts['flow'] = [{id, label, cookies: [...]}, ...]
    """
    SITE_MAP = {
        "flow":    "flow",
        "chatgpt": "chatgpt",
        "gemini":  "gemini",
    }
    accounts: Dict[str, List[Dict]] = {svc: [] for svc in SITE_MAP}
    for fname in sorted(os.listdir(cookies_dir)):
        if not fname.endswith(".json"):
            continue
        # Parse "flow_acc_01.json" -> site=flow, num=01
        m = None
        for site in SITE_MAP:
            if fname.startswith(site + "_acc_"):
                num = fname[len(site) + 5:-5]
                m = (site, num)
                break
        if not m:
            continue
        site, num = m
        if len(accounts[site]) >= max_per_service:
            continue
        fpath = os.path.join(cookies_dir, fname)
        with open(fpath, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception:
                continue
        if not isinstance(data, list):
            continue
        accounts[site].append({
            "id": f"{site[0]}{num}",
            "label": f"{site.capitalize()} Acc {num}",
            "cookies": data,
        })

    return build_vault(accounts, master_email, master_password, output_path)


# ------------------------------------------------------------------ #
#  CLI                                                               #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import sys
    BASE = os.path.dirname(os.path.abspath(__file__))
    cookies_dir = os.path.join(BASE, "cookies")
    out = os.path.join(BASE, "vault.bin")
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        # Build tu cookies/ hien co
        path = build_from_cookies_dir(cookies_dir, output_path=out)
        info = unlock_vault(path, DEFAULT_MASTER_EMAIL, DEFAULT_MASTER_PASS)
        n = list_accounts(info)
        size = os.path.getsize(path)
        print(f"Vault: {path}  ({size} bytes)")
        print(f"  master: {DEFAULT_MASTER_EMAIL} / {DEFAULT_MASTER_PASS}")
        print(f"  accounts: {n}")
    elif len(sys.argv) >= 2 and sys.argv[1] == "unlock":
        # Test unlock
        info = unlock_vault(out, DEFAULT_MASTER_EMAIL, DEFAULT_MASTER_PASS)
        n = list_accounts(info)
        print(f"OK: master={info['master_email']}, accounts={n}")
    else:
        print("Usage:")
        print("  python cookie_vault.py build    # Build vault.bin tu folder cookies/")
        print("  python cookie_vault.py unlock   # Test unlock vault.bin")
