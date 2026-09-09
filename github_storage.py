# -*- coding: utf-8 -*-
"""
GitHub Storage - Luu data vao GitHub repo thay cho o dia local.
Dung khi host tren Render Free (khong co persistent disk).

Moi file se duoc luu nhu 1 file trong repo (vd: data/users.json, data/vaults/email.bin).
Khi ghi -> push len GitHub (auto commit). Khi doc -> pull tu GitHub (cache 5p trong RAM).
"""
import os
import json
import time
import base64
import requests

GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GH_REPO = os.environ.get("GITHUB_REPO", "hoanghaiminh2004-rgb/vault-may-chu")
GH_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
GH_API = "https://api.github.com"

_cache: dict = {}  # path -> (content_str, loaded_at)
_CACHE_TTL = 300  # 5 phut


def _headers():
    return {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vault-server/1.0",
    }


def is_enabled() -> bool:
    return bool(GH_TOKEN)


def read_file(path: str) -> str:
    """Doc file tu GitHub. Tra ve chuoi (decode base64 neu binary). Cache 5p."""
    if not is_enabled():
        raise RuntimeError("GITHUB_TOKEN not set, GitHub storage disabled")
    # Check cache
    if path in _cache:
        content, loaded_at = _cache[path]
        if time.time() - loaded_at < _CACHE_TTL:
            return content
    url = f"{GH_API}/repos/{GH_REPO}/contents/{path}"
    r = requests.get(url, headers=_headers(),
                       params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code == 200:
        d = r.json()
        content = base64.b64decode(d["content"]).decode("utf-8", errors="replace")
        _cache[path] = (content, time.time())
        return content
    elif r.status_code == 404:
        return ""  # File chua ton tai
    else:
        raise RuntimeError(f"GitHub read {path}: {r.status_code} {r.text[:200]}")


def read_bytes(path: str) -> bytes:
    """Doc file binary (vd: vault.bin)."""
    if not is_enabled():
        raise RuntimeError("GITHUB_TOKEN not set, GitHub storage disabled")
    if path in _cache:
        content, loaded_at = _cache[path]
        if time.time() - loaded_at < _CACHE_TTL:
            return content.encode("latin-1") if isinstance(content, str) else content
    url = f"{GH_API}/repos/{GH_REPO}/contents/{path}"
    r = requests.get(url, headers=_headers(),
                       params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code == 200:
        d = r.json()
        raw = base64.b64decode(d["content"])
        _cache[path] = (raw.decode("latin-1"), time.time())
        return raw
    elif r.status_code == 404:
        return b""
    else:
        raise RuntimeError(f"GitHub read {path}: {r.status_code} {r.text[:200]}")


def write_file(path: str, content: str, commit_msg: str = "update"):
    """Ghi string len GitHub (auto get/create sha)."""
    if not is_enabled():
        raise RuntimeError("GITHUB_TOKEN not set, GitHub storage disabled")
    url = f"{GH_API}/repos/{GH_REPO}/contents/{path}"
    # Get current sha neu co
    sha = None
    r = requests.get(url, headers=_headers(),
                       params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code == 200:
        sha = r.json().get("sha")
    # Write
    body = {
        "message": commit_msg,
        "branch": GH_BRANCH,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
    }
    if sha:
        body["sha"] = sha
    r = requests.put(url, headers=_headers(), json=body, timeout=30)
    if r.status_code in (200, 201):
        # Invalidate cache
        _cache.pop(path, None)
        return True
    raise RuntimeError(f"GitHub write {path}: {r.status_code} {r.text[:300]}")


def write_bytes(path: str, content: bytes, commit_msg: str = "update"):
    """Ghi binary len GitHub."""
    if not is_enabled():
        raise RuntimeError("GITHUB_TOKEN not set, GitHub storage disabled")
    url = f"{GH_API}/repos/{GH_REPO}/contents/{path}"
    sha = None
    r = requests.get(url, headers=_headers(),
                       params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code == 200:
        sha = r.json().get("sha")
    body = {
        "message": commit_msg,
        "branch": GH_BRANCH,
        "content": base64.b64encode(content).decode("ascii"),
    }
    if sha:
        body["sha"] = sha
    r = requests.put(url, headers=_headers(), json=body, timeout=30)
    if r.status_code in (200, 201):
        _cache.pop(path, None)
        return True
    raise RuntimeError(f"GitHub write {path}: {r.status_code} {r.text[:300]}")


def delete_file(path: str, commit_msg: str = "delete"):
    """Xoa file tren GitHub."""
    if not is_enabled():
        return False
    url = f"{GH_API}/repos/{GH_REPO}/contents/{path}"
    r = requests.get(url, headers=_headers(),
                       params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code != 200:
        return False
    sha = r.json().get("sha")
    if not sha:
        return False
    r = requests.delete(url, headers=_headers(),
                          json={"message": commit_msg, "branch": GH_BRANCH, "sha": sha},
                          timeout=15)
    _cache.pop(path, None)
    return r.status_code in (200, 204)


def invalidate_cache(path: str = None):
    """Xoa cache (force reload tu GitHub)."""
    if path:
        _cache.pop(path, None)
    else:
        _cache.clear()
