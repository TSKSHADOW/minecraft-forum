"""
MCWorld Forum - HTTP Server v3
python localhost.py -> http://localhost:8000
"""

import http.server
import socketserver
import json
import os
import uuid
import hashlib
import time
import base64
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", 8000))
DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DIR, "db.json")
UPLOADS_DIR = os.path.join(DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

# Аккаунты с постоянной ролью owner
OWNER_ACCOUNTS = {"Admin", "k1prs"}

# --- Database ---
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return default_db()

def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def default_db():
    db = {
        "users": {},
        "posts": [],
        "sessions": {}
    }
    # Admin account
    db["users"]["Admin"] = {
        "password": hash_pw("ForumMCAdmin"),
        "role": "owner",
        "nickname": "Admin",
        "avatar": "",
        "registered": time.time(),
        "ban_until": 0,
        "mute_until": 0
    }
    # k1prs account
    db["users"]["k1prs"] = {
        "password": hash_pw("zV3wkR7bjH4iaN0tsS6cnB9ob"),
        "role": "owner",
        "nickname": "k1prs",
        "avatar": "",
        "registered": time.time(),
        "ban_until": 0,
        "mute_until": 0
    }
    save_db(db)
    return db

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

DB = load_db()

# Ensure Admin exists with owner role
if "Admin" not in DB["users"]:
    DB["users"]["Admin"] = {
        "password": hash_pw("ForumMCAdmin"),
        "role": "owner", "nickname": "Admin", "avatar": "",
        "registered": time.time(), "ban_until": 0, "mute_until": 0
    }
    save_db(DB)
else:
    # Force owner role for Admin
    DB["users"]["Admin"]["role"] = "owner"
    save_db(DB)

# Ensure k1prs exists with owner role
if "k1prs" not in DB["users"]:
    DB["users"]["k1prs"] = {
        "password": hash_pw("zV3wkR7bjH4iaN0tsS6cnB9ob"),
        "role": "owner", "nickname": "k1prs", "avatar": "",
        "registered": time.time(), "ban_until": 0, "mute_until": 0
    }
    save_db(DB)
else:
    DB["users"]["k1prs"]["role"] = "owner"
    save_db(DB)

if "sessions" not in DB:
    DB["sessions"] = {}

# Migrate old users
changed = False
for uname, udata in DB["users"].items():
    for field, default in [("nickname", uname), ("avatar", ""), ("ban_until", 0), ("mute_until", 0), ("registered", time.time())]:
        if field not in udata:
            udata[field] = default
            changed = True
    # Force owner role for owner accounts
    if uname in OWNER_ACCOUNTS and udata.get("role") != "owner":
        udata["role"] = "owner"
        changed = True
if changed:
    save_db(DB)


def is_banned(username):
    u = DB["users"].get(username, {})
    return u.get("ban_until", 0) > time.time()

def is_muted(username):
    u = DB["users"].get(username, {})
    return u.get("mute_until", 0) > time.time()

def get_role_level(role):
    """Числовой уровень роли для сравнения"""
    levels = {"player": 0, "vip": 1, "moder": 2, "admin": 3, "coowner": 4, "owner": 5}
    return levels.get(role, 0)

def can_manage(caller_role, target_role):
    """Может ли caller управлять target"""
    return get_role_level(caller_role) > get_role_level(target_role)


class ForumHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/posts":
            self.send_json(200, {"posts": DB["posts"]})

        elif parsed.path == "/api/users":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if not session or caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Доступ запрещён"})
                return
            users_list = []
            for uname, udata in DB["users"].items():
                users_list.append({
                    "username": uname,
                    "role": udata["role"],
                    "nickname": udata.get("nickname", uname),
                    "avatar": udata.get("avatar", ""),
                    "ban_until": udata.get("ban_until", 0),
                    "mute_until": udata.get("mute_until", 0)
                })
            self.send_json(200, {"users": users_list})

        elif parsed.path == "/api/me":
            session = self.get_session()
            if session and session in DB["users"]:
                u = DB["users"][session]
                # Always return owner role for owner accounts
                role = "owner" if session in OWNER_ACCOUNTS else u["role"]
                self.send_json(200, {
                    "username": session,
                    "role": role,
                    "nickname": u.get("nickname", session),
                    "avatar": u.get("avatar", ""),
                    "ban_until": u.get("ban_until", 0),
                    "mute_until": u.get("mute_until", 0)
                })
            else:
                self.send_json(200, {"username": None})

        elif parsed.path.startswith("/api/profile/"):
            username = parsed.path.split("/api/profile/")[1]
            if username in DB["users"]:
                u = DB["users"][username]
                self.send_json(200, {
                    "username": username,
                    "role": u["role"],
                    "nickname": u.get("nickname", username),
                    "avatar": u.get("avatar", ""),
                    "registered": u.get("registered", 0),
                    "ban_until": u.get("ban_until", 0),
                    "mute_until": u.get("mute_until", 0)
                })
            else:
                self.send_json(404, {"error": "Пользователь не найден"})
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self.read_body()

        if parsed.path == "/api/register":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not username or not password:
                self.send_json(400, {"error": "Заполни все поля!"}); return
            if len(username) < 3:
                self.send_json(400, {"error": "Логин слишком короткий (мин. 3)"}); return
            if len(password) < 4:
                self.send_json(400, {"error": "Пароль слишком короткий (мин. 4)"}); return
            if username in DB["users"]:
                self.send_json(400, {"error": "Пользователь уже существует"}); return
            role = "owner" if username in OWNER_ACCOUNTS else "player"
            DB["users"][username] = {
                "password": hash_pw(password),
                "role": role,
                "nickname": username,
                "avatar": "",
                "registered": time.time(),
                "ban_until": 0,
                "mute_until": 0
            }
            save_db(DB)
            token = str(uuid.uuid4())
            DB["sessions"][token] = username
            self.send_json_with_cookie(200, {"ok": True, "username": username, "role": role}, token)

        elif parsed.path == "/api/login":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            user = DB["users"].get(username)
            if not user or user["password"] != hash_pw(password):
                self.send_json(400, {"error": "Неверный логин или пароль"}); return
            if is_banned(username):
                remaining = int(user.get("ban_until", 0) - time.time())
                hrs = remaining // 3600
                mins = (remaining % 3600) // 60
                self.send_json(403, {"error": f"Вы забанены! Осталось: {hrs}ч {mins}мин"}); return
            # Always ensure owner role for owner accounts
            role = "owner" if username in OWNER_ACCOUNTS else user["role"]
            if username in OWNER_ACCOUNTS and user["role"] != "owner":
                DB["users"][username]["role"] = "owner"
                save_db(DB)
            token = str(uuid.uuid4())
            DB["sessions"][token] = username
            self.send_json_with_cookie(200, {"ok": True, "username": username, "role": role}, token)

        elif parsed.path == "/api/logout":
            cookie = self.get_cookie("session")
            if cookie and cookie in DB["sessions"]:
                del DB["sessions"][cookie]
            self.send_json_with_cookie(200, {"ok": True}, "deleted")

        elif parsed.path == "/api/posts":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "Вы не авторизованы"}); return
            if is_muted(session):
                remaining = int(DB["users"][session].get("mute_until", 0) - time.time())
                mins = remaining // 60
                self.send_json(403, {"error": f"Вы замьючены! Осталось: {mins} мин"}); return
            title = body.get("title", "").strip()
            content = body.get("content", "").strip()
            if not title or not content:
                self.send_json(400, {"error": "Заполни все поля!"}); return
            media_file = ""
            media_type = ""
            media_data = body.get("media", "")
            media_name = body.get("media_name", "")
            if media_data and media_name:
                ext = media_name.rsplit(".", 1)[-1].lower() if "." in media_name else "bin"
                fname = str(uuid.uuid4())[:8] + "." + ext
                fpath = os.path.join(UPLOADS_DIR, fname)
                try:
                    if "," in media_data:
                        media_data = media_data.split(",", 1)[1]
                    file_bytes = base64.b64decode(media_data)
                    with open(fpath, "wb") as f:
                        f.write(file_bytes)
                    media_file = "uploads/" + fname
                    if ext in ("jpg", "jpeg", "png", "gif", "bmp", "webp"):
                        media_type = "image"
                    elif ext in ("mp4", "webm", "ogg", "avi", "mov"):
                        media_type = "video"
                    else:
                        media_type = "file"
                except:
                    pass
            user = DB["users"][session]
            role = "owner" if session in OWNER_ACCOUNTS else user["role"]
            post = {
                "id": str(uuid.uuid4())[:8],
                "author": session,
                "role": role,
                "nickname": user.get("nickname", session),
                "avatar": user.get("avatar", ""),
                "title": title,
                "content": content,
                "media": media_file,
                "media_type": media_type,
                "time": time.time(),
                "replies": []
            }
            DB["posts"].insert(0, post)
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/reply":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "Вы не авторизованы"}); return
            if is_muted(session):
                self.send_json(403, {"error": "Вы замьючены!"}); return
            post_id = body.get("post_id", "")
            content = body.get("content", "").strip()
            if not content:
                self.send_json(400, {"error": "Пустой ответ"}); return
            user = DB["users"][session]
            role = "owner" if session in OWNER_ACCOUNTS else user["role"]
            for post in DB["posts"]:
                if post["id"] == post_id:
                    post["replies"].append({
                        "author": session,
                        "role": role,
                        "nickname": user.get("nickname", session),
                        "avatar": user.get("avatar", ""),
                        "content": content,
                        "time": time.time()
                    })
                    save_db(DB)
                    self.send_json(200, {"ok": True})
                    return
            self.send_json(404, {"error": "Тема не найдена"})

        elif parsed.path == "/api/admin/role":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            # Owner accounts always get owner privileges
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            target = body.get("username", "")
            new_role = body.get("role", "")
            valid_roles = ["player", "vip", "moder", "admin", "coowner", "owner"]
            if new_role not in valid_roles:
                self.send_json(400, {"error": "Неверная роль"}); return
            if target not in DB["users"]:
                self.send_json(404, {"error": "Пользователь не найден"}); return
            # Only owner can assign coowner/owner
            if new_role in ("coowner", "owner") and caller_role != "owner":
                self.send_json(403, {"error": "Только Owner может выдавать эту роль"}); return
            # Can't demote owner accounts
            if target in OWNER_ACCOUNTS:
                self.send_json(403, {"error": "Нельзя изменить роль Owner-аккаунта"}); return
            target_role = DB["users"][target]["role"]
            if not can_manage(caller_role, target_role) and caller_role != "owner":
                self.send_json(403, {"error": "Нельзя управлять пользователем с такой же или выше ролью"}); return
            DB["users"][target]["role"] = new_role
            for post in DB["posts"]:
                if post["author"] == target:
                    post["role"] = new_role
                for reply in post.get("replies", []):
                    if reply["author"] == target:
                        reply["role"] = new_role
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/ban":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            target = body.get("username", "")
            duration = int(body.get("duration", 3600))
            if target not in DB["users"]:
                self.send_json(404, {"error": "Пользователь не найден"}); return
            if target in OWNER_ACCOUNTS:
                self.send_json(403, {"error": "Нельзя забанить Owner-аккаунт"}); return
            target_role = DB["users"][target]["role"]
            if not can_manage(caller_role, target_role):
                self.send_json(403, {"error": "Нельзя банить пользователя с такой же или выше ролью"}); return
            if caller_role == "moder" and duration > 86400:
                duration = 86400
            DB["users"][target]["ban_until"] = time.time() + duration
            # Снять роль moder/admin при бане
            if target_role in ("moder", "admin"):
                DB["users"][target]["role"] = "player"
                for post in DB["posts"]:
                    if post["author"] == target:
                        post["role"] = "player"
                    for reply in post.get("replies", []):
                        if reply["author"] == target:
                            reply["role"] = "player"
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/unban":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            target = body.get("username", "")
            if target in DB["users"]:
                DB["users"][target]["ban_until"] = 0
                save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/mute":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            target = body.get("username", "")
            duration = int(body.get("duration", 3600))
            if target not in DB["users"]:
                self.send_json(404, {"error": "Пользователь не найден"}); return
            if target in OWNER_ACCOUNTS:
                self.send_json(403, {"error": "Нельзя замьютить Owner-аккаунт"}); return
            target_role = DB["users"][target]["role"]
            if not can_manage(caller_role, target_role):
                self.send_json(403, {"error": "Нельзя мьютить пользователя с такой же или выше ролью"}); return
            if caller_role == "moder" and duration > 86400:
                duration = 86400
            DB["users"][target]["mute_until"] = time.time() + duration
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/unmute":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            target = body.get("username", "")
            if target in DB["users"]:
                DB["users"][target]["mute_until"] = 0
                save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/delete_post":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            if caller_role not in ("admin", "moder", "owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            post_id = body.get("post_id", "")
            DB["posts"] = [p for p in DB["posts"] if p["id"] != post_id]
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/delete_user":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if session in OWNER_ACCOUNTS:
                caller_role = "owner"
            target = body.get("username", "")
            # Owner/coowner can delete others; any user can delete themselves
            if session != target and caller_role not in ("owner", "coowner"):
                self.send_json(403, {"error": "Нет прав"}); return
            if target not in DB["users"]:
                self.send_json(404, {"error": "Пользователь не найден"}); return
            if target in OWNER_ACCOUNTS and session != target:
                self.send_json(403, {"error": "Нельзя удалить Owner-аккаунт"}); return
            # Delete user posts and replies
            DB["posts"] = [p for p in DB["posts"] if p["author"] != target]
            for post in DB["posts"]:
                post["replies"] = [r for r in post.get("replies", []) if r["author"] != target]
            # Delete sessions
            to_delete = [tok for tok, uname in DB["sessions"].items() if uname == target]
            for tok in to_delete:
                del DB["sessions"][tok]
            del DB["users"][target]
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/profile/avatar":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "Вы не авторизованы"}); return
            avatar_data = body.get("avatar", "")
            if avatar_data:
                try:
                    raw = avatar_data.split(",", 1)[1] if "," in avatar_data else avatar_data
                    file_bytes = base64.b64decode(raw)
                    fname = "avatar_" + session + ".png"
                    fpath = os.path.join(UPLOADS_DIR, fname)
                    with open(fpath, "wb") as f:
                        f.write(file_bytes)
                    DB["users"][session]["avatar"] = "uploads/" + fname
                    save_db(DB)
                    self.send_json(200, {"ok": True, "avatar": "uploads/" + fname})
                except Exception as e:
                    self.send_json(400, {"error": "Ошибка загрузки"})
            else:
                self.send_json(400, {"error": "Нет данных"})

        elif parsed.path == "/api/profile/nickname":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "Вы не авторизованы"}); return
            nickname = body.get("nickname", "").strip()
            if not nickname or len(nickname) < 2:
                self.send_json(400, {"error": "Ник слишком короткий"}); return
            if len(nickname) > 20:
                self.send_json(400, {"error": "Ник слишком длинный (макс. 20)"}); return
            DB["users"][session]["nickname"] = nickname
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/profile/password":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "Вы не авторизованы"}); return
            old_pw = body.get("old_password", "")
            new_pw = body.get("new_password", "")
            if DB["users"][session]["password"] != hash_pw(old_pw):
                self.send_json(400, {"error": "Неверный старый пароль"}); return
            if len(new_pw) < 4:
                self.send_json(400, {"error": "Новый пароль слишком короткий"}); return
            DB["users"][session]["password"] = hash_pw(new_pw)
            save_db(DB)
            self.send_json(200, {"ok": True})

        else:
            self.send_json(404, {"error": "Не найдено"})

    def get_session(self):
        cookie = self.get_cookie("session")
        if cookie and cookie in DB["sessions"]:
            username = DB["sessions"][cookie]
            if username in DB["users"]:
                return username
        return None

    def get_cookie(self, name):
        cookies = self.headers.get("Cookie", "")
        for part in cookies.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return None

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except:
            return {}

    def send_json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def send_json_with_cookie(self, code, data, token):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), ForumHandler) as httpd:
        print(f"[*] MCWorld Forum v3 started!")
        print(f"[>] Open: http://localhost:{PORT}")
        print(f"[!] Owner accounts: Admin / k1prs")
        print(f"[!] Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[x] Server stopped.")
