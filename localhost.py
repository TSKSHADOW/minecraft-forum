"""
MiniClaft Forum - HTTP Server v2
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
    admin_hash = hash_pw("ForumMCAdmin")
    db = {
        "users": {
            "Admin": {
                "password": admin_hash,
                "role": "admin",
                "nickname": "Admin",
                "avatar": "",
                "registered": time.time(),
                "ban_until": 0,
                "mute_until": 0
            }
        },
        "posts": [],
        "sessions": {}
    }
    save_db(db)
    return db

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

DB = load_db()
if "Admin" not in DB["users"]:
    DB["users"]["Admin"] = {
        "password": hash_pw("ForumMCAdmin"),
        "role": "admin", "nickname": "Admin", "avatar": "",
        "registered": time.time(), "ban_until": 0, "mute_until": 0
    }
    save_db(DB)
if "sessions" not in DB:
    DB["sessions"] = {}
# Migrate old users
for uname, udata in DB["users"].items():
    changed = False
    for field, default in [("nickname", uname), ("avatar", ""), ("ban_until", 0), ("mute_until", 0)]:
        if field not in udata:
            udata[field] = default
            changed = True
    if changed:
        save_db(DB)


def is_banned(username):
    u = DB["users"].get(username, {})
    return u.get("ban_until", 0) > time.time()

def is_muted(username):
    u = DB["users"].get(username, {})
    return u.get("mute_until", 0) > time.time()


class ForumHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/posts":
            self.send_json(200, {"posts": DB["posts"]})
        elif parsed.path == "/api/users":
            session = self.get_session()
            if not session or DB["users"].get(session, {}).get("role") not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0414\u043e\u0441\u0442\u0443\u043f \u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d"})
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
                self.send_json(200, {
                    "username": session,
                    "role": u["role"],
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
                self.send_json(404, {"error": "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d"})
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self.read_body()

        if parsed.path == "/api/register":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not username or not password:
                self.send_json(400, {"error": "\u0417\u0430\u043f\u043e\u043b\u043d\u0438 \u0432\u0441\u0435 \u043f\u043e\u043b\u044f!"})
                return
            if len(username) < 3:
                self.send_json(400, {"error": "\u041b\u043e\u0433\u0438\u043d \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043a\u043e\u0440\u043e\u0442\u043a\u0438\u0439 (\u043c\u0438\u043d. 3)"})
                return
            if len(password) < 4:
                self.send_json(400, {"error": "\u041f\u0430\u0440\u043e\u043b\u044c \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043a\u043e\u0440\u043e\u0442\u043a\u0438\u0439 (\u043c\u0438\u043d. 4)"})
                return
            if username in DB["users"]:
                self.send_json(400, {"error": "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u0443\u0436\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442"})
                return
            DB["users"][username] = {
                "password": hash_pw(password),
                "role": "player",
                "nickname": username,
                "avatar": "",
                "registered": time.time(),
                "ban_until": 0,
                "mute_until": 0
            }
            save_db(DB)
            token = str(uuid.uuid4())
            DB["sessions"][token] = username
            self.send_json_with_cookie(200, {"ok": True, "username": username, "role": "player"}, token)

        elif parsed.path == "/api/login":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            user = DB["users"].get(username)
            if not user or user["password"] != hash_pw(password):
                self.send_json(400, {"error": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043b\u043e\u0433\u0438\u043d \u0438\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c"})
                return
            if is_banned(username):
                remaining = int(user.get("ban_until", 0) - time.time())
                hrs = remaining // 3600
                mins = (remaining % 3600) // 60
                self.send_json(403, {"error": f"\u0412\u044b \u0437\u0430\u0431\u0430\u043d\u0435\u043d\u044b! \u041e\u0441\u0442\u0430\u043b\u043e\u0441\u044c: {hrs}\u0447 {mins}\u043c\u0438\u043d"})
                return
            token = str(uuid.uuid4())
            DB["sessions"][token] = username
            self.send_json_with_cookie(200, {
                "ok": True, "username": username, "role": user["role"]
            }, token)

        elif parsed.path == "/api/logout":
            cookie = self.get_cookie("session")
            if cookie and cookie in DB["sessions"]:
                del DB["sessions"][cookie]
            self.send_json_with_cookie(200, {"ok": True}, "deleted")

        elif parsed.path == "/api/posts":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "\u0412\u044b \u043d\u0435 \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d\u044b"})
                return
            if is_muted(session):
                remaining = int(DB["users"][session].get("mute_until", 0) - time.time())
                mins = remaining // 60
                self.send_json(403, {"error": f"\u0412\u044b \u0437\u0430\u043c\u044c\u044e\u0447\u0435\u043d\u044b! \u041e\u0441\u0442\u0430\u043b\u043e\u0441\u044c: {mins} \u043c\u0438\u043d"})
                return
            title = body.get("title", "").strip()
            content = body.get("content", "").strip()
            if not title or not content:
                self.send_json(400, {"error": "\u0417\u0430\u043f\u043e\u043b\u043d\u0438 \u0432\u0441\u0435 \u043f\u043e\u043b\u044f!"})
                return
            # Handle media
            media_file = ""
            media_type = ""
            media_data = body.get("media", "")
            media_name = body.get("media_name", "")
            if media_data and media_name:
                ext = media_name.rsplit(".", 1)[-1].lower() if "." in media_name else "bin"
                fname = str(uuid.uuid4())[:8] + "." + ext
                fpath = os.path.join(UPLOADS_DIR, fname)
                try:
                    # Remove data URI prefix if present
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
            post = {
                "id": str(uuid.uuid4())[:8],
                "author": session,
                "role": user["role"],
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
                self.send_json(403, {"error": "\u0412\u044b \u043d\u0435 \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d\u044b"})
                return
            if is_muted(session):
                self.send_json(403, {"error": "\u0412\u044b \u0437\u0430\u043c\u044c\u044e\u0447\u0435\u043d\u044b!"})
                return
            post_id = body.get("post_id", "")
            content = body.get("content", "").strip()
            if not content:
                self.send_json(400, {"error": "\u041f\u0443\u0441\u0442\u043e\u0439 \u043e\u0442\u0432\u0435\u0442"})
                return
            user = DB["users"][session]
            for post in DB["posts"]:
                if post["id"] == post_id:
                    post["replies"].append({
                        "author": session,
                        "role": user["role"],
                        "nickname": user.get("nickname", session),
                        "avatar": user.get("avatar", ""),
                        "content": content,
                        "time": time.time()
                    })
                    save_db(DB)
                    self.send_json(200, {"ok": True})
                    return
            self.send_json(404, {"error": "\u0422\u0435\u043c\u0430 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u0430"})

        elif parsed.path == "/api/admin/role":
            session = self.get_session()
            if not session or DB["users"].get(session, {}).get("role") != "admin":
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430"})
                return
            target = body.get("username", "")
            new_role = body.get("role", "")
            if new_role not in ("player", "vip", "moder", "admin"):
                self.send_json(400, {"error": "\u041d\u0435\u0432\u0435\u0440\u043d\u0430\u044f \u0440\u043e\u043b\u044c"})
                return
            if target not in DB["users"]:
                self.send_json(404, {"error": "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d"})
                return
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
            if caller_role not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            target = body.get("username", "")
            duration = int(body.get("duration", 3600))
            if target not in DB["users"]:
                self.send_json(404, {"error": "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d"})
                return
            target_role = DB["users"][target]["role"]
            if target_role in ("admin", "moder") and caller_role != "admin":
                self.send_json(403, {"error": "\u041d\u0435\u043b\u044c\u0437\u044f \u0431\u0430\u043d\u0438\u0442\u044c \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            if caller_role == "moder" and duration > 86400:
                duration = 86400
            DB["users"][target]["ban_until"] = time.time() + duration
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/unban":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if caller_role not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            target = body.get("username", "")
            if target in DB["users"]:
                DB["users"][target]["ban_until"] = 0
                save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/mute":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if caller_role not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            target = body.get("username", "")
            duration = int(body.get("duration", 3600))
            if target not in DB["users"]:
                self.send_json(404, {"error": "\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d"})
                return
            target_role = DB["users"][target]["role"]
            if target_role in ("admin", "moder") and caller_role != "admin":
                self.send_json(403, {"error": "\u041d\u0435\u043b\u044c\u0437\u044f \u043c\u044c\u044e\u0442\u0438\u0442\u044c \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            if caller_role == "moder" and duration > 86400:
                duration = 86400
            DB["users"][target]["mute_until"] = time.time() + duration
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/unmute":
            session = self.get_session()
            caller_role = DB["users"].get(session, {}).get("role", "")
            if caller_role not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            target = body.get("username", "")
            if target in DB["users"]:
                DB["users"][target]["mute_until"] = 0
                save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/admin/delete_post":
            session = self.get_session()
            user_role = DB["users"].get(session, {}).get("role", "")
            if user_role not in ("admin", "moder"):
                self.send_json(403, {"error": "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0430\u0434\u043c\u0438\u043d\u0430/\u043c\u043e\u0434\u0435\u0440\u0430"})
                return
            post_id = body.get("post_id", "")
            DB["posts"] = [p for p in DB["posts"] if p["id"] != post_id]
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/profile/avatar":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "\u0412\u044b \u043d\u0435 \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d\u044b"})
                return
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
                    self.send_json(400, {"error": "\u041e\u0448\u0438\u0431\u043a\u0430 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0438"})
            else:
                self.send_json(400, {"error": "\u041d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445"})

        elif parsed.path == "/api/profile/nickname":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "\u0412\u044b \u043d\u0435 \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d\u044b"})
                return
            nickname = body.get("nickname", "").strip()
            if not nickname or len(nickname) < 2:
                self.send_json(400, {"error": "\u041d\u0438\u043a \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043a\u043e\u0440\u043e\u0442\u043a\u0438\u0439"})
                return
            if len(nickname) > 20:
                self.send_json(400, {"error": "\u041d\u0438\u043a \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u0434\u043b\u0438\u043d\u043d\u044b\u0439 (\u043c\u0430\u043a\u0441. 20)"})
                return
            DB["users"][session]["nickname"] = nickname
            save_db(DB)
            self.send_json(200, {"ok": True})

        elif parsed.path == "/api/profile/password":
            session = self.get_session()
            if not session:
                self.send_json(403, {"error": "\u0412\u044b \u043d\u0435 \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d\u044b"})
                return
            old_pw = body.get("old_password", "")
            new_pw = body.get("new_password", "")
            if DB["users"][session]["password"] != hash_pw(old_pw):
                self.send_json(400, {"error": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u0441\u0442\u0430\u0440\u044b\u0439 \u043f\u0430\u0440\u043e\u043b\u044c"})
                return
            if len(new_pw) < 4:
                self.send_json(400, {"error": "\u041d\u043e\u0432\u044b\u0439 \u043f\u0430\u0440\u043e\u043b\u044c \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043a\u043e\u0440\u043e\u0442\u043a\u0438\u0439"})
                return
            DB["users"][session]["password"] = hash_pw(new_pw)
            save_db(DB)
            self.send_json(200, {"ok": True})

        else:
            self.send_json(404, {"error": "\u041d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e"})

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
        print(f"[*] MiniClaft Forum v2 started!")
        print(f"[>] Open: http://localhost:{PORT}")
        print(f"[!] Admin: Admin / ForumMCAdmin")
        print(f"[!] Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[x] Server stopped.")
