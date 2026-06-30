"""
Dark Tunnel Config Decryptor Bot
Developer: @Rahmatullah_1
Channel: @minarulsensi
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from struct import unpack
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers import modes
except ImportError:
    from cryptography.hazmat.primitives.ciphers import modes

from pyrogram import Client, filters, enums
from pyrogram.types import (
    Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
)
from pyrogram.errors import UserNotParticipant

# ==================== BOT CONFIGURATION ====================
API_ID   = 34808897
API_HASH = "2ab743fe8f005ebea00e9d8c269a1ad3"
BOT_TOKEN = "8949050319:AAHZiBoZrTw3QvkXDjq6QSjhj52JTtbSPRk"

CHANNEL_USERNAME = "minarulsensi"
CHANNEL_URL      = "https://t.me/minarulsensi"
# ===========================================================

OUTER_KEY = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
INNER_KEY = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV        = bytes.fromhex("232e39185523184a5723586242200e05")


# ─── Msgpack reader ─────────────────────────────────────────
class MsgpackReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos  = 0

    def read(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise ValueError("truncated msgpack data")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def read_u8(self)  -> int:  return self.read(1)[0]
    def read_str(self, size: int) -> str: return self.read(size).decode("utf-8")
    def read_map(self, size: int) -> dict: return {self.unpack(): self.unpack() for _ in range(size)}
    def read_array(self, size: int) -> list: return [self.unpack() for _ in range(size)]

    def unpack(self) -> Any:
        code = self.read_u8()
        if code <= 0x7F: return code
        if code >= 0xE0: return code - 0x100
        if 0x80 <= code <= 0x8F: return self.read_map(code & 0x0F)
        if 0x90 <= code <= 0x9F: return self.read_array(code & 0x0F)
        if 0xA0 <= code <= 0xBF: return self.read_str(code & 0x1F)
        if code == 0xC0: return None
        if code == 0xC2: return False
        if code == 0xC3: return True
        if code == 0xC4: return self.read(self.read_u8())
        if code == 0xC5: return self.read(unpack(">H", self.read(2))[0])
        if code == 0xC6: return self.read(unpack(">I", self.read(4))[0])
        if code == 0xCA: return unpack(">f", self.read(4))[0]
        if code == 0xCB: return unpack(">d", self.read(8))[0]
        if code == 0xCC: return self.read_u8()
        if code == 0xCD: return unpack(">H", self.read(2))[0]
        if code == 0xCE: return unpack(">I", self.read(4))[0]
        if code == 0xCF: return unpack(">Q", self.read(8))[0]
        if code == 0xD0: return unpack(">b", self.read(1))[0]
        if code == 0xD1: return unpack(">h", self.read(2))[0]
        if code == 0xD2: return unpack(">i", self.read(4))[0]
        if code == 0xD3: return unpack(">q", self.read(8))[0]
        if code == 0xD9: return self.read_str(self.read_u8())
        if code == 0xDA: return self.read_str(unpack(">H", self.read(2))[0])
        if code == 0xDB: return self.read_str(unpack(">I", self.read(4))[0])
        if code == 0xDC: return self.read_array(unpack(">H", self.read(2))[0])
        if code == 0xDD: return self.read_array(unpack(">I", self.read(4))[0])
        if code == 0xDE: return self.read_map(unpack(">H", self.read(2))[0])
        if code == 0xDF: return self.read_map(unpack(">I", self.read(4))[0])
        raise ValueError(f"unsupported msgpack marker 0x{code:02x}")


def msgpack_unpack(data: bytes) -> Any:
    reader = MsgpackReader(data)
    value  = reader.unpack()
    return value


# ─── Crypto helpers ──────────────────────────────────────────
def b64decode_any(value: str) -> bytes:
    value = value.strip().replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
    value += "=" * ((4 - len(value) % 4) % 4)
    try:   return base64.urlsafe_b64decode(value)
    except: return base64.b64decode(value)

def aes_cfb_decrypt(data: bytes, key: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.CFB(IV)).decryptor().update(data)


# ─── Config processing ───────────────────────────────────────
def parse_dark_content(text: str) -> dict:
    text = text.strip()
    if "darktunnel://" in text:
        text = text.split("darktunnel://", 1)[1].split()[0]
        return json.loads(b64decode_any(text))
    return json.loads(text)

def maybe_parse_text(text: str) -> Any:
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try: return json.loads(stripped)
        except json.JSONDecodeError: pass
    return text

def bytes_for_json(value: bytes) -> Any:
    if len(value) == 96:
        head, tail = value[:64], value[64:]
        try:
            head_text = head.decode("ascii")
            if all(ch in "0123456789abcdefABCDEF" for ch in head_text):
                return {"hash_hex": head_text, "extra_hash_hex": tail.hex(), "length": len(value)}
        except UnicodeDecodeError: pass
    try: return maybe_parse_text(value.decode("utf-8"))
    except UnicodeDecodeError:
        return {"bytes_b64": base64.b64encode(value).decode("ascii"), "bytes_hex": value.hex(), "length": len(value)}

def json_safe(value: Any) -> Any:
    if isinstance(value, dict): return {str(json_safe(k)): json_safe(v) for k, v in value.items()}
    if isinstance(value, list): return [json_safe(item) for item in value]
    if isinstance(value, bytes): return bytes_for_json(value)
    return value

def decrypt_value(value: bytes) -> Any:
    if not value: return ""
    return bytes_for_json(aes_cfb_decrypt(value, INNER_KEY))

def decrypt_inner_fields(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict = {}
        for key, item in value.items():
            key_text = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            if key_text.startswith("Encrypted") and isinstance(item, bytes):
                out[key_text[len("Encrypted"):]] = decrypt_value(item)
            else:
                out[key_text] = decrypt_inner_fields(item)
        return out
    if isinstance(value, list):  return [decrypt_inner_fields(item) for item in value]
    if isinstance(value, bytes): return bytes_for_json(value)
    return value

def to_camel_case(d: Any) -> Any:
    if isinstance(d, dict):
        new_d: dict = {}
        for k, v in d.items():
            if isinstance(k, str) and k:
                if   k == "V2RayConfig":  new_k = "v2rayConfig"
                elif k == "SshConfig":    new_k = "sshConfig"
                elif k == "InjectConfig": new_k = "injectConfig"
                elif k == "DnsttDnsHost": new_k = "dnsttUdpDnsHost"
                elif k == "DnsttDnsPort": new_k = "dnsttUdpDnsPort"
                elif k == "DnsttPubkey":  new_k = "dnsttPublicKey"
                else: new_k = k[0].lower() + k[1:]
                new_d[new_k] = to_camel_case(v)
            else:
                new_d[k] = to_camel_case(v)
        return new_d
    elif isinstance(d, list): return [to_camel_case(i) for i in d]
    return d

def create_unlocked_config(config_dict: dict) -> dict:
    unlocked = json.loads(json.dumps(config_dict))
    decrypted_locked = unlocked.pop("decryptedLockedConfig", {})
    inner_config = decrypted_locked.get("DecryptedInnerConfig")

    if inner_config:
        camel_inner   = to_camel_case(inner_config)
        tunnel_type   = unlocked.get("type", "")
        parts         = tunnel_type.lower().split('_')
        tunnel_config_key = parts[0] + ''.join(p.capitalize() for p in parts[1:]) + "TunnelConfig"

        if tunnel_config_key not in unlocked:
            unlocked[tunnel_config_key] = {}

        for k, v in camel_inner.items():
            if isinstance(v, dict):
                v.pop("isEncrypted", None)
                v.pop("isLocked", None)
                if k == "v2rayConfig" and "config" in v:
                    if tunnel_type == "V2RAY_CUSTOM_CONFIG":
                        if isinstance(v["config"], dict): unlocked[tunnel_config_key]["v2rayCustomConfig"] = json.dumps(v.pop("config"))
                        else: unlocked[tunnel_config_key]["v2rayCustomConfig"] = str(v.pop("config"))
                        v.pop("isInjectModeEnabled", None)
                    else:
                        try:
                            if isinstance(v["config"], str):
                                safe_json = re.sub(r':\s*\$[A-Z0-9_]+', ': true', v["config"])
                                v2_data = json.loads(safe_json)
                            else: v2_data = v["config"]
                            outbounds = v2_data.get("outbounds", [])
                            if outbounds:
                                ob       = outbounds[0]
                                settings = ob.get("settings", {})
                                stream   = ob.get("streamSettings", {})
                                vnext    = settings.get("vnext", [{}])[0]
                                users    = vnext.get("users", [{}])[0]
                                if not vnext and settings.get("servers"):
                                    vnext = settings.get("servers", [{}])[0]
                                    users = vnext
                                v["host"]                  = vnext.get("address", "")
                                v["port"]                  = vnext.get("port", 443)
                                v["uuid"]                  = users.get("id", "") or users.get("password", "")
                                v["serverNameIndication"]  = stream.get("tlsSettings", {}).get("serverName", "")
                                net = stream.get("network", "")
                                if net == "ws":
                                    v["wsPath"]       = stream.get("wsSettings", {}).get("path", "")
                                    v["wsHeaderHost"] = stream.get("wsSettings", {}).get("headers", {}).get("Host", "")
                                elif net == "grpc":
                                    v["grpcServiceName"] = stream.get("grpcSettings", {}).get("serviceName", "")
                        except: pass
                        v.pop("config", None)
                        v.pop("isInjectModeEnabled", None)

                for int_key in ["port", "proxyPort", "dnsttUdpDnsPort"]:
                    if int_key in v:
                        try: v[int_key] = int(v[int_key])
                        except ValueError: pass

                if k in unlocked[tunnel_config_key] and isinstance(unlocked[tunnel_config_key][k], dict):
                    unlocked[tunnel_config_key][k].update(v)
                else:
                    unlocked[tunnel_config_key][k] = v

        if tunnel_type == "SSH_DNSTT":
            inj = unlocked[tunnel_config_key].pop("injectConfig", {})
            if inj:
                unlocked[tunnel_config_key]["dnsttConfig"] = {
                    "udpDnsHost": inj.get("dnsttUdpDnsHost", ""),
                    "serverName": inj.get("dnsttServerName", ""),
                    "publicKey":  inj.get("dnsttPublicKey", "")
                }
                port = inj.get("dnsttUdpDnsPort")
                if port and port not in (53, "53"):
                    unlocked[tunnel_config_key]["dnsttConfig"]["udpDnsPort"] = int(port)

        for k in list(unlocked[tunnel_config_key].keys()):
            val = unlocked[tunnel_config_key][k]
            if isinstance(val, dict):
                for sub_k in [sk for sk, sv in val.items() if sv == ""]:
                    if sub_k != "payload": del val[sub_k]
                if not val:                                                          del unlocked[tunnel_config_key][k]
                elif k == "sshConfig"    and not val.get("host") and not val.get("username"):   del unlocked[tunnel_config_key][k]
                elif k == "injectConfig" and not val.get("proxyHost") and "payload" not in val and not val.get("dnsttServerName"): del unlocked[tunnel_config_key][k]
                elif k == "v2rayConfig"  and not val.get("host")  and not val.get("uuid"):      del unlocked[tunnel_config_key][k]

    return unlocked

def process_dark_config(content: str) -> dict:
    config    = parse_dark_content(content)
    encrypted = config.pop("encryptedLockedConfig", None)
    if encrypted:
        outer_msgpack = aes_cfb_decrypt(b64decode_any(encrypted), OUTER_KEY)
        outer         = msgpack_unpack(outer_msgpack)
        locked_app    = outer.get("LockedAppConfig", {}) if isinstance(outer, dict) else {}
        inner_blob    = outer.get("EncryptedLockedConfig", b"") if isinstance(outer, dict) else b""
        decrypted_inner = None
        if isinstance(inner_blob, bytes) and inner_blob:
            inner_msgpack   = aes_cfb_decrypt(inner_blob, INNER_KEY)
            inner           = msgpack_unpack(inner_msgpack)
            decrypted_inner = decrypt_inner_fields(inner)
        config["decryptedLockedConfig"] = {
            "LockedAppConfig":     json_safe(locked_app),
            "DecryptedInnerConfig": decrypted_inner
        }
    return config


# ─── Telegram helpers ─────────────────────────────────────────
async def check_user_joined(client: Client, user_id: int) -> bool:
    try:
        member = await client.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in [
            enums.ChatMemberStatus.OWNER,
            enums.ChatMemberStatus.ADMINISTRATOR,
            enums.ChatMemberStatus.MEMBER,
        ]
    except UserNotParticipant:
        return False
    except Exception as e:
        print(f"Membership check error: {e}")
        return True   # allow on technical error

def get_force_join_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📢 Join Our Channel", url=CHANNEL_URL)],
        [InlineKeyboardButton("Check Join 🟢",       callback_data="check_join")],
    ])


# ─── Bot setup ────────────────────────────────────────────────
bot = Client(
    "dark_decryptor_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN,
)


# ─── /start handler ──────────────────────────────────────────
@bot.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    if not await check_user_joined(client, message.from_user.id):
        await message.reply_text(
            "╭──────────────────────────────╮\n"
            "│      ⚠️ ACCESS DENIED ⚠️     │\n"
            "├──────────────────────────────┤\n"
            "│ বোটটি ব্যবহার করতে হলে আপনাকে │\n"
            "│ অবশ্যই আমাদের চ্যানেলে জয়েন │\n"
            "│ করতে হবে।                    │\n"
            "├──────────────────────────────┤\n"
            "│ নিচের বাটনে ক্লিক করে জয়েন   │\n"
            "│ করুন এবং Check Join 🟢     │\n"
            "│ বাটনে চাপুন।                 │\n"
            "╰──────────────────────────────╯",
            reply_markup=get_force_join_markup(),
        )
        return

    await message.reply_text(
        "╭──────────────────────────────╮\n"
        "│  👋 𝐖𝐄𝐋𝐂𝐎𝐌𝐄 𝐓𝐎 𝐃𝐀𝐑𝐊 𝐓𝐔𝐍𝐍𝐄𝐋  │\n"
        "│   💎 𝐂𝐎𝐍𝐅𝐈𝐆 𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓 💎 │\n"
        "├──────────────────────────────┤\n"
        "│  ⚡ 𝐒𝐭𝐚𝐭𝐮𝐬    : Unlocking Active│\n"
        "│  🚀 𝐒𝐩𝐞𝐞𝐝    : Ultra Fast      │\n"
        "│  👨‍💻 𝐃𝐞𝐯𝐞𝐥𝐨𝐩𝐞𝐫 : @Rahmatullah_1     │\n"
        "├──────────────────────────────┤\n"
        "│  📂 এখন যেকোনো `dark` কনফিগ │\n"
        "│  ফাইল পাঠান, মুহূর্তেই আনলক   │\n"
        "│  হয়ে যাবে।😁                   │\n"
        "╰──────────────────────────────╯",
        parse_mode=enums.ParseMode.MARKDOWN,
    )


# ─── File handler ─────────────────────────────────────────────
@bot.on_message(filters.document)
async def file_handler(client: Client, message: Message):
    filename = (message.document.file_name or "").lower()
    if ".dark" not in filename:
        return

    if not await check_user_joined(client, message.from_user.id):
        await message.reply_text(
            "╭──────────────────────────────╮\n"
            "│    ❌ JOIN CHANNEL FIRST ❌  │\n"
            "├──────────────────────────────┤\n"
            "│ আমাদের চ্যানেলের মেম্বার না   │\n"
            "│ হলে ফাইল আনলক করা যাবে না।   │\n"
            "├──────────────────────────────┤\n"
            "│ দয়া করে নিচের চ্যানেল বাটনে  │\n"
            "│ ক্লিক করে জয়েন সম্পন্ন করুন। │\n"
            "╰──────────────────────────────╯",
            reply_markup=get_force_join_markup(),
        )
        return

    status_msg = await message.reply_text("⚡ **Processing & Decrypting...**")
    download_path = None
    dark_path = None
    try:
        download_path = await message.download()
        with open(download_path, "r", errors="ignore") as f:
            content = f.read()

        result        = process_dark_config(content)
        base_filename = re.split(r'\.dark', message.document.file_name, flags=re.IGNORECASE)[0]
        dark_path     = f"{base_filename}_unlocked.dark"

        unlocked_json = create_unlocked_config(result)
        unlocked_text = json.dumps(unlocked_json, separators=(',', ':'))
        b64_encoded   = base64.b64encode(unlocked_text.encode("utf-8")).decode("utf-8")

        with open(dark_path, "w", encoding="utf-8") as f:
            f.write(f"darktunnel://{b64_encoded}")

        await status_msg.edit_text("📤 **Sending Unlocked File...**")
        await message.reply_document(
            document=dark_path,
            caption="┠─━━ 🔓 UNLOCK DONE ━━─┨",
        )
        await status_msg.delete()

    except Exception as e:
        await status_msg.edit_text(f"❌ **Error:** {str(e)}")
    finally:
        if download_path and os.path.exists(download_path): os.remove(download_path)
        if dark_path     and os.path.exists(dark_path):     os.remove(dark_path)


# ─── Check Join callback ──────────────────────────────────────
@bot.on_callback_query(filters.regex("check_join"))
async def callback_check_join(client: Client, callback_query: CallbackQuery):
    if await check_user_joined(client, callback_query.from_user.id):
        await callback_query.answer("Success! You have joined. 🎉", show_alert=True)
        await callback_query.message.edit_text(
            "╭──────────────────────────────╮\n"
            "│     ✅ JOINED SUCCESS 🎉     │\n"
            "├──────────────────────────────┤\n"
            "│ ধন্যবাদ আমাদের সাথে থাকার জন্য│\n"
            "│                              │\n"
            "│ এখন আপনার কাঙ্ক্ষিত `.dark`   │\n"
            "│ ফাইলটি বোটে সেন্ড করুন।       │\n"
            "╰──────────────────────────────╯"
        )
    else:
        await callback_query.answer(
            "❌ আপনি এখনো জয়েন করেননি! দয়া করে জয়েন করুন।",
            show_alert=True,
        )


if __name__ == "__main__":
    print("🤖 Dark Tunnel Decryptor Bot starting...")
    bot.run()
