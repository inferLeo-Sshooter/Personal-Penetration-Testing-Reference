
---

## Flask

### How Flask Sessions Work
Flask stores session data **client-side inside the cookie** — not on the server. The cookie has three dot-separated parts:
```
PAYLOAD.TIMESTAMP.SIGNATURE
```
- The payload is base64 + zlib compressed JSON — **readable without the secret key**
- The signature is HMAC signed with `SECRET_KEY` — prevents tampering
- `HttpOnly: false` (common misconfiguration) means JavaScript can steal it via XSS

### Decoding a Flask Cookie
```bash
flask-unsign --decode --cookie 'COOKIE_VALUE'
```
Or manually (no tools needed):
```bash
echo "PAYLOAD_PART" | python3 -c "
import sys, base64, zlib
data = sys.stdin.read().strip()
data += '=' * (4 - len(data) % 4)
print(zlib.decompress(base64.urlsafe_b64decode(data)))
"
```

### What to Look For in the Cookie
Once decoded, the JSON fields tell you exactly what controls access:
```json
{
  "isAdmin": false,          ← privilege flag
  "is_testuser_account": false,
  "username": "user@site.com"
}
```
If you find the `SECRET_KEY` (via LFI on `/proc/self/environ` or source code), you can **forge any cookie** for any user.

### Identifying Flask
- Default 404 page has a specific HTML doctype pattern
- Port 5000 or 8000 common for dev/Werkzeug
- Banner: `Werkzeug/x.x.x Python/x.x.x`
- Cookie named `session` with the dot-separated format above
- MD5 passwords with no salt = likely a quick/dirty Flask app

### Common Weak Patterns in Flask Apps
- `SECRET_KEY = os.urandom(24).hex()` on startup — means it rotates every restart, can't crack offline
- `SESSION_COOKIE_HTTPONLY = False` — XSS cookie theft is possible
- Passwords hashed with `hashlib.md5()` — no salt, trivially crackable on CrackStation

---

