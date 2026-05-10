|Framework |Look For|
|---|---|
|Flask|Cookie format, Werkzeug banner, debug mode RCE|
|Django|`/admin` panel, CSRF tokens, `csrfmiddlewaretoken`|
|Laravel|`.env` files with DB creds, debug pages leaking config|
|Express|`X-Powered-By: Express` header|
|Rails|Cookie named `_session_id`, predictable paths|
