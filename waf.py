from flask import Flask, request, Response
import requests
import re
from datetime import datetime

app = Flask(__name__)

BACKEND_URL = "http://127.0.0.1:8000"

BLOCK_PATTERNS = [
    r"<\s*script\b",
    r"onerror\s*=",
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"drop\s+table",
    r"\.\./",
    r"(;|&&|\|\|)",
    r"sleep\s*\(",
    r"load_file\s*\(",
]

def is_malicious(text: str) -> bool:
    if not text:
        return False
    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def log_block(path: str, reason: str, payload: str):
    ts = datetime.utcnow().isoformat() + "Z"
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    with open("waf.log", "a", encoding="utf-8") as f:
        f.write(f"[{ts}] BLOCKED ip={ip} method={request.method} path=/{path} reason={reason} payload={payload}\n")

@app.route('/', defaults={'path': ''}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route('/<path:path>', methods=["GET","POST","PUT","DELETE","PATCH"])
def proxy(path):
    body_text = request.get_data(as_text=True) or ""
    body_bytes = request.get_data() or b""
    query_values = " ".join(request.args.values()) if request.args else ""
    check_text = " ".join(filter(None, [path, query_values, body_text]))

    if is_malicious(check_text):
        log_block(path, "pattern-match", check_text)
        return Response("Request blocked by WAF", status=403)

    target_url = f"{BACKEND_URL}/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            params=request.args,
            headers=headers,
            data=body_bytes,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=15
        )
    except requests.RequestException as e:
        return Response(f"Backend error: {e}", status=502)

    excluded = {"content-encoding", "transfer-encoding", "content-length", "connection"}
    response_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

    return Response(resp.content, status=resp.status_code, headers=response_headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
