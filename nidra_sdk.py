import requests
from functools import wraps
from flask import request
from datetime import datetime
from urllib.parse import unquote
from datetime import datetime, timezone, timedelta
# import pytz

IST = timezone(timedelta(hours=5,minutes=30))

# "timestamp": datetime.now(IST).isoformat(),

NIDRA_BACKEND = "https://nidra.onrender.com"
# NIDRA_BACKEND = "http://localhost:8000"

def now_ist():
    return datetime.now(IST).isoformat()

class NidraSDK:

    def capture_request(self, request_obj):

        decoded_path = unquote(request_obj.full_path)

        forwarded = request_obj.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else request_obj.remote_addr

        log_data = {
            "timestamp": now_ist(),
            # "ip_address": request_obj.remote_addr,
            # "ip_address": ip,
            "ip_address": request_obj.headers.get("X-Forwarded-For", request_obj.remote_addr),
            "method": request_obj.method,
            "path": decoded_path,
            "user_agent": request_obj.headers.get("User-Agent"),
            "body": request_obj.form.to_dict() if request_obj.form else {},
            "files": [f.filename for f in request_obj.files.values()] if request_obj.files else []
        }   

        try:
            # print("[NIDRA SDK] Sending to backend:", log_data)

            response = requests.post(
                f"{NIDRA_BACKEND}/api/rules/analyze",
                json=[log_data],
                timeout=5
            )

            # 🔥 If backend already blocked this IP
            if response.status_code == 403:
                return "403 Forbidden - Blocked by NIDRA", 403

            result = response.json()

            if result.get("blocked"):
                return "403 Forbidden - Blocked by NIDRA", 403

        except Exception as e:
            print(f"[SDK ERROR] {e}")

        return None


def sniff_request_decorator(sdk_instance):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):

            result = sdk_instance.capture_request(request)

            if result is not None:
                return result

            return func(*args, **kwargs)

        return wrapper
    return decorator