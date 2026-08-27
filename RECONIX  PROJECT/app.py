"""
================================================================================
app.py — سيرفر Flask جاهز يستخدم master_link.py كباكاند
================================================================================
لازم يكون في نفس الفولدر مع:
    security_behavior_engine.py
    http_scanner.py
    robots_analyzer.py
    master_link.py

التشغيل:
    pip install flask flask-cors
    python3 app.py

هيفتح سيرفر على:  http://127.0.0.1:5000

Endpoints المتاحة:
    GET  /                          -> health check عام
    GET  /api/v1/master/health      -> health check للماستر بلوبرنت
    POST /api/v1/master/scan        -> الفحص الكامل (body: {"url": "..."})

مثال cURL:
    curl -X POST http://127.0.0.1:5000/api/v1/master/scan \
         -H "Content-Type: application/json" \
         -d '{"url": "https://example.com"}'
================================================================================
"""

from flask import Flask, jsonify

from master_link import create_master_blueprint
from osint_api import create_osint_blueprint

# --------------------------------------------------------------------------
# لو حابب تسمح للفرونت إند (React/Vue/إلخ) يكلم السيرفر ده من دومين مختلف،
# فعّل flask-cors (اختياري - شيل الكومنت لو محتاجه):
# --------------------------------------------------------------------------
try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False


def create_app() -> Flask:
    app = Flask(__name__)

    if HAS_CORS:
        CORS(app)  # يسمح لأي origin يكلم الـ API - قيّدها في الإنتاج لو محتاج

    # تسجيل الـ Blueprint بتاع الماستر سكان تحت المسار /api/v1/master
    master_bp = create_master_blueprint()
    if master_bp is not None:
        app.register_blueprint(master_bp, url_prefix="/api/v1/master")
    else:
        print("[!] WARNING: Flask not detected inside master_link — blueprint not created.")

    # OSINT lookup endpoints — one identifier per request, called manually
    # by the frontend when the operator picks a discovered identity to
    # look up. See osint_api.py for scope notes.
    osint_bp = create_osint_blueprint()
    if osint_bp is not None:
        app.register_blueprint(osint_bp, url_prefix="/api/v1/osint")
    else:
        print("[!] WARNING: Flask not detected inside osint_api — blueprint not created.")

    @app.route("/")
    def index():
        return jsonify({
            "service": "Reconix Security Toolkit Backend",
            "status": "running",
            "endpoints": {
                "health": "/api/v1/master/health",
                "scan": "/api/v1/master/scan (POST, body: {\"url\": \"...\"})",
                "osint_username": "/api/v1/osint/username (POST, body: {\"value\": \"...\"})",
                "osint_email": "/api/v1/osint/email (POST, body: {\"value\": \"...\"})",
                "osint_ip": "/api/v1/osint/ip (POST, body: {\"value\": \"...\"})",
                "osint_phone": "/api/v1/osint/phone (POST, body: {\"value\": \"...\", \"country\": \"EG\"})",
            },
        })

    return app


app = create_app()


if __name__ == "__main__":
    # debug=True مفيد أثناء التطوير بس، شيلها في الإنتاج
    app.run(host="0.0.0.0", port=5000, debug=False)