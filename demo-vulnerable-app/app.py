"""
Intentionally vulnerable Flask application for demoing the Security Agent
JetBrains plugin during the BEST UC3M hackathon.

DO NOT DEPLOY. DO NOT EXPOSE TO THE INTERNET.
"""

from flask import Flask, jsonify

from auth_routes import auth_bp
from data_routes import data_bp
from network_routes import network_bp
from ui_routes import ui_bp

app = Flask(__name__)

# CWE-798 - hardcoded application secret
app.config["SECRET_KEY"] = "vigil-ai-demo-secret-do-not-ship"

app.register_blueprint(auth_bp)
app.register_blueprint(data_bp)
app.register_blueprint(network_bp)
app.register_blueprint(ui_bp)


@app.route("/")
def index():
    return jsonify(
        {
            "service": "vigil-ai-demo",
            "routes": [
                "/login",
                "/register",
                "/ping",
                "/fetch",
                "/restore",
                "/config",
                "/download",
                "/hello",
            ],
        }
    )


if __name__ == "__main__":
    # CWE-489 / CWE-668 demo flags that should be caught by the scan.
    app.run(debug=True, host="0.0.0.0", port=5000)
