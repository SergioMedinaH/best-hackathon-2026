"""
Presentation routes with intentionally unsafe template handling.
"""

from flask import Blueprint, render_template_string, request

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/hello")
def hello():
    name = request.args.get("name", "world")

    # CWE-79 / SSTI-style unsafe template construction
    return render_template_string(f"<h1>Hello {name}</h1>")
