"""
Data import/export routes used to showcase unsafe file and deserialization flows.
"""

import os
import pickle

import yaml
from flask import Blueprint, request, send_file

data_bp = Blueprint("data", __name__)


@data_bp.route("/restore", methods=["POST"])
def restore_session():
    blob = request.get_data()

    # CWE-502 - insecure deserialization on user-controlled bytes
    state = pickle.loads(blob)
    return {"restored": str(state)}


@data_bp.route("/config", methods=["POST"])
def upload_config():
    # CWE-502 - unsafe YAML loader
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"loaded": list(cfg.keys()) if isinstance(cfg, dict) else []}


@data_bp.route("/download")
def download():
    filename = request.args.get("file")

    # CWE-22 - path traversal
    path = os.path.join("/var/app/uploads", filename)
    return send_file(path)
