"""HTML view routes for the Sonar Catalog web interface."""

import os
from flask import Blueprint, render_template

views_bp = Blueprint(
    "views", __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static",
)


@views_bp.route("/")
def index():
    return render_template("index.html")


@views_bp.route("/globe")
def globe():
    return render_template("globe.html")
