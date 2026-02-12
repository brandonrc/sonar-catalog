"""Flask web interface for the Sonar Catalog."""

import logging

from flask import Flask

from ..config import Config
from ..database import CatalogDB

logger = logging.getLogger(__name__)


def create_app(config: Config = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config is None:
        config = Config.load()

    # Store DB factory on app so routes can access it
    app.config["CATALOG_CONFIG"] = config

    def get_db() -> CatalogDB:
        return CatalogDB(config.database)

    app.config["GET_DB"] = get_db

    from .api import api_bp
    from .views import views_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(views_bp)

    # Let plugins register additional web routes
    try:
        from ..plugins import plugin_manager, _initialized
        if _initialized:
            plugin_manager.call_hook("register_web_routes", app=app)
    except ImportError:
        pass

    return app
