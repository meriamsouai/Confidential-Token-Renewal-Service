from pydantic_settings import BaseSettings

# Built-in default used only until the operator sets a URL in the dashboard (stored in DB).
DEFAULT_GITLAB_BASE_URL = "https://se-gitlab.inf.tu-dresden.de"


class Settings(BaseSettings):
    master_key: str = "ctrs-demo-master-key-32bytes!!!!"
    database_url: str = "sqlite:///./ctrs.db"
    service_host: str = "0.0.0.0"
    service_port: int = 8080
    renewal_check_interval_minutes: int = 15
    default_short_lived_ttl_seconds: int = 3600
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    admin_api_key: str = ""  # legacy; prefer GitLab OAuth sessions
    # Runtime GitLab API base — loaded from DB on startup / updated from the dashboard.
    gitlab_base_url: str = DEFAULT_GITLAB_BASE_URL
    gitlab_pat: str = ""  # legacy global PAT; per-user OAuth token preferred

    # GitLab OAuth application (create under GitLab → Applications)
    gitlab_oauth_client_id: str = ""
    gitlab_oauth_client_secret: str = ""
    # Must match the dashboard origin (Vite proxy) so the session cookie is set for :5173
    gitlab_oauth_redirect_uri: str = "http://127.0.0.1:5173/api/v1/auth/gitlab/callback"
    gitlab_oauth_scopes: str = "read_user api"
    session_secret: str = "ctrs-dev-session-secret-change-me"
    session_cookie_name: str = "ctrs_session"
    session_ttl_hours: int = 72
    dashboard_url: str = "http://127.0.0.1:5173"

    # Real SMTP for operator notifications
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
