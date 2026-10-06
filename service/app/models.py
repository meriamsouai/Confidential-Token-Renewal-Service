from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    gitlab_user_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(256), default="")
    email: Mapped[str] = mapped_column(String(512), default="")
    name: Mapped[str] = mapped_column(String(512), default="")
    encrypted_gitlab_token: Mapped[str] = mapped_column(Text, default="")
    encrypted_gitlab_refresh_token: Mapped[str] = mapped_column(Text, default="")
    token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notify_email_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ManagedToken(Base):
    __tablename__ = "managed_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    target_system: Mapped[str] = mapped_column(String(64))
    owner: Mapped[str] = mapped_column(String(256))
    scopes: Mapped[str] = mapped_column(Text, default="")
    encrypted_secret: Mapped[str] = mapped_column(Text)
    renewal_method: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_renewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_renewal_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    renewal_status: Mapped[str] = mapped_column(String(32), default="healthy")
    usage_locations: Mapped[str] = mapped_column(Text, default="")
    default_short_lived_ttl: Mapped[int] = mapped_column(Integer, default=3600)
    provider_metadata: Mapped[str] = mapped_column(Text, default="")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_expiry_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    handles: Mapped[list["TokenHandle"]] = relationship(back_populates="token")
    renewal_events: Mapped[list["RenewalEvent"]] = relationship(back_populates="token")


class TokenHandle(Base):
    __tablename__ = "token_handles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    handle: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    token_id: Mapped[str] = mapped_column(String(64), ForeignKey("managed_tokens.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    token: Mapped["ManagedToken"] = relationship(back_populates="handles")


class Runner(Base):
    __tablename__ = "runners"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    runner_type: Mapped[str] = mapped_column(String(32), default="self-hosted")
    encrypted_secret: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(256), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_id: Mapped[str] = mapped_column(String(64), ForeignKey("managed_tokens.id"))
    effect: Mapped[str] = mapped_column(String(16), default="allow")
    conditions_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    token_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    runner_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    repository: Mapped[str] = mapped_column(String(256), default="")
    workflow: Mapped[str] = mapped_column(String(256), default="")
    branch: Mapped[str] = mapped_column(String(256), default="")
    outcome: Mapped[str] = mapped_column(String(32))
    policy_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RenewalEvent(Base):
    __tablename__ = "renewal_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[str] = mapped_column(String(64), ForeignKey("managed_tokens.id"))
    status: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text, default="")
    # manual | scheduler | gitlab_external | gitlab_resync
    source: Mapped[str] = mapped_column(String(32), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    token: Mapped["ManagedToken"] = relationship(back_populates="renewal_events")


class OperatorSettings(Base):
    """Per-user operator preferences (renewal schedule + GitLab base URL)."""

    __tablename__ = "operator_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), unique=True, nullable=True, index=True)
    renewal_check_interval_minutes: Mapped[int] = mapped_column(Integer, default=15)
    renewal_threshold_days: Mapped[int] = mapped_column(Integer, default=14)
    gitlab_base_url: Mapped[str] = mapped_column(String(512), default="")


class TrackedGitLabProject(Base):
    """Projects a user wants in their token inventory."""

    __tablename__ = "tracked_gitlab_projects"
    __table_args__ = (UniqueConstraint("user_id", "project_path", name="uq_tracked_user_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.id"), nullable=True, index=True)
    project_path: Mapped[str] = mapped_column(String(512), index=True)
    project_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _add_column_if_missing(table: str, column: str, ddl: str) -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if table not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns(table)}
    if column not in cols:
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))


def _migrate_schema() -> None:
    """Add columns introduced after initial prototype (SQLite-safe)."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    _add_column_if_missing("managed_tokens", "provider_metadata", "provider_metadata TEXT DEFAULT ''")
    _add_column_if_missing("managed_tokens", "is_demo", "is_demo BOOLEAN DEFAULT 0")
    _add_column_if_missing("managed_tokens", "user_id", "user_id VARCHAR(64)")
    _add_column_if_missing(
        "managed_tokens", "last_expiry_notified_at", "last_expiry_notified_at DATETIME"
    )

    _add_column_if_missing("runners", "user_id", "user_id VARCHAR(64)")
    _add_column_if_missing("policies", "user_id", "user_id VARCHAR(64)")
    _add_column_if_missing("audit_events", "policy_id", "policy_id VARCHAR(64) DEFAULT ''")
    _add_column_if_missing("audit_events", "user_id", "user_id VARCHAR(64)")
    _add_column_if_missing("tracked_gitlab_projects", "user_id", "user_id VARCHAR(64)")
    _add_column_if_missing("renewal_events", "source", "source VARCHAR(32) DEFAULT 'manual'")

    if "operator_settings" in inspector.get_table_names():
        ops_cols = {c["name"] for c in inspector.get_columns("operator_settings")}
        with engine.begin() as conn:
            if "gitlab_base_url" not in ops_cols:
                conn.execute(
                    text("ALTER TABLE operator_settings ADD COLUMN gitlab_base_url VARCHAR(512) DEFAULT ''")
                )
            if "user_id" not in ops_cols:
                conn.execute(text("ALTER TABLE operator_settings ADD COLUMN user_id VARCHAR(64)"))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate_schema()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
