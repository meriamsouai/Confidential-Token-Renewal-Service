import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
import httpx


def _sign_request(runner_secret: str, timestamp: str, nonce: str) -> str:
    message = f"{timestamp}:{nonce}".encode()
    return hmac.new(runner_secret.encode(), message, hashlib.sha256).hexdigest()


def _detect_runner_environment() -> str:
    if os.environ.get("RUNNER_ENVIRONMENT"):
        return os.environ["RUNNER_ENVIRONMENT"]
    if os.environ.get("GITHUB_ACTIONS") == "true":
        runner_name = os.environ.get("RUNNER_NAME", "")
        if runner_name.startswith("GitHub Actions") or runner_name == "":
            return "github-hosted"
        return "self-hosted"
    if os.environ.get("CI") and os.environ.get("GITLAB_CI") == "true":
        tags = os.environ.get("CI_RUNNER_TAGS", "").lower()
        description = os.environ.get("CI_RUNNER_DESCRIPTION", "").lower()
        if "shared" in tags or "instance" in tags or "shared" in description:
            return "gitlab-shared"
        if os.environ.get("CI_RUNNER_ID") and not os.environ.get("CTRS_RUNNER_SECRET") and not os.environ.get(
            "CTRS_RUNNER_SECRET_FILE"
        ):
            return "gitlab-shared"
        return "self-hosted"
    return "self-hosted"


def _collect_context() -> dict:
    branch = (
        os.environ.get("GITHUB_REF", "")
        .replace("refs/heads/", "")
        or os.environ.get("CI_COMMIT_REF_NAME", "")
    )
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY") or os.environ.get("CI_PROJECT_PATH", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW") or os.environ.get("CI_JOB_NAME", ""),
        "branch": branch,
        "runner_environment": _detect_runner_environment(),
    }


def _load_runner_secret() -> str:
    secret = os.environ.get("CTRS_RUNNER_SECRET", "")
    secret_file = os.environ.get("CTRS_RUNNER_SECRET_FILE", "")
    if secret_file and Path(secret_file).exists():
        try:
            secret = Path(secret_file).read_text().strip()
        except PermissionError as exc:
            raise click.ClickException(
                f"Permission denied reading {secret_file}. "
                "The file is owned by gitlab-runner (mode 600). Run prove-host as that user, e.g.\n"
                f"  sudo -u gitlab-runner env CTRS_RUNNER_ID=$CTRS_RUNNER_ID "
                f"CTRS_SERVICE_URL=$CTRS_SERVICE_URL CTRS_RUNNER_SECRET_FILE={secret_file} "
                f"$(command -v confstr) prove-host"
            ) from exc
    if not secret:
        raise click.ClickException(
            "Set CTRS_RUNNER_SECRET or CTRS_RUNNER_SECRET_FILE (file should be mode 600)"
        )
    return secret


@click.group()
def main():
    """confstr — exchange generic token handles for short-lived access tokens."""


@main.command("exchange")
@click.option("--target", type=click.Choice(["github", "gitlab", "registry", "auto"]), default="auto")
@click.option("--output", type=click.Choice(["token", "json", "env"]), default="token")
@click.option("--service-url", envvar="CTRS_SERVICE_URL", default="http://localhost:8080")
@click.option("--handle", envvar="CTRS_GENERIC_HANDLE", required=False)
@click.option("--runner-id", envvar="CTRS_RUNNER_ID", required=False)
def exchange(target: str, output: str, service_url: str, handle: str | None, runner_id: str | None):
    """Exchange a generic handle for a short-lived real token."""
    if not handle:
        raise click.ClickException("Set CTRS_GENERIC_HANDLE or pass --handle")
    if not runner_id:
        raise click.ClickException("Set CTRS_RUNNER_ID or pass --runner-id")

    env = _detect_runner_environment()
    if env == "github-hosted":
        click.echo("ERROR: confstr refuses to run on GitHub-hosted runners.", err=True)
        sys.exit(2)

    runner_secret = _load_runner_secret()
    ctx = _collect_context()
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(8)
    signature = _sign_request(runner_secret, timestamp, nonce)

    payload = {
        "handle": handle,
        "runner_id": runner_id,
        "signature": signature,
        "timestamp": timestamp,
        "nonce": nonce,
        **ctx,
    }

    try:
        resp = httpx.post(f"{service_url.rstrip('/')}/api/v1/exchange", json=payload, timeout=30.0)
    except httpx.RequestError as e:
        raise click.ClickException(f"Cannot reach token service: {e}") from e

    if resp.status_code != 200:
        detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        raise click.ClickException(f"Exchange denied ({resp.status_code}): {detail}")

    data = resp.json()
    if target != "auto" and data.get("target_system") != target:
        raise click.ClickException(
            f"Handle targets '{data.get('target_system')}', not '{target}'"
        )

    if output == "json":
        # Never log this in CI — use ::add-mask:: in workflow
        click.echo(json.dumps(data))
    elif output == "env":
        click.echo(f"CTRS_ACCESS_TOKEN={data['access_token']}")
        click.echo(f"CTRS_TOKEN_EXPIRES_AT={data['expires_at']}")
    else:
        click.echo(data["access_token"])


@main.command("verify-runner")
def verify_runner():
    """Check whether this machine appears to be an authorized runner environment."""
    env = _detect_runner_environment()
    ctx = _collect_context()
    click.echo(f"Runner environment: {env}")
    click.echo(f"Repository: {ctx['repository'] or '(not set)'}")
    click.echo(f"Workflow: {ctx['workflow'] or '(not set)'}")
    click.echo(f"Branch: {ctx['branch'] or '(not set)'}")
    if env == "github-hosted":
        click.echo("WARNING: GitHub-hosted runner — token exchange will be denied.")
        sys.exit(1)
    click.echo("OK: Environment appears suitable for confstr.")


@main.command("prove-host")
@click.option("--service-url", envvar="CTRS_SERVICE_URL", default="http://localhost:8080")
@click.option("--runner-id", envvar="CTRS_RUNNER_ID", required=False)
def prove_host(service_url: str, runner_id: str | None):
    """Prove /etc/ctrs/runner-secret matches the runner registered in CTRS."""
    if not runner_id:
        raise click.ClickException("Set CTRS_RUNNER_ID or pass --runner-id")

    runner_secret = _load_runner_secret()
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(8)
    signature = _sign_request(runner_secret, timestamp, nonce)
    payload = {
        "runner_id": runner_id,
        "signature": signature,
        "timestamp": timestamp,
        "nonce": nonce,
    }
    try:
        resp = httpx.post(
            f"{service_url.rstrip('/')}/api/v1/runners/heartbeat",
            json=payload,
            timeout=30.0,
        )
    except httpx.RequestError as e:
        raise click.ClickException(f"Cannot reach token service: {e}") from e

    if resp.status_code != 200:
        detail = (
            resp.json().get("detail", resp.text)
            if resp.headers.get("content-type", "").startswith("application/json")
            else resp.text
        )
        raise click.ClickException(f"Host proof failed ({resp.status_code}): {detail}")

    data = resp.json()
    click.echo(data.get("message") or "OK: host setup verified")
    click.echo(f"host_setup={data.get('host_setup')} last_seen_at={data.get('last_seen_at')}")


if __name__ == "__main__":
    main()
