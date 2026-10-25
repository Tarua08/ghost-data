"""Run a minimal Gemini API connectivity test using local .env settings."""

from __future__ import annotations

import os
from pathlib import Path

from google import genai


REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"


def load_local_env(path: Path) -> None:
    """Load simple KEY=VALUE settings without printing their values."""
    if not path.is_file():
        raise RuntimeError(f"Missing local environment file: {path}")

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def main() -> None:
    load_local_env(ENV_PATH)
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    model = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is empty in .env")

    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=model,
            contents=(
                "This is a connectivity test. Reply with exactly "
                "GEMINI_CONNECTION_OK and no other text."
            ),
        )
        print(f"Model: {model}")
        print(f"Response: {(response.text or '').strip()}")
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            print(f"Usage: {usage}")
    except Exception as exc:
        safe_message = str(exc).replace(api_key, "[REDACTED]")
        raise RuntimeError(f"Gemini request failed: {safe_message}") from None
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()


if __name__ == "__main__":
    main()
