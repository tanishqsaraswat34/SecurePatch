import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]

GOOGLE_CLOUD_PROJECT = os.getenv(
    "GOOGLE_CLOUD_PROJECT",
    "",
)

GOOGLE_CLOUD_LOCATION = os.getenv(
    "GOOGLE_CLOUD_LOCATION",
    "global",
)

MODEL = os.getenv(
    "SECUREPATCH_MODEL",
    "gemini-3.5-flash",
)

INDUCE_FAILURE = (
    os.getenv(
        "SECUREPATCH_INDUCE_FAILURE",
        "false",
    ).lower()
    == "true"
)

RUNS_DIR = PROJECT_ROOT / "runs"
RUNS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

MAX_FILE_SIZE = 200_000