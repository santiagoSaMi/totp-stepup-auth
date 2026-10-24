from pathlib import Path

from dotenv import load_dotenv

# Load .env before anything imports Prefect, so PREFECT_API_URL is picked up.
# Variables already set in the environment take precedence.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
