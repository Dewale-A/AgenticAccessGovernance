#!/usr/bin/env python3
"""Start the FastAPI server."""
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load .env
from dotenv import load_dotenv
load_dotenv()

import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
