"""Vercel Serverless Function entrypoint for Project Vero.
Exposes the FastAPI application directly to Vercel's Python runtime.
"""

import os
import sys

# Ensure repository root and api-agents package are on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_AGENTS_DIR = os.path.join(ROOT_DIR, "api-agents")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if API_AGENTS_DIR not in sys.path:
    sys.path.insert(0, API_AGENTS_DIR)

from api_agents.main import app

# Vercel looks for 'app' or WSGI/ASGI handler
handler = app
