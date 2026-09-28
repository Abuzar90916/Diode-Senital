"""
Diode-Sentinel Root Application Entrypoint for Vercel and ASGI runners.
Exposes the FastAPI instance from dashboard.server.
"""
from dashboard.server import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
