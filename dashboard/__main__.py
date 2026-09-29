import sys
import os
import uvicorn
import argparse

def main():
    default_host = os.environ.get("HOST", "127.0.0.1")
    default_port = int(os.environ.get("PORT", 8000))

    parser = argparse.ArgumentParser(description="Diode-Sentinel NTRO Operations Dashboard")
    parser.add_argument("--host", default=default_host, help=f"Host interface (default: {default_host})")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to bind (default: {default_port})")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    args = parser.parse_args()

    print("=" * 72)
    print("  DIODE-SENTINEL // NTRO TACTICAL OPERATIONS DASHBOARD")
    print(f"  Interface: http://{args.host}:{args.port}")
    print("  Zero-Egress Diode Hardware: RX-ONLY [ENFORCED]")
    print("  Single-Command Demo Mode: READY")
    print("=" * 72)

    uvicorn.run(
        "dashboard.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()
