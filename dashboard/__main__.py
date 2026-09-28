import sys
import os
import uvicorn
import argparse

def main():
    parser = argparse.ArgumentParser(description="Diode-Sentinel NTRO Operations Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
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
