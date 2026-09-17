"""Operator commands; schema creation is an explicit action."""

import argparse
import json

from agentgate.config import Settings
from agentgate.storage.database import Store


def main():
    parser = argparse.ArgumentParser(prog="agentgate")
    parser.add_argument("command", choices=["init-db", "check", "prune", "serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    settings = Settings()
    if args.command == "serve":
        import uvicorn

        uvicorn.run("agentgate.api.app:app", host=args.host, port=args.port, workers=1)
        return
    store = Store(settings.database_url)
    try:
        if args.command == "init-db":
            store.initialize()
        else:
            store.check()
        if args.command == "prune":
            store.prune(settings.retention_days)
        print(json.dumps({"status": "ok", "command": args.command, "schema_version": 1}))
    finally:
        store.engine.dispose()


if __name__ == "__main__":
    main()
