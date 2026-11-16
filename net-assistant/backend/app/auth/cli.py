"""Explicit local administration; secrets are prompted, never command-line arguments."""
import argparse
from getpass import getpass
from pathlib import Path

from app.auth.store import AuthStore
from app.discovery.store import initialize_database


def main():
    parser = argparse.ArgumentParser(description="平台账户管理（显式数据库路径）")
    parser.add_argument("--database", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("migrate")
    add = sub.add_parser("create-user")
    add.add_argument("username")
    add.add_argument("--role", choices=("admin", "operator", "viewer"), default="viewer")
    for action in ("disable-user", "reset-password"):
        sub.add_parser(action).add_argument("username")
    args = parser.parse_args()
    if not args.database.is_absolute():
        parser.error("--database must be absolute")
    if args.action == "migrate":
        initialize_database(args.database)
        print("Database migrated (existing migration framework makes a consistency backup).")
        return
    store = AuthStore(args.database)
    if args.action == "disable-user":
        store.disable_user(args.username)
    else:
        password = getpass("Password (12-128 characters): ")
        if password != getpass("Repeat password: "):
            parser.error("Passwords differ.")
        if args.action == "create-user":
            store.create_user(args.username, password, args.role)
        else:
            store.reset_password(args.username, password)
    print("Completed; no password or session token is printed.")


if __name__ == "__main__":
    main()
