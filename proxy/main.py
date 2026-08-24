from __future__ import annotations

import argparse
import logging

from .config import load_config
from .server import run


def main() -> None:
    parser = argparse.ArgumentParser(description="ssh-proxy-guard: allowlisted SSH proxy for AI agents")
    parser.add_argument("--config", required=True, help="path to the YAML config file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    devices = load_config(args.config)
    run(devices)


if __name__ == "__main__":
    main()
