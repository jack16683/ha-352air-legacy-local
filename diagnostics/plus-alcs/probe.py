#!/usr/bin/env python3
"""Test-tool entry point. No credentials in command-line arguments."""

import json

if __name__ == "__main__":
    try:
        from plus_testkit.cli import main
    except ImportError:
        print(
            json.dumps(
                {
                    "tool_version": "0.1.0-test1",
                    "status": "failed",
                    "error": {"reason": "RUNTIME_DEPENDENCY_MISSING"},
                }
            )
        )
        raise SystemExit(2)
    raise SystemExit(main())
