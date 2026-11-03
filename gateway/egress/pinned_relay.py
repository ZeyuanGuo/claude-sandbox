"""Compatibility entry for the shared, lease-gated relay implementation."""
from controlled_dev_machine.degraded_egress import *  # noqa: F403
from controlled_dev_machine.degraded_egress import _relay, _respond, _header, _check_parent_response, main

if __name__ == "__main__":
    raise SystemExit(main())
