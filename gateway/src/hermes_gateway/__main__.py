"""Make ``python -m hermes_gateway`` launch the supervised gateway.

The LaunchAgent shim execs ``<venv-python> -m hermes_gateway``. Without this
module that invocation raises ``No module named hermes_gateway.__main__`` and
the KeepAlive job crash-loops on every launch.
"""
from __future__ import annotations

from .main import main

if __name__ == "__main__":
    main()
