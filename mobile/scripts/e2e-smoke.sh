#!/usr/bin/env bash
# ACT end-to-end simulator smoke — the one command.
#
#   mobile/scripts/e2e-smoke.sh                 # everything
#   mobile/scripts/e2e-smoke.sh --verbose       # stream flutter output
#   mobile/scripts/e2e-smoke.sh --scenario app_boot
#
# Starts its own gateway on a private port with a throw-away database, runs the
# integration_test scenarios on the iOS Simulator, tears everything down and
# exits non-zero if any scenario fails. See integration_test/README.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# -u so progress reaches a redirected log as it happens, not at exit.
exec /usr/bin/env python3 -u "$here/e2e_smoke.py" "$@"
