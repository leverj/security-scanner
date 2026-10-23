import sys

from security_scan.main import cli

if __name__ == "__main__":
    # Propagate cli()'s return code. `python -m security_scan` is the Docker
    # ENTRYPOINT; dropping the code here made every failure (config 2,
    # all-scanners-failed 3, GitHub 4) exit 0 and show green in CI.
    sys.exit(cli())
