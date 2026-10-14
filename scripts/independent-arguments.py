# TOOL-01: shared CLI for the independent Python reimplementations.
"""The strict command line shared by the independent Python checkers.

Loaded before optional cryptographic dependencies, so malformed commands
fail with usage and exit 2 before any computation or record write.
"""
import argparse


def parse_arguments(arguments, check_command):
    """Encryption parameters, nonempty check files, or vector
    options/files.
    """
    suite = 3 if check_command == "passwords" else 4
    parser = argparse.ArgumentParser(prog=f"python3 scripts/independent-suite{suite}.py")
    commands = parser.add_subparsers(dest="command", required=True)
    encryption = commands.add_parser("encrypt")
    encryption.add_argument("phrase")
    encryption.add_argument("password")
    encryption.add_argument("pim", type=int, nargs="?", default=0)
    encryption.add_argument("memory_level", type=int, nargs="?", default=0)
    checks = commands.add_parser(check_command)
    checks.add_argument("files", nargs="+")
    vectors = commands.add_parser("vector")
    vectors.add_argument("--trust-argon2-keys", action="store_true")
    vectors.add_argument("--record")
    vectors.add_argument("files", nargs="+")
    return parser.parse_args(arguments)
