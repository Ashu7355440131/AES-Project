import sys
from src.cli.commands import build_parser
from src.crypto.cipher import CryptographicIntegrityError


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (
        CryptographicIntegrityError,
        FileNotFoundError,
        FileExistsError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()