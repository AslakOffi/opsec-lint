import sys
import argparse
from opsec_lint.scanner import scan_text
from opsec_lint.report import print_results, print_json_results


def main():
    parser = argparse.ArgumentParser(
        prog='opsec-lint',
        description='OPSEC linter — detect personal info leaks before posting online',
    )
    sub = parser.add_subparsers(dest='command')

    # commande scan
    scan_parser = sub.add_parser('scan', help='scan a file or stdin')
    scan_parser.add_argument('file', help='file to scan (or - for stdin)')
    scan_parser.add_argument('--level', choices=['low', 'medium', 'high', 'critical'],
                             default='low', help='minimum severity level (default: low)')
    scan_parser.add_argument('--format', choices=['text', 'json'], default='text',
                             help='output format (default: text)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'scan':
        if args.file == '-':
            text = sys.stdin.read()
            filename = 'stdin'
        else:
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    text = f.read()
                filename = args.file
            except FileNotFoundError:
                print(f"Error: file '{args.file}' not found")
                sys.exit(1)
            except UnicodeDecodeError:
                with open(args.file, 'r', encoding='latin-1') as f:
                    text = f.read()
                filename = args.file

        results = scan_text(text, min_level=args.level)

        if args.format == 'json':
            print_json_results(results, filename=filename)
        else:
            print_results(results, filename=filename)

        # exit code non-zero si des trucs ont ete trouves
        if results:
            sys.exit(2)


if __name__ == '__main__':
    main()
