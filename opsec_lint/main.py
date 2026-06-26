import sys
import argparse
from opsec_lint.scanner import scan_text
from opsec_lint.report import print_results


def main():
    parser = argparse.ArgumentParser(
        prog='opsec-lint',
        description='Linter OPSEC — detecte les fuites d\'infos perso avant de poster en ligne',
    )
    sub = parser.add_subparsers(dest='command')

    # commande scan
    scan_parser = sub.add_parser('scan', help='scanner un fichier ou stdin')
    scan_parser.add_argument('file', help='fichier a scanner (ou - pour stdin)')
    scan_parser.add_argument('--level', choices=['low', 'medium', 'high', 'critical'],
                             default='low', help='niveau de severite minimum (default: low)')

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
                print(f"Erreur: fichier '{args.file}' introuvable")
                sys.exit(1)
            except UnicodeDecodeError:
                with open(args.file, 'r', encoding='latin-1') as f:
                    text = f.read()
                filename = args.file

        results = scan_text(text, min_level=args.level)
        print_results(results, filename=filename)

        # exit code non-zero si des trucs ont ete trouves
        if results:
            sys.exit(2)


if __name__ == '__main__':
    main()
