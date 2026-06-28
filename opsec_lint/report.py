import json
from opsec_lint import __version__

# couleurs ANSI
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
GRAY = '\033[90m'
BOLD = '\033[1m'
RESET = '\033[0m'
MAGENTA = '\033[95m'

severity_colors = {
    'low': CYAN,
    'medium': YELLOW,
    'high': RED,
    'critical': MAGENTA,
}


def truncate_context(context, match, max_len=70):
    # coupe le contexte autour du match pour l'affichage
    idx = context.lower().find(str(match).lower())
    if idx == -1:
        # si on trouve pas, on prend le debut
        if len(context) > max_len:
            return context[:max_len] + '...'
        return context

    start = max(0, idx - 30)
    end = min(len(context), idx + len(str(match)) + 30)
    snippet = context[start:end]

    prefix = '... ' if start > 0 else ''
    suffix = ' ...' if end < len(context) else ''
    return prefix + snippet + suffix


def print_results(results, filename=None):
    # affiche les resultats dans le terminal
    print()
    print(f"  {BOLD}opsec-lint v{__version__}{RESET}")
    if filename:
        print(f"  {GRAY}file: {filename}{RESET}")
    print()

    if not results:
        print(f"  {CYAN}✓ All clear — no leaks detected{RESET}")
        print()
        return

    for r in results:
        color = severity_colors.get(r['severity'], YELLOW)
        match_str = r['matches'][0] if r['matches'] else ''
        ctx = truncate_context(r['context'], match_str)

        print(f"  {color}[!]{RESET} line {r['line']} : "
              f"{BOLD}{r['type']}{RESET} — {get_description(r['type'])}")
        print(f"      {GRAY}\"{ctx}\"{RESET}")
        print()

    # resume
    print(f"  {GRAY}---{RESET}")
    counts = {}
    for r in results:
        t = r['type'].lower()
        counts[t] = counts.get(t, 0) + 1

    total = len(results)
    detail = ', '.join(f"{v} {k}" for k, v in counts.items())
    print(f"  {BOLD}{total} problem{'s' if total > 1 else ''} found{RESET} ({detail})")
    print(f"  {YELLOW}Clean up before posting!{RESET}")
    print()


def print_json_results(results, filename=None):
    # sortie json pour integration dans des pipelines / scripts
    output = {
        'version': __version__,
        'file': filename,
        'total': len(results),
        'results': [],
    }

    for r in results:
        output['results'].append({
            'line': r['line'],
            'type': r['type'],
            'severity': r['severity'],
            'matches': r['matches'],
            'context': r['context'],
        })

    print(json.dumps(output, indent=2, ensure_ascii=False))


def get_description(check_type):
    # descriptions courtes pour chaque type
    desc = {
        'EMAIL': 'email address detected',
        'PHONE': 'phone number detected',
        'IBAN/CB': 'IBAN or card number detected',
        'PATH': 'system path detected',
        'TIMEZONE': 'time reference detected',
        'IP': 'IP address detected',
        'API_KEY': 'API key or token detected',
        'GEO': 'location name detected',
        'SENSITIVE_FILE': 'sensitive file mentioned',
    }
    return desc.get(check_type, 'leak detected')
