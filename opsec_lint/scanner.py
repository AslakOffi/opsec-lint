from opsec_lint.checks import (
    check_emails, check_phones, check_iban, check_paths,
    check_timezones, check_ips, check_api_keys, check_geo,
    check_sensitive_files,
)

# mapping type -> fonction de check
checkers = {
    'EMAIL': check_emails,
    'PHONE': check_phones,
    'IBAN/CB': check_iban,
    'PATH': check_paths,
    'TIMEZONE': check_timezones,
    'IP': check_ips,
    'API_KEY': check_api_keys,
    'GEO': check_geo,
    'SENSITIVE_FILE': check_sensitive_files,
}

# niveaux de severite par type
severity = {
    'EMAIL': 'high',
    'PHONE': 'high',
    'IBAN/CB': 'critical',
    'PATH': 'medium',
    'TIMEZONE': 'low',
    'IP': 'medium',
    'API_KEY': 'critical',
    'GEO': 'low',
    'SENSITIVE_FILE': 'medium',
}

severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}


def scan_text(text, min_level='low'):
    # scan le texte ligne par ligne et retourne les alertes
    min_sev = severity_order.get(min_level, 0)
    results = []
    lines = text.split('\n')

    for num, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for check_type, check_fn in checkers.items():
            if severity_order[severity[check_type]] < min_sev:
                continue
            hits = check_fn(line)
            if hits:
                results.append({
                    'line': num,
                    'type': check_type,
                    'severity': severity[check_type],
                    'matches': hits,
                    'context': line.strip(),
                })

    return results
