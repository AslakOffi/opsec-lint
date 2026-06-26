import re

# --- checks opsec ---
# chaque fonction prend une ligne de texte et retourne une liste de matches


def check_emails(line):
    # check les emails dans la ligne
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(pattern, line)


def check_phones(line):
    # numeros FR et internationaux
    patterns = [
        r'(?:(?:\+33|0033)\s*[1-9](?:[\s.-]*\d{2}){4})',
        r'(?:0[67](?:[\s.-]*\d{2}){4})',
        r'(?:\+\d{1,3}[\s.-]?\d{1,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4})',
    ]
    hits = []
    for p in patterns:
        hits.extend(re.findall(p, line))
    return hits


def check_iban(line):
    # IBAN et numeros de carte bancaire
    hits = []
    # iban (jusqu'a 34 caracteres alphanumeriques apres le code pays)
    iban = re.findall(r'\b[A-Z]{2}\d{2}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{0,4}\b', line)
    hits.extend(iban)
    # carte bancaire (16 chiffres groupes par 4)
    cb = re.findall(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', line)
    hits.extend(cb)
    return hits


def check_paths(line):
    # chemins systeme windows/linux/mac
    patterns = [
        r'[A-Z]:\\(?:Users|Documents and Settings)\\[^\s"\'<>|]+',
        r'/(?:home|Users)/[a-zA-Z0-9._-]+(?:/[^\s"\'<>|]*)?',
        r'~/(?:\.[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+)(?:/[^\s"\'<>|]*)?',
    ]
    hits = []
    for p in patterns:
        hits.extend(re.findall(p, line))
    return hits


def check_timezones(line):
    # mentions d'heure qui revelent un fuseau
    patterns_ci = [
        r'\b\d{1,2}[h]\d{0,2}\s*(?:du mat(?:in)?|du soir|de l\'aprem|de nuit)\b',
        r'\b(?:il est|vers)\s+\d{1,2}h\d{0,2}\b',
        r'\bà\s+\d{1,2}h\d{0,2}\b',
        r'\bat\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)\b',
        r'\b\d{1,2}:\d{2}\s*(?:am|pm)\b',
        r'\b\d{1,2}\s*(?:am|pm)\b',
    ]
    # les abreviations timezone en majuscules seulement (sinon "est" en francais matche EST)
    patterns_cs = [
        r'\b(?:UTC|GMT|CET|CEST|EST|PST|CST)[+-]?\d{0,2}\b',
    ]
    hits = []
    for p in patterns_ci:
        hits.extend(re.findall(p, line, re.IGNORECASE))
    for p in patterns_cs:
        hits.extend(re.findall(p, line))
    return hits


def check_ips(line):
    # adresses IPv4
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    matches = re.findall(pattern, line)
    # on filtre les trucs qui sont clairement pas des IPs
    valid = []
    for m in matches:
        parts = m.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid.append(m)
    return valid


def check_api_keys(line):
    # cles API, tokens, secrets
    patterns = [
        r'sk_live_[a-zA-Z0-9]{20,}',
        r'sk_test_[a-zA-Z0-9]{20,}',
        r'ghp_[a-zA-Z0-9]{36,}',
        r'github_pat_[a-zA-Z0-9_]{20,}',
        r'glpat-[a-zA-Z0-9\-]{20,}',
        r'AKIA[0-9A-Z]{16}',
        r'xox[baprs]-[a-zA-Z0-9-]{10,}',
        r'ya29\.[a-zA-Z0-9_-]{20,}',
        r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}',
        r'(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
    ]
    hits = []
    for p in patterns:
        hits.extend(re.findall(p, line, re.IGNORECASE))
    return hits


def check_geo(line):
    # noms de lieux, villes, stations, quartiers
    # on met les plus courants, c'est pas exhaustif
    villes = [
        'paris', 'lyon', 'marseille', 'toulouse', 'nice', 'nantes',
        'strasbourg', 'montpellier', 'bordeaux', 'lille', 'rennes',
        'reims', 'toulon', 'grenoble', 'dijon', 'angers', 'nimes',
        'clermont-ferrand', 'le havre', 'saint-etienne', 'brest',
        'versailles', 'rouen', 'mulhouse', 'perpignan', 'caen',
        'orleans', 'nancy', 'metz', 'besancon', 'avignon',
        'london', 'new york', 'berlin', 'tokyo', 'bruxelles',
        'geneve', 'montreal', 'amsterdam', 'barcelona', 'roma',
    ]
    quartiers = [
        'montmartre', 'belleville', 'bastille', 'chatelet',
        'republique', 'nation', 'oberkampf', 'marais', 'pigalle',
        'la defense', 'saint-germain', 'opera', 'sentier',
    ]
    stations = [
        'chatelet', 'gare du nord', 'gare de lyon', 'saint-lazare',
        'montparnasse', 'austerlitz', 'rer a', 'rer b', 'rer c',
        'rer d', 'rer e', 'la defense', 'nation', 'etoile',
    ]
    pays = [
        'france', 'allemagne', 'espagne', 'italie', 'belgique',
        'suisse', 'canada', 'etats-unis', 'usa', 'royaume-uni',
        'angleterre', 'japon', 'chine', 'russie', 'bresil',
    ]

    all_places = set(villes + quartiers + stations + pays)
    hits = []
    line_lower = line.lower()

    for place in all_places:
        # on check avec des word boundaries
        if re.search(r'\b' + re.escape(place) + r'\b', line_lower):
            hits.append(place)

    # codes postaux francais
    cp = re.findall(r'\b\d{5}\b', line)
    for c in cp:
        # les codes postaux vont de 01000 a 98999 en gros
        if 1000 <= int(c) <= 98999:
            hits.append(c)

    # noms de rues
    rues = re.findall(r'(?:rue|avenue|boulevard|place|impasse|passage|allée|chemin)\s+(?:de\s+(?:la\s+)?|du\s+|des\s+|d\')?[A-ZÀ-Ü][a-zà-ü]+(?:\s+[A-ZÀ-Ü][a-zà-ü]+)*', line, re.IGNORECASE)
    hits.extend(rues)

    return hits


def check_sensitive_files(line):
    # noms de fichiers sensibles mentionnes dans le texte
    fichiers = [
        'id_rsa', 'id_rsa.pub', 'id_ed25519', 'id_dsa',
        '.env', '.env.local', '.env.production',
        'passwd', 'shadow', 'htpasswd',
        '.htaccess', '.git-credentials', '.netrc',
        'wp-config.php', 'config.php', 'database.yml',
        'credentials.json', 'service-account.json',
        'keystore.jks', '.pgpass', '.my.cnf',
        'docker-compose.yml',
    ]
    hits = []
    for f in fichiers:
        if f.lower() in line.lower():
            hits.append(f)
    return hits
