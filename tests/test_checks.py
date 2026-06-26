import pytest
from opsec_lint.checks import (
    check_emails, check_phones, check_iban, check_paths,
    check_timezones, check_ips, check_api_keys, check_geo,
    check_sensitive_files,
)


# --- emails ---

def test_email_basic():
    assert check_emails("contacte moi à jean.dupont@gmail.com stp")

def test_email_none():
    assert check_emails("salut tout le monde") == []

def test_email_multiple():
    hits = check_emails("envoie a foo@bar.com et baz@qux.org")
    assert len(hits) == 2


# --- telephones ---

def test_phone_fr_mobile():
    assert check_phones("appelle moi au 06 12 34 56 78")

def test_phone_fr_intl():
    assert check_phones("mon num: +33 6 12 34 56 78")

def test_phone_none():
    assert check_phones("pas de numero ici") == []


# --- iban / cb ---

def test_iban_fr():
    assert check_iban("mon IBAN: FR7630006000011234567890189")

def test_cb():
    assert check_iban("ma carte: 4970 1012 3456 7890")

def test_iban_none():
    assert check_iban("juste du texte normal") == []


# --- paths ---

def test_path_windows():
    assert check_paths(r"le fichier est dans C:\Users\music\projet\truc.py")

def test_path_linux():
    assert check_paths("regarde /home/music/scripts/hack.sh")

def test_path_home():
    assert check_paths("ma config est dans ~/.config/nvim")

def test_path_none():
    assert check_paths("rien de special ici") == []


# --- timezones ---

def test_timezone_fr():
    assert check_timezones("il est 3h du mat et je code encore")

def test_timezone_en():
    assert check_timezones("i was up at 2:30 AM coding")

def test_timezone_utc():
    assert check_timezones("le serveur est en UTC+2")

def test_timezone_none():
    assert check_timezones("je code beaucoup") == []


# --- ips ---

def test_ip_basic():
    assert check_ips("le serveur est sur 192.168.1.1")

def test_ip_public():
    assert check_ips("mon IP: 85.123.45.67")

def test_ip_invalid():
    assert check_ips("999.999.999.999") == []

def test_ip_none():
    assert check_ips("pas d'IP ici") == []


# --- api keys ---

def test_api_key_stripe():
    assert check_api_keys("sk_live_abc123def456ghi789jkl012mno")

def test_api_key_github():
    assert check_api_keys("mon token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234")

def test_api_key_aws():
    assert check_api_keys("AKIAIOSFODNN7EXAMPLE")

def test_api_key_generic():
    assert check_api_keys("api_key=abcdef1234567890abcdef")

def test_api_key_none():
    assert check_api_keys("du texte normal sans cle") == []


# --- geo ---

def test_geo_ville():
    assert check_geo("je suis a Paris en ce moment")

def test_geo_station():
    assert check_geo("j'ai pris le RER A a la defense")

def test_geo_code_postal():
    assert check_geo("j'habite dans le 75013")

def test_geo_rue():
    hits = check_geo("rdv au 12 rue de la Paix")
    assert hits

def test_geo_none():
    assert check_geo("rien a voir avec un lieu") == []


# --- fichiers sensibles ---

def test_sensitive_id_rsa():
    assert check_sensitive_files("j'ai copié mon id_rsa sur le serveur")

def test_sensitive_env():
    assert check_sensitive_files("check le fichier .env pour les creds")

def test_sensitive_none():
    assert check_sensitive_files("un fichier texte normal") == []


# --- test du scanner complet ---

def test_scanner_integration():
    from opsec_lint.scanner import scan_text
    text = """salut les gars
je suis a Paris et il est 3h du mat
envoyez moi un mail a test@example.com
mon serveur est sur 192.168.1.42
"""
    results = scan_text(text)
    types = [r['type'] for r in results]
    assert 'GEO' in types
    assert 'TIMEZONE' in types
    assert 'EMAIL' in types
    assert 'IP' in types


def test_scanner_level_filter():
    from opsec_lint.scanner import scan_text
    text = "je suis a Paris et mon mail est test@example.com"
    # GEO est low, EMAIL est high
    results = scan_text(text, min_level='high')
    types = [r['type'] for r in results]
    assert 'EMAIL' in types
    assert 'GEO' not in types
