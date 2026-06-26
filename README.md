# opsec-lint

Un linter OPSEC en ligne de commande qui analyse un texte avant publication et détecte les fuites d'informations personnelles involontaires.

L'idée est simple : avant de poster un message sur un forum, un Discord ou n'importe où en ligne, on passe le texte dans opsec-lint et il signale tout ce qui pourrait compromettre l'anonymat de l'auteur.

## Détections supportées

L'outil scanne un fichier texte (ou un pipe stdin) et détecte :

- **Timezone** — les mentions d'heure qui révèlent ton fuseau horaire
- **Géolocalisation** — villes, stations de métro, quartiers, codes postaux, pays
- **Chemins système** — `C:\Users\...`, `/home/...`, `~/.config/...`
- **Emails** — adresses email
- **Téléphones** — numéros FR et internationaux
- **IBAN / CB** — numéros IBAN et cartes bancaires
- **Clés API** — tokens Stripe, GitHub, AWS, etc.
- **Fichiers sensibles** — mentions de `id_rsa`, `.env`, `passwd`, etc.
- **Adresses IP** — IPv4 publiques et privées

## Installation

```bash
git clone <repo-url>
cd opsec-lint
pip install -e .
```

## Utilisation

```bash
# scanner un fichier
python -m opsec_lint scan message.txt

# scanner depuis stdin
echo "rdv au café place de la bastille à 14h" | python -m opsec_lint scan -

# filtrer par sévérité
python -m opsec_lint scan --level medium message.txt
```

Les niveaux de sévérité : `low`, `medium`, `high`, `critical`.

## Exemple

```
$ python -m opsec_lint scan samples/example.txt

  opsec-lint v0.1.0

  [!] ligne 3 : TIMEZONE — mention d'heure détectée
      "... il est 3h du mat et je suis encore dessus ..."

  [!] ligne 7 : GEO — nom de lieu détecté
      "... Le RER A à Versailles était en panne ..."

  [!] ligne 12 : PATH — chemin système détecté
      "... le fichier est dans C:\Users\music\projet\config.yml ..."

  ---
  4 problèmes trouvés (1 timezone, 1 geo, 1 path, 1 email)
  Pense à nettoyer avant de poster !
```

## Tests

```bash
pip install pytest
pytest
```

## Exit codes

- `0` — aucun problème trouvé
- `1` — erreur (fichier introuvable, etc.)
- `2` — des fuites OPSEC ont été détectées
