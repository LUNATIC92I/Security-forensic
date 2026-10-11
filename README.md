# LUNATIC MOBILE FORENSICS

Plateforme de **criminalistique numérique mobile** en Python, locale par défaut, destinée aux laboratoires,
équipes SOC, services d'investigation autorisés et consultants en réponse aux incidents.

> Usage réservé aux investigations **légalement autorisées**. Le logiciel n'implémente aucun contournement de
> verrouillage, aucune exploitation, aucune extraction clandestine ni neutralisation de protections.
> Il ne présente jamais une collecte logique comme une extraction physique.

![tests](https://img.shields.io/badge/tests-144%20passed-2f8cff) ![coverage](https://img.shields.io/badge/coverage-91%25-2f8cff)

## Fonctionnalités principales
- **Investigations** : identifiants uniques, statuts, responsable, enquêteurs autorisés, autorité légale, périmètre, historique.
- **Rôles** administrateur / enquêteur / analyste / auditeur, cloisonnement des dossiers, verrouillage de session.
- **Import sécurisé** : détection du type réel, contrôle de structure, protection traversée / bombes / liens / XML, plugins
  (ZIP, TAR, dossiers, sauvegarde Android `.ab` (y compris chiffrée, avec le mot de passe fourni), sauvegarde iOS non chiffrée, fichiers isolés).
- **Chaîne de conservation** : SHA-256 avant/après, coffre en lecture seule, copies de travail, journal d'audit chaîné et vérifiable.
- **Analyse** (32 analyseurs) : contacts, SMS/MMS/iMessage, appels, calendrier, notes, navigateurs, WhatsApp (bases en clair),
  médias (EXIF/GPS, MP4), documents, géolocalisation (enregistrée vs estimée), journaux, inventaire des applications,
  **données résiduelles et carving (expérimental)**.
- **Corrélation** : chronologie UTC multi-sources, périodes d'activité, doublons, incohérences temporelles, graphe de relations ;
  chaque corrélation cite ses artefacts et distingue **faits** et **hypothèses**.
- **Recherche** combinable et paginée, traçable jusqu'au fichier / table / ligne d'origine.
- **Rapports PDF et HTML** (voir [`examples/sample_report.pdf`](examples/sample_report.pdf)).
- **Acquisition autorisée** : ADB (sans root) et libimobiledevice (appairage, service de sauvegarde officiel).
- **Interface PySide6** sombre (noir, graphite, argent, bleu électrique), CLI complète, API locale optionnelle.

## Téléchargement Windows (un clic)
**[⬇ LunaticMobileForensics.exe](https://github.com/LUNATIC92I/Security-forensic/releases/download/v0.1.0/LunaticMobileForensics.exe)**
(Windows 10/11 64 bits, aucune installation, ~70 Mo) — empreinte dans
[SHA256SUMS.txt](https://github.com/LUNATIC92I/Security-forensic/releases/download/v0.1.0/SHA256SUMS.txt),
page de la version : [v0.1.0](https://github.com/LUNATIC92I/Security-forensic/releases/tag/v0.1.0).
Double-cliquez : au premier lancement, créez le compte administrateur. L'exécutable n'est pas signé :
SmartScreen peut afficher « Windows a protégé votre ordinateur » → *Informations complémentaires* → *Exécuter quand même*.
Auto-test : `LunaticMobileForensics.exe self-test --output resultat.txt`. L'exe est reconstruit, testé sous Windows
et republié automatiquement par GitHub Actions (`.github/workflows/build-windows.yml`).

## Installation depuis les sources
```bash
# Linux / macOS
./scripts/install.sh
export LUNATIC_MASTER_PASSPHRASE='une phrase secrète longue'   # recommandé
./scripts/run.sh                 # interface graphique (le 1er lancement crée l'administrateur)
```
```powershell
# Windows
scripts\install.ps1
scripts\run.bat
scripts\build_windows.ps1        # exécutable autonome (PyInstaller)
```
Manuel : `pip install -e ".[api,dev]"` puis `python -m lunatic_forensics gui`.

## Démarrage rapide (données synthétiques)
```bash
python -m lunatic_forensics demo-data ./demo            # jeu de données 100 % fictif
python -m lunatic_forensics --home ./lab init --admin admin
python -m lunatic_forensics --home ./lab --user admin case-create "Démo" --timezone Europe/Paris
python -m lunatic_forensics --home ./lab --user admin import 1 ./demo/ios_backup_00008110 --analyze
python -m lunatic_forensics --home ./lab --user admin search 1 --phone "06 39 98 00 01"
python -m lunatic_forensics --home ./lab --user admin report 1 --format pdf
```

## Tests
```bash
python -m pytest                                   # 144 tests, aucune donnée réelle
python -m pytest --cov=lunatic_forensics --cov-report=html
```

## Documentation
| Document | Contenu |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | **Bilan** : opérationnel / partiel / expérimental / non disponible, dépendances, validation |
| [docs/architecture.md](docs/architecture.md) | architecture, flux, points d'extension, base de données |
| [docs/technical.md](docs/technical.md) | sécurité, configuration, décodage des dates, liste des parseurs, tests |
| [docs/user_guide.md](docs/user_guide.md) | guide utilisateur (GUI et CLI) |
| [docs/exchange_format.md](docs/exchange_format.md) | format d'échange documenté pour importer des exports tiers |

## Structure
```
lunatic_forensics/
  core/         configuration, sécurité, RBAC, temps, empreintes, normalisation
  storage/      modèles SQLAlchemy, colonnes chiffrées, migrations
  ingest/       sécurité d'import + plugins de conteneurs
  analyzers/    moteurs d'analyse par catégorie / application
  correlation/  moteur de corrélation (fonctions pures)
  services/     services métier (auth, dossiers, preuves, analyse, recherche, rapports, audit, sauvegarde)
  acquisition/  connecteurs ADB et iOS autorisés
  reports/      génération HTML / PDF
  api/          API locale FastAPI (127.0.0.1)
  gui/          application PySide6
  synthetic.py  générateur de données de test fictives
tests/          suite pytest     docs/  documentation     scripts/  installation, lancement, build
packaging/      spécification PyInstaller     examples/  rapport d'exemple
```

## Limites importantes
Voir [docs/STATUS.md](docs/STATUS.md). En résumé : pas d'extraction physique ni de déchiffrement des sauvegardes iOS chiffrées ;
formats propriétaires tiers non pris en charge sans spécification (passer par le format d'échange) ; connecteurs
ADB/iOS testés en simulation et à valider sur appareils de test ; module de récupération expérimental ; une empreinte
SHA-256 ne suffit pas à établir l'authenticité ou la recevabilité juridique d'une preuve.
