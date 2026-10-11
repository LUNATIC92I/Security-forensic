# Bilan des fonctionnalités - LUNATIC MOBILE FORENSICS 0.1.0

Légende : ✅ opérationnel et testé · 🟡 partiel (limites indiquées) · 🧪 expérimental · ⛔ non disponible (volontairement ou faute de documentation)

## Opérationnel ✅
| Domaine | Détail | Tests |
|---|---|---|
| Gestion des investigations | identifiant unique `LMF-AAAA-XXXXXX`, statut, responsable, enquêteurs autorisés, autorité légale, périmètre, fuseau, historique | `test_auth_cases.py` |
| Rôles | administrateur / enquêteur / analyste / auditeur, cloisonnement par dossier | `test_auth_cases.py`, `test_api_backup_cli.py` |
| Authentification | argon2id, politique de mot de passe, verrouillage après échecs, verrouillage de session | `test_auth_cases.py` |
| Chiffrement au repos | champs sensibles Fernet, clé enveloppée par phrase secrète (scrypt + AES-GCM) | `test_core.py`, `test_auth_cases.py` |
| Import sécurisé | type réel, taille, structure, traversée, liens, bombes de décompression, XML DTD | `test_ingest_safety.py` |
| Conteneurs | ZIP, TAR(.gz/.bz2/.xz), dossiers, sauvegarde Android `.ab` (non chiffrée **ou chiffrée AES-256 avec le mot de passe fourni**), sauvegarde iOS non chiffrée (Manifest.db) | `test_ingest_safety.py`, `test_evidence.py` |
| Chaîne de conservation | SHA-256 (+MD5) source/copie, coffre en lecture seule, copies de travail, vérifications import/pré/post-analyse/manuelles, alertes, journal d'audit chaîné | `test_evidence.py`, `test_audit.py` |
| Contacts, SMS/MMS, appels, calendrier (Android & iOS) | schémas AOSP / iOS documentés, valeurs brutes vs interprétées | `test_analyzers_mobile.py` |
| Navigateurs | Chromium (historique, téléchargements, favoris, métadonnées cookies), Safari, Firefox | `test_analyzers_files.py` |
| Images/vidéos | empreintes, EXIF, GPS, MP4/MOV (date, durée, ISO 6709), aperçu sécurisé | `test_analyzers_files.py`, `test_gui.py` |
| Documents | OOXML/ODF (métadonnées + texte), PDF (métadonnées), indexation texte | `test_analyzers_files.py` |
| Géolocalisation | EXIF, Photos.sqlite, Takeout, GPX, messages ; **enregistrée vs estimée** ; carte hors ligne ; export GeoJSON/KML | tests + GUI |
| Corrélation | chronologie UTC, fuseaux, doublons, identifiants partagés, liens contacts, proximité appel/message, co-localisation, incohérences temporelles, graphe de relations ; faits ≠ hypothèses | `test_correlation.py`, `test_search_reports.py` |
| Recherche | téléphone (tout format), e-mail, nom, texte (y compris contenu chiffré), période, SHA-256 (artefacts + fichiers), type, conversation, zone GPS, pagination, traçabilité | `test_search_reports.py` |
| Rapports | PDF et HTML : couverture, périmètre, appareils, méthodes, empreintes, résultats, chronologie, graphiques, corrélations, constatations (fait/interprétation/hypothèse), limites, audit, annexes | `test_search_reports.py`, `examples/` |
| Interface | 14 pages PySide6, assistant d'import, notifications, progression, confirmations, verrouillage | `test_gui.py` |
| CLI, API locale | CLI complète ; FastAPI liée à 127.0.0.1 avec jeton | `test_api_backup_cli.py` |
| Sauvegardes chiffrées | AES-256-GCM par blocs, détection troncature/altération, restauration | `test_api_backup_cli.py` |

## Partiel 🟡
| Élément | Limite |
|---|---|
| Connecteur ADB | collecte logique sans root uniquement (propriétés, paquets, logcat, stockage partagé, fournisseurs de contenu si l'OS l'autorise). Testé avec un `adb` simulé ; **à valider sur appareils réels** du laboratoire |
| Connecteur iOS | libimobiledevice (`ideviceinfo`, `idevicebackup2`) : testé avec sorties simulées, à valider sur appareil réel ; sauvegardes chiffrées non exploitables |
| WhatsApp Android/iOS | uniquement bases **déjà en clair** (msgstore.db, ChatStorage.sqlite) ; les schémas évoluent selon les versions — à revalider à chaque version |
| Apple Notes | texte brut du protobuf ; mise en forme, pièces jointes et notes verrouillées non restituées |
| `attributedBody` iOS 16+ | décodage heuristique signalé comme tel |
| PDF | métadonnées du dictionnaire Info non compressé ; pas d'extraction de texte |
| HEIC | empreinte seulement (pilote `pillow-heif` optionnel non intégré) |
| Historique de localisation Google | formats Takeout/Timeline connus ; le format évolue |
| Journaux logcat/syslog | l'année est absente du format : année supposée et marquée comme estimée |
| Normalisation des numéros | heuristique (indicatif pays par défaut) ; valeur brute toujours conservée |

## Expérimental 🧪
| Élément | Remarque |
|---|---|
| Données résiduelles SQLite | pages libres, zones non allouées, freeblocks, WAL : fragments de texte avec décalage exact, confiance faible. Un enregistrement supprimé n'est récupérable que si les octets subsistent (inexistant si `secure_delete` ou réorganisation des pages) |
| Carving JPEG/PNG/PDF | par en-tête/pied ; fichiers fragmentés non reconstruits |

## Non disponible ⛔ (et alternative légitime)
| Élément | Raison / alternative |
|---|---|
| Extraction physique, contournement de verrouillage, exploits, root/jailbreak | exclus par conception. Alternative : importer une acquisition réalisée par un outil validé et autorisé (ZIP/TAR/dossier) |
| Sauvegardes iOS chiffrées | déchiffrement (keybag) non implémenté ; pas d'attaque de mot de passe. Alternative : sauvegarde non chiffrée réalisée avec l'autorisation du titulaire. Les sauvegardes **Android** chiffrées sont désormais prises en charge avec le mot de passe fourni (vérifié par la somme de contrôle de la clé maître, jamais stocké ; validé contre une implémentation tierce indépendante) |
| Formats propriétaires d'éditeurs tiers (UFDR, OFB, etc.) | non documentés publiquement ; non annoncés. Alternative : exports CSV/JSON/XML de ces outils via le **format d'échange LUNATIC** (`docs/exchange_format.md`) ou un plugin dédié une fois la spécification disponible |
| Telegram, Signal, Messenger, Instagram, Snapchat... | bases chiffrées (Signal SQLCipher) ou sérialisation propriétaire (Telegram) : seulement **inventoriées** ; aucune clé n'est extraite, aucun compte distant n'est accédé |
| Fond de carte | volontairement hors ligne (aucune transmission) ; export GeoJSON/KML vers un SIG validé |
| Recevabilité juridique | une empreinte prouve l'absence de modification depuis l'import, pas l'authenticité ni la recevabilité |

## Dépendances
Python ≥ 3.11 (testé 3.13), PySide6, SQLAlchemy 2, Pydantic 2, cryptography, argon2-cffi, Pillow, ReportLab, tzdata ;
optionnel : FastAPI + uvicorn (API), psycopg (PostgreSQL), PyInstaller (exécutable Windows).
Outils externes optionnels : Android platform-tools (`adb`), libimobiledevice.
Linux (GUI) : `libegl1 libgl1 libxkbcommon0 libfontconfig1`.
APScheduler n'est pas utilisé : aucune tâche planifiée n'est justifiée.

## Procédures de validation
1. `python -m pytest` → 144 tests (cœur, sécurité, import hostile, chaque analyseur, corrélation, recherche, rapports, connecteurs simulés, API, sauvegarde, CLI, GUI hors écran, non-régression).
2. `python -m pytest --cov=lunatic_forensics --cov-report=html` → rapport de couverture (≈ 91 %, GUI exclue).
3. `python scripts/generate_sample_report.py` → régénère `examples/sample_report.pdf|html`.
4. Avant usage en laboratoire : valider chaque parseur sur des jeux de référence du laboratoire (appareils de test, versions d'OS/apps), consigner les versions dans le registre des outils, calculer l'empreinte de l'exécutable, tester ADB/iOS sur appareils de test.
