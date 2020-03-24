# RIA
Recherche Automatisé d'information
## But
Apprendre le python.
Jouer avec du Json,XML,API WEB.
En bonus RE, Sqlite, creer un class...

Completer le bulletin du CERTFR avec le plus d'informations possibles

Le code est donc pas propre, optimiser, voir clair.
test sous FEDORA 31 , Python 3.7.6

## Actuellement
- Telechargement automatique des CERTFR et CVE
- Lecture des bulletin CERTFR depuis archive rar
- Lecture des cve depuis les json
- Gestion en SQLITE
- Liste des KB microsoft API (fichier a part)

## Todo
- integrer l'api Microsoft
- ajouter d'autres sources
- nettoyer le code 

## Dependances
- re
- os 
- zipfile
- tarfile
- json
- datetime
- sqlite3
- hashlib
- requests
- shutil
- tqdm 
- base64
- logging