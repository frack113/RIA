# RIA
Recherche Automatisée d'informations
## But
Apprendre le python.

Jouer avec du Json,XML,API WEB,RE, Sqlite, créer une class...

Complèter un bulletin du CERTFR[1] avec le plus d'informations possibles

Le code n'est donc pas propre ou bien optimisé.

Test sous :
- FEDORA 31 x64, Python 3.7.6
- WINDOWS 1903 x64, Python 3.8.1

## Actuellement
- Téléchargement automatique des CERTFR et CVE
- Lecture des bulletins CERTFR depuis archive rar [1]
- Lecture des cve depuis les json [2]
- Gestion en SQLITE3
- Liste des KB via **API** microsoft[4]
- Wrapper les sites d'éditeurs pour trouver les CVE
- Ajouter de l'aide grace aux **Mogs** (ajout manuel)
- Utilisation des Docstring PEP 257 [3]
- Sortie en Json
- Gestion des options cmd
- Commandline "--help"

## Todo
- nettoyer le code
- Ajouter au Wrapper
- ?..

## Documentation
- Doxygen
- Graphviz
- Textlive pour LATEX to PDF

## Dépendance PIP
- requests
- BeautifulSoup4

## Options lancement
- "--Verbose"			Ecrit dans le fichier log
- "--ForceWrapper"	 	Force la mise à jour du Wrapper
- "--Info" 				Information sur la BDD
- "--Uri" 				Ecrit les fichiers uri pour la recherche manuelle
- "--Json" 				Ecrit les fichiers json
- "--Text"				Ecrit les fichiers certfr modifiés en txt
- "--Last N"			Ecrit les N derniers bulletins
- "--Year XXXX"   Ecrit les bulletins de l'année XXXX 

## Références
[1]: https://www.cert.ssi.gouv.fr/
[2]: https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
[3]: https://www.python.org/dev/peps/pep-0257/
[4]: https://portal.msrc.microsoft.com/fr-fr/developer
