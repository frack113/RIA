## Gestion des CERTFR,CVE et CPE
# @file RIA_class.py
# @author Frack113
# @date 01/04/2020
# @brief Class pour les CERTFR,CVE et CPE
# Objet pour manipuler les des bulletins,CVE ou CPE sans passer par le sql
#

import hashlib
import base64

##
# @brief Manipulation des CERTFR
#
class C_certfr:
    """
    Class qui repressente un bulletin du CERTFR
    """

    ## The constructor.
    def __init__(self):
       ## le nom du bulletin
       self.nom=""
       ##l'objet du bulletin
       self.obj=""
       ##Date de creation du bulletin
       self.dateOrigine=""
       ##Date de modification du bulletin
       self.dateUpdate=""
       ##boolean 0 deja traité , 1 nouveau
       self.New=0
       ##Le bulletin complet
       self.file=""
       ##Clé unique
       self.crc=""
       ##Les liens dans le bulletin
       self.link=[]

    ##
    # @brief permet de remettre les variables à l'état initial
    def reset(self):
       self.nom=""
       self.obj=""
       self.dateOrigine=""
       self.dateUpdate=""
       self.New=0
       self.file=""
       self.crc=""
       self.link=[]

    ##
    # @brief Calcul le CRC pour la clée UNIQUE SQL
    def set_crc(self):
        str_hkey=f"{self.nom}_{self.dateOrigine}_{self.dateUpdate}"
        self.crc=hashlib.sha1(str_hkey.encode()).hexdigest()

    ##
    # @brief decode le fichier base64
    def decode_file(self):
        return base64.b64decode(self.file).decode()

    ##
    # @brief encode le fichier en base64
    def encode_file(self):
        return base64.b64encode(self.file.encode()).decode()

    ##
    # @brief encode les liens en base64
    # surement plus utile
    def encode_link(self):
        hyrule=[]
        for zelda in self.link:
            hyrule.append(base64.b64encode(zelda.encode()).decode())
        self.link=hyrule

    ##
    # @brief decode les liens en base64
    # surement plus utile
    def decode_link(self):
        hyrule=[]
        for zelda in self.link:
            hyrule.append(base64.b64decode(zelda).decode())
        self.link=hyrule

##
# @brief manipulation des CVE
class C_cve:

    ## The constructor.
    def __init__(self):
        ## L'id CVE
        self.id=""
        ## Le cvssV3
        self.cvssV3="NA"
        ## La note de Base cvssV3
        self.cvssV3base=0
        ## Le cvssV2
        self.cvssV2="NA"
        ## La note de base cvssV2
        self.cvssV2base=0
        ## La date de creation du CVE
        self.dateOrigine=""
        ## La date derniere modification du CVE
        self.dateUpdate=""
        ## boolean 0 deja traité , 1 nouveau
        self.New=0
        ## Clé unique
        self.crc=""

    ##
    # @brief Remet les variables à l'état initial
    def reset(self):
        self.id=""
        self.cvssV3="NA"
        self.cvssV3base=0
        self.cvssV2="NA"
        self.cvssV2base=0
        self.dateOrigine=""
        self.dateUpdate=""
        self.New=0
        self.crc=""

    ##
    # @brief Calcul le CRC pour la clée UNIQUE SQL
    def set_crc(self):
        str_hkey=f"{self.id}_{self.cvssV3}_{self.cvssV3base}_{self.cvssV2}_{self.cvssV2base}_{self.dateOrigine}_{self.dateUpdate}"
        self.crc=hashlib.sha1(str_hkey.encode()).hexdigest()

##
# @brief Manipulation CPE
class C_cpe:

    ## The constructor.
    def __init__(self):
        ## l'ID du CPE
        self.id=""
        ## Le cve de reférence
        self.cve=""
        ## Nombre de configuration
        self.conf=0
        ## Operateur OR ou AND
        self.operateur=""
        ## Si vulnerable
        #  ex Firefox sur windows firefox AND (false) Windows
        self.vulnerable=""
        ## l'URI en 2.3
        self.cpe23Uri=""
        ## Version de depart exclue
        self.versionStartExcluding=""
        ## Version de depart inclue
        self.versionStartIncluding=""
        ## Version de fin exclue
        self.versionEndExcluding=""
        ## Version de fin inclue
        self.versionEndIncluding=""
        ## boolean 0 deja traité , 1 nouveau
        self.New=0
        ##Clé unique
        self.crc=""

    ##
    # @brief Remet les variables à l'état initial
    def reset(self):
        self.id=""
        self.cve=""
        self.conf=0
        self.operateur=""
        self.vulnerable=""
        self.cpe23Uri=""
        self.versionStartExcluding=""
        self.versionStartIncluding=""
        self.versionEndExcluding=""
        self.versionEndIncluding=""
        self.New=0
        self.crc=""

    ##
    # @brief Calcul le CRC pour la clée UNIQUE SQL
    def set_crc(self):
        str_hkey=f"{self.id}_{self.cve}_{self.conf}_{self.operateur}_{self.vulnerable}_{self.cpe23Uri}_{self.versionStartExcluding}_{self.versionStartIncluding}_{self.versionEndExcluding}_{self.versionEndIncluding}"
        self.crc=hashlib.sha1(str_hkey.encode()).hexdigest()
