## La gestion de l'API Microsoft
# @file RIA_mskb.py
# @author Frack113
# @date 07/04/2020
# @brief Recherhce de CVE et KB via l'API Microsoft
# @warning la clé API est dans RIA_mskb.key
# @todo optimiser le code
# @todo peut être une class Wsus cab http://go.microsoft.com/fwlink/?linkid=74689

import requests
import json
import re
import os
from RIA_sql import *

##
# @brief Gestion API Microsoft
# @details Python help
class C_mskb:
    """ Class pour l'utilisation de l'api microsoft
    https://portal.msrc.microsoft.com/fr-fr/developer
    """

    ##
    # @brief Constructors
    # @param MaBdd un objet C_sql
    # @details Python help
    def __init__(self,MaBdd):
        """ Constructors
        Mabdd C_sql déjà initialisé
        il faut une clé API sauvegardée dans RIA_mskb.key
        crée automatiquement les tables SQL
        """
        ## la clé API
        try :
            file=open('RIA_mskb.key','r')
            key=file.readline()
            file.close()
            self.api_key=key.replace('\n','')
        except:
            self.api_key='Manque le fichier RIA_mskb.key'
        ## le type de transaction
        self.api_type='application/json'
        ## L'url API
        self.api_url='https://api.msrc.microsoft.com/updates?api-version=2017'
        ## le header
        self.header={'Accept': self.api_type,'api-key': self.api_key}
        ## La Bdd
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
         CREATE TABLE IF NOT EXISTS MS_Product (ProductID TEXT UNIQUE NOT NULL,Value text);
         CREATE TABLE IF NOT EXISTS MS_Vuln (CVE TEXT,FIX_ID TEXT UNIQUE,ProductID TEXT,URL TEXT,Supercedence TEXT,Type TEXT);
        """)

    ##
    # @brief Efface totalement les tables
    # @details Python help
    def reset_db(self):
        """ Efface toutes les tables SQL
        """
        self.MaBdd.write_sc("""
         DELETE FROM MS_Product;
         DELETE FROM MS_Vuln;
        """)

    ## recupere toutes les URL
    # @details Python help
    def update_all_url(self):
        """ Recupére toutes les url à traiter
        """
        rep= requests.get(self.api_url,headers=self.header)
        jsontmp=json.loads(rep.text)
        rep.close()
        return jsontmp['value']

    ## sauvegarde en BDD un ProductID
    # @param ProductID le nmr de ref
    # @param Value la valeur lisible
    # @details Python help
    def write_product(self,ProductID,Value):
        """ Inscrit en BDD le couple "ID:Nom en clair"
        """
        self.MaBdd.write_sc(f'INSERT OR IGNORE INTO MS_Product VALUES("{ProductID}","{Value}");')

    ## sauvegarde en BDD un cve
    # @param ms_cve le CVE corrigé
    # @param fix_id le numero de KB
    # @param product le ProductID
    # @param ms_url l'URL pour plusd'information
    # @param fix_Supercedence le KB remplacé
    # @param typekb le type de KB
    # @details Python help
    def write_cve_kb(self,ms_cve,fix_id,product,ms_url,fix_Supercedence,typekb):
        """Ecrit en BDD les information d'une CVE MS
        """
        self.MaBdd.write_sc(f'INSERT OR IGNORE INTO MS_Vuln VALUES("{ms_cve}","{fix_id}","{product}","{ms_url}","{fix_Supercedence}","{typekb}");')

    ## recupere toutes les information
    # @details Python help
    def update_all_info(self):
        """Vérifie toutes les pages d'informations
        """
        for security_update in self.update_all_url():
            url=security_update['CvrfUrl']
            rep=requests.get(url,headers=self.header)
            jsoncve=json.loads(rep.text)
            rep.close()

            if 'FullProductName' in jsoncve['ProductTree']:
                for ref in jsoncve['ProductTree']['FullProductName']:
                    self.write_product(ref["ProductID"],ref["Value"])

            if 'Vulnerability' in jsoncve:
                for data in jsoncve['Vulnerability']:
                    ms_cve=data['CVE']
                for kb in data['Remediations']:
                    if kb['Type']==2:  #2 vendor Fix
                        fix_id=kb['Description']['Value']
                    ms_url=''
                    if 'URL' in kb:
                        ms_url=kb['URL']
                    fix_Supercedence=''
                    if 'Supercedence' in kb:
                        fix_Supercedence=kb['Supercedence']
                    typekb=''
                    if 'SubType' in kb:
                        typekb=kb['SubType']
                        for product in kb['ProductID']:
                            self.write_cve_kb(ms_cve,fix_id,product,ms_url,fix_Supercedence,typekb)

    ## Cherche les information pour un CERTFR
    # @param certfr le nom du CERTFR
    # @details Python help
    def get_info_certfr(self,certfr):
        """Revoie une liste pour un nom de bulletin données
        certfr est une string avec le nom à chercher
        """
        return self.MaBdd.get_sc(f'select CVE,Value,FIX_ID,Url,type from MS_vuln left JOIN MS_Product ON MS_vuln.ProductID=MS_Product.ProductID WHERE MS_vuln.CVE IN (SELECT CVE from CERTFR_cve WHERE BULTIN="{certfr}");')

    ## Verifie la mise a jour
    # @param date la date "YYYYMMDD" a verifier
    # @return String d'information
    # @details Python help
    def Check_Mskb_Update(self,date):
        """Verifie s'il y des mise à jour par API
        """
        if self.api_key=='Manque le fichier RIA_mskb.key':
            return (self.api_key)
        else:
            if self.MaBdd.get_Info_date("Microsoft")==date:
                    return ("Microsoft déjà à jour")
            else:
                self.update_all_info()
                self.MaBdd.set_Info_date("Microsoft",date)
                return ("Microsoft mise à jour")
