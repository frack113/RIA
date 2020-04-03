## La gestion des wrapper Internet
# @file RIA_wrapper.py
# @author Frack113
# @date 03/04/2020
# @brief module pour les recherches Internet
#
# @todo traiter les New

import requests
import re
from bs4 import BeautifulSoup
import json
import copy
import os
import shutil

from RIA_sql import *

##
# @brief Class Objet info Wrapper
class C_wrapper_info:
    def __init__(self):
        self.Url=""
        self.Fichier=""
        self.Taille=0
        self.Rep=""
        self.Date=""
        self.Regex=""
        self.S_Url=""
        self.Module=""
        self.New=0

##
# @brief Class pour le Wrapper
class C_wrapper:

    ## constructors
    # @param MaBdd C_sql
    def __init__(self,MaBdd):
        ##la Bdd via C_sql
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
          CREATE TABLE IF NOT EXISTS URL_info (Url TEXT UNIQUE,Fichier TEXT,rep TEXT,Taille INTEGER,Date TEXT,Regex TEXT,Surl TEXT,Module TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS URL_cve (Url TEXT UNIQUE,CVE TEXT,Date TEXT,New INTEGER);
        """)

    ##
    # @brief remet a 0 le champ New
    # 
    def Reset_New(self):
        self.MaBdd.write_sc('UPDATE URL_info SET New=0;')


#
#                         Partie Fonction interne
#

    ##
    # @brief Sauvegarde tous les couples Url/CVE trouvés
    # @todo traite les New
    def Flush_cve(self):
        wrap_cve=self.MaBdd.get_sc('SELECT Nom,CVE FROM CERTFR_Url JOIN URL_cve WHERE CERTFR_Url.Url=URL_cve.Url;')
        for w_cve in wrap_cve:
            self.MaBdd.write_certfr_cve(w_cve[0],w_cve[1])

    ##
    # @brief Sauvegarde dans URL_ck
    # @param info liste
    def write_url_cve(self,info):
        self.MaBdd.write_sc(f'INSERT OR REPLACE INTO URL_cve VALUES("{info[0]}","{info[1]}","{info[2]}",1)')

    ##
    # @brief Sauvegarde en BDD un objet C_wrapper_info
    # @param info C_wrapper_info
    def Write_wrapper_info(self,info):
        self.MaBdd.write_sc(f'''INSERT OR REPLACE INTO URL_info VALUES(
         "{info.Url}",
         "{info.Fichier}",
         "{info.Rep}",
          {info.Taille},
         "{info.Date}",
         "{info.Regex}",
         "{info.S_Url}",
         "{info.Module}",
          {info.New});''')

    ##
    # @brief Lit en BDD des objet C_wrapper_info
    # @param Champ le champ a chercher
    # @param value la valeur a chercher
    # @param strict pour recherche sql True: =  sinon like "%%"
    # @param New True ajoute " AND New=1;" a la recherche sql
    # @return Une liste de C_wrapper_info
    def Read_wrapper_info(self,Champ,value,strict,New):
        l_info=[]
        info=C_wrapper_info()
        if strict== True:
            if type(value) is str:
                sql=f'SELECT * FROM URL_info WHERE {Champ}="{value}"'
            else:
                sql=f'SELECT * FROM URL_info WHERE {Champ}={value}'
        else:
            sql=f'SELECT * FROM URL_info WHERE {Champ} LIKE "%{value}%"'
        if New==True:
            sql=sql+" AND New=1;"
        else:
            sql=sql+";"
        reponses=self.MaBdd.get_sc(sql)
        for reponse in reponses:
            info.Url=reponse[0]
            info.Fichier=reponse[1]
            info.Rep=reponse[2]
            info.Taille=reponse[3]
            info.Date=reponse[4]
            info.Regex=reponse[5]
            info.S_Url=reponse[6]
            info.Module=reponse[7]
            info.New=reponse[8]
            l_info.append(copy.copy(info))
        return l_info

    ##
    # @brief Télécharge un fichiers si plus récent
    # @param info C_wrapper_info
    def Url_down_file(self,info):
        r_file = requests.head(info.Url)
        if r_file.headers['last-modified']==info.Date:
            download=False
        else:
            if not os.path.exists(info.Rep) and info.Rep>"":
                os.mkdir(info.Rep)
            r_file = requests.get(info.Url, stream=True)
            info.Date=r_file.headers['last-modified']
            info.Taille=r_file.headers['content-length']
            info.New=1
            with open(info.Rep + info.Fichier, 'wb') as f:
                shutil.copyfileobj(r_file.raw, f)
            self.Write_wrapper_info(info)
        r_file.close()    

    ##
    # @brief Verifie si le header de la page distante est plus recent
    # @param info le C_wrapper_info a verifier
    # @return Boolean 
    def Url_is_updated(self,info):
        h_web=requests.head(info.Url)
        date=h_web.headers['Last-Modified']
        h_web.close()
        reponse=self.Read_wrapper_info("Url",info.Url,True,False)
        if reponse :
            if date==reponse[0].Date:
                return False
            else:
                return True
        else:
            return True  #existe pas donc nouvelle url :)

    ##
    # @brief Parse une url en regex
    # @param info Un C_wrapper_info
    def check_regex(self,info):
        if self.Url_is_updated(info):
            r_web= requests.get(info.Url)
            info.Date=r_web.headers['Last-Modified']
            info.New=1
            self.Write_wrapper_info(info)
            l_info=copy.copy(info)
            feed=re.findall(info.Regex,r_web.text)
            for url in feed:
                full_url=info.S_Url+url
                if full_url[-1]=='/':
                    pass #rien a faire
                else:
                    full_url=full_url+'/'
                l_info.Url=full_url
                c_info=self.Read_wrapper_info("Url",full_url,True,False)
                if c_info:
                    pass #sous page deja traitée
                else:
                    feed_web=requests.get(full_url)
                    l_info.Date=feed_web.headers['Last-Modified']
                    self.Write_wrapper_info(l_info)
                    all_cve=re.findall('CVE-\d+-\d+',feed_web.text)
                    c_info=[full_url,"",l_info.Date]
                    for cve in all_cve:
                        c_info[1]=cve
                        self.write_url_cve(c_info)
                    feed_web.close()
            r_web.close()

#
#                   Partie wrapper une fonction par editeur
#
    ##
    # @brief Télécharge les Tar CERTFR si plus récent
    # @param EndDate l'année de fin int(YYYY)
    def Check_Certfr(self,EndDate):
        info=C_wrapper_info()
        for annee in range(2000,EndDate+1):
            fichier=str(annee)+".tar"
            l_info=self.Read_wrapper_info("Fichier",fichier,True,False)
            if l_info:
                info=l_info[0]
            else:
                info.Module="CERTFR"
                info.Rep="certfr/"
                info.Fichier=fichier
                info.Url="https://www.cert.ssi.gouv.fr/tar/"+fichier 
            self.Url_down_file(info)

    ##
    # @brief Télécharge les ZIP CVE NIST si plus récent
    # 
    def Check_CVE(self):
        info=C_wrapper_info()
        r_feed = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
        feed=re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r_feed.text)
        for fichier in feed:
            l_info=self.Read_wrapper_info("Fichier",fichier,True,False)
            if l_info:
                info=l_info[0]
            else:
                info.Module="CVE"
                info.Rep="nvd/"
                info.Fichier=fichier
                info.Url="https://nvd.nist.gov/feeds/json/cve/1.1/"+fichier 
            self.Url_down_file(info)
        r_feed.close()    

    ##
    # @brief Verifie les release de la page about.gitlab.com
    #          
    def Check_Gitlab(self):
        inf=C_wrapper_info()
        inf.Url='https://about.gitlab.com/releases/categories/releases/'
        inf.Module="Gitlab"
        inf.Regex=r'<a class=cover href=\'(/releases/\d{4}/\d{2}/\d{2}/.*-released/)\''
        inf.S_Url='https://about.gitlab.com'
        self.check_regex(inf) 

    ##
    # @brief Verifie les release de la page https://usn.ubuntu.com/months/
    #
    def Check_Ubuntu(self):
        inf=C_wrapper_info()
        inf.Url='https://usn.ubuntu.com/months/'
        inf.Module='Ubuntu'
        inf.Regex=r'https://usn.ubuntu.com/\d+-\d+/'
        self.check_regex(inf)

    ##
    # @brief Verifie Kaspersky
    #
    def Check_Kaspersky(self):
        base_url='https://support.kaspersky.com/general/vulnerability.aspx?el=12430'
        inf=C_wrapper_info()
        inf.Url=base_url
        inf.Module='Kaspersky'
        inf.New=1
        r_web=requests.get(inf.Url)
        inf.Date=r_web.headers['Date']
        self.Write_wrapper_info(inf)
        soup=BeautifulSoup(r_web.text,'html.parser')
        for div in soup.findAll("div",class_="wincont_c3"):
            F_open=div.findAll(attrs={"class":"open"})
            F_cve=div.findAll(string=re.compile("CVE"))
            if F_open:
                l_url=re.findall(r'href="(.*)" id',str(F_open))
                inf.Url=base_url+l_url[0]
                self.Write_wrapper_info(inf)
                all_cve=re.findall(r'CVE-\d+-\d+',str(F_cve))
                c_info=[inf.Url,"",inf.Date]
                for cve in all_cve:
                    c_info[1]=cve
                    self.write_url_cve(c_info)
        r_web.close()

    ##
    # @brief Verifie Xen
    #
    def Check_Xen(self):
        inf=C_wrapper_info()
        inf.Url='http://xenbits.xen.org/xsa/xsa.json'
        inf.Module='Xen'
        inf.New=1
        r_web=requests.get(inf.Url)
        inf.Date=r_web.headers['Last-Modified']
        self.Write_wrapper_info(inf)
        r_json=json.loads(r_web.text)
        for node in r_json[0]['xsas']:
            ref=node['xsa']
            inf.Url="http://xenbits.xen.org/xsa/advisory-"+str(ref)+".html"
            if 'cve' in node:
                all_cve=node['cve']
            else:
                all_cve=[]
            self.Write_wrapper_info(inf)
            c_info=[inf.Url,"",inf.Date]
            for cve in all_cve:
                c_info[1]=cve
                self.write_url_cve(c_info)
                
    ##
    # Vérifie tous les editeurs en une seule fonction
    # @param date la date "YYYYMMDD" a verifier
    def Check_ALL_Wapper_Update(self,date):
        if self.MaBdd.get_Info_date("Gitlab")== date:
            pass
        else:
            self.Check_Gitlab()
            self.MaBdd.set_Info_date("Gitlab",date)

        if self.MaBdd.get_Info_date("Ubuntu")== date:
            pass
        else:
            self.Check_Ubuntu()
            self.MaBdd.set_Info_date("Ubuntu",date)

        if self.MaBdd.get_Info_date("Kaspersky")== date:
            pass
        else:
            self.Check_Kaspersky()
            self.MaBdd.set_Info_date("Kaspersky",date)

        if self.MaBdd.get_Info_date("Xen")== date:
            pass
        else:
            self.Check_Xen()
            self.MaBdd.set_Info_date("Xen",date)
