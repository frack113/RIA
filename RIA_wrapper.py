## La gestion des wrapper Internet
# @file RIA_wrapper.py
# @author Frack113
# @date 01/04/2020
# @brief Class pour les recherches Internet
#
# @todo Replacer info[] par un objet
# @todo traiter les New

import requests
import re
from bs4 import BeautifulSoup
import json
import copy
import os
import shutil

from RIA_sql import *

##Class Objet info Wrapper
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

##Class pour le Wrapper
class C_wrapper:

    ## constructors
    # @param MaBdd C_sql
    def __init__(self,MaBdd):
        ##la MaBdd
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
          CREATE TABLE IF NOT EXISTS URL_info (Url TEXT UNIQUE,Fichier TEXT,rep TEXT,Taille INTEGER,Date TEXT,Regex TEXT,Surl TEXT,Module TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS URL_ck (Url TEXT UNIQUE,Date TEXT,Mod TEXT);
          CREATE TABLE IF NOT EXISTS URL_cve (Url TEXT UNIQUE,CVE TEXT,Date TEXT);
        """)

    ##Sauvegarde dans URL_ck
    # @param info liste
    def write_url_ck(self,info):
        self.MaBdd.write_sc(f'INSERT OR REPLACE INTO URL_ck VALUES("{info[0]}","{info[1]}","{info[2]}")')

    ##Sauvegarde dans URL_ck
    # @param info liste
    def write_url_cve(self,info):
        self.MaBdd.write_sc(f'INSERT OR REPLACE INTO URL_cve VALUES("{info[0]}","{info[1]}","{info[2]}")')

    ##Sauvegarde tous les couples Url/CVE trouvés
    def Flush_cve(self):
        wrap_cve=self.MaBdd.get_sc('SELECT Nom,CVE FROM CERTFR_Url JOIN URL_cve WHERE CERTFR_Url.Url=URL_cve.Url;')
        for w_cve in wrap_cve:
            self.MaBdd.write_certfr_cve(w_cve[0],w_cve[1])

    ## Verifie si la page distante est plus recente
    # @param url L'URL a vérifier
    def check_url_update(self,url):
        h_web=requests.head(url)
        date=h_web.headers['Last-Modified']
        row=self.MaBdd.get_sc(f'SELECT Date FROM URL_ck WHERE Url="{url}"')
        if row :
            if date==row[0]:
                return None
            else:
                return date
        else:
            return date

    ## Verifie si l'url existe deja dans la MaBdd
    # @param url L'URL a vérifier
    def Url_exist(self,url):
        row=self.MaBdd.get_sc(f'SELECT Date FROM URL_ck WHERE Url="{url}"')
        if row:
            return True
        else:
            return False

    ## Parse une url en regex
    # @param info liste
    def check_regex(self,info):
        info[1]=self.check_url_update(info[0])
        if info[1]:
            r_web= requests.get(info[0])
            self.write_url_ck(info)
            feed=re.findall(info[3],r_web.text)
            for url in feed:
                full_url=info[4]+url
                if full_url[-1]=='/':
                    pass #rien a faire
                else:
                    full_url=full_url+'/'
                if self.Url_exist(full_url):
                    pass #sous page deja traitée
                else:
                    date=self.check_url_update(full_url)
                    l_info=[full_url,date,info[2]]
                    self.write_url_ck(l_info)
                    feed_web=requests.get(full_url)
                    all_cve=re.findall('CVE-\d+-\d+',feed_web.text)
                    c_info=[full_url,"",date]
                    for cve in all_cve:
                        c_info[1]=cve
                        self.write_url_cve(c_info)
                    feed_web.close()
            r_web.close()

    ## Verifie Gitlab
    def check_Gitlab(self):
        inf=C_wrapper_info()
        inf.Url='https://about.gitlab.com/releases/categories/releases/'
        inf.Module="Gitlab"
        inf.Regex=r'<a class=cover href=\'(/releases/\d{4}/\d{2}/\d{2}/.*-released/)\''
        inf.S_Url='https://about.gitlab.com'

        info=['https://about.gitlab.com/releases/categories/releases/','date','Gitlab',r'<a class=cover href=\'(/releases/\d{4}/\d{2}/\d{2}/.*-released/)\'','https://about.gitlab.com']
        self.check_regex(info)

    ##Verifie Ubuntu
    def check_Ubuntu(self):
        info=['https://usn.ubuntu.com/months/','date','Ubuntu',r'https://usn.ubuntu.com/\d+-\d+/','']
        self.check_regex(info)

    ##Verifie Kaspersky
    def check_Kaspersky(self):
        info=['https://support.kaspersky.com/general/vulnerability.aspx?el=12430','date','Kaspersky']
        r_web=requests.get(info[0])
        info[1]=r_web.headers['Date']
        self.write_url_ck(info)
        soup=BeautifulSoup(r_web.text,'html.parser')
        for div in soup.findAll("div",class_="wincont_c3"):
            F_open=div.findAll(attrs={"class":"open"})
            F_cve=div.findAll(string=re.compile("CVE"))
            l_info=["",info[1],info[2]]
            if F_open:
                l_url=re.findall(r'href="(.*)" id',str(F_open))
                full_url=info[0]+l_url[0]
                l_info[0]=full_url
                self.write_url_ck(l_info)
                all_cve=re.findall(r'CVE-\d+-\d+',str(F_cve))
                c_info=[full_url,"",info[1]]
                for cve in all_cve:
                    c_info[1]=cve
                    self.write_url_cve(c_info)
        r_web.close()

    ## Verifie Xen
    def check_Xen(self):
       info=['http://xenbits.xen.org/xsa/xsa.json','date','Xen']
       r_web=requests.get(info[0])
       info[1]=r_web.headers['Last-Modified']
       self.write_url_ck(info)
       r_json=json.loads(r_web.text)
       for node in r_json[0]['xsas']:
           ref=node['xsa']
           full_url="http://xenbits.xen.org/xsa/advisory-"+str(ref)+".html"
           if 'cve' in node:
               all_cve=node['cve']
           else:
               all_cve=[]
           l_info=[full_url,info[1],info[2]]
           self.write_url_ck(l_info)
           c_info=[full_url,"",info[1]]
           for cve in all_cve:
               c_info[1]=cve
               self.write_url_cve(c_info)

    ##
    # Vérifie tous les editeurs en une seule fonction
    # @param date la date "YYYYMMDD" a verifier
    def Check_Wapper_Update(self,date):
        if self.MaBdd.get_Info_date("Gitlab")== date:
            pass
        else:
            self.check_Gitlab()
            self.MaBdd.set_Info_date("Gitlab",date)

        if self.MaBdd.get_Info_date("Ubuntu")== date:
            pass
        else:
            self.check_Ubuntu()
            self.MaBdd.set_Info_date("Ubuntu",date)

        if self.MaBdd.get_Info_date("Kaspersky")== date:
            pass
        else:
            self.check_Kaspersky()
            self.MaBdd.set_Info_date("Kaspersky",date)

        if self.MaBdd.get_Info_date("Xen")== date:
            pass
        else:
            self.check_Xen()
            self.MaBdd.set_Info_date("Xen",today)

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
    # @brief Sauvegarde en BDD un objet C_wrapper_info
    # @param Champ le champ a chercher
    # @param value la valeur a chercher
    # @param strict pour recherche sql 1: =  sinon like "%%"
    # @return Un C_wrapper_info
    def Read_wrapper_info(self,Champ,value,strict):
        l_info=[]
        info=C_wrapper_info()
        if strict==1:
            if type(value) is str:
                sql=f'SELECT * FROM URL_info WHERE {Champ}="{value}";'
            else:
                sql=f'SELECT * FROM URL_info WHERE {Champ}={value};'
        else:
            sql=f'SELECT * FROM URL_info WHERE {Champ} LIKE "%{value}%";'
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
    # @brief Télécharge les Tar CERTFR si plus récent
    # @param EndDate l'année de fin int(YYYY)
    def Check_Certfr(self,EndDate):
        info=C_wrapper_info()
        for annee in range(2000,EndDate+1):
            fichier=str(anne)+".tar"
            l_info=self.Read_wrapper_info("Fichier",fichier,1)
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
            l_info=self.Read_wrapper_info("Fichier",fichier,1)
            if l_info:
                info=l_info[0]
            else:
                info.Module="CVE"
                info.Rep="nvd/"
                info.Fichier=fichier
                info.Url="https://nvd.nist.gov/feeds/json/cve/1.1/"+fichier 
            self.Url_down_file(info)
        r_feed.close()    
          
   
