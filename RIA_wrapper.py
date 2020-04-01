## La gestion des wrapper Internet
# @file RIA_wrapper.py
# @author Frack113
# @date 01/04/2020
# @brief Class pour les recherches Internet
#
# @todo Replacer info[] par un objet

import requests
import re
from bs4 import BeautifulSoup
import json

from RIA_sql import *

##Class pour le Wrapper
class C_wrapper:

    ## constructors
    # @param MaBdd C_sql
    def __init__(self,MaBdd):
        ##la MaBdd
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
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
    def check_update(self,url):
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

    ## Verifie si l'url existe deja dan sla MaBdd
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
        info[1]=self.check_update(info[0])
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
                    date=self.check_update(full_url)
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
