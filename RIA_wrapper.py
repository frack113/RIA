## La gestion des wrapper Internet
# @file RIA_wrapper.py
# @author Frack113
# @date 06/04/2020
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
import zipfile
import tarfile


from RIA_sql import *

##
# @brief Class Objet info Wrapper
# @details Python help
class C_wrapper_info:
    """Objet pour manipuler les information sans passer par des listes
    """

    ##
    # @brief le constructor
    # @details Python help
    def __init__(self):
        """constructor
        """
        ## L'url
        self.Url=""
        ## Le fichier sert pour les CVE et CERTFR
        self.Fichier=""
        ## La taille du fichier sans emploi maintenant
        self.Taille=0
        ## Le sous répertoire de sauvegarde du fichier
        self.Rep=""
        ## Date de référence
        self.Date="date"
        ## la Regex de recherche de lien dans la page
        self.Regex=""
        ## le prefix a ajouter aux liens trouvés
        self.S_Url=""
        ## Quelle fonction fait la recherche
        self.Module=""
        ## Boolean Sqlite si nouveau
        self.New=0

##
# @brief Class pour le Wrapper
# @details Python help
class C_wrapper:
    """Class pour le Data mining Internet
    """

    ## constructors
    # @param MaBdd C_sql
    # @details Python help
    def __init__(self,MaBdd):
        """le constructor
        MaBdd est un C_sql déjà ouvert
        On ajoute les tables SQL spécifiques
        Url est UNIQUE pour géré les conflits d'INSERT
        """
        ##la Bdd via C_sql
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
          CREATE TABLE IF NOT EXISTS URL_info (Url TEXT UNIQUE,Fichier TEXT,rep TEXT,Taille INTEGER,Date TEXT,Regex TEXT,Surl TEXT,Module TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS URL_cve (Url TEXT UNIQUE,cve_id TEXT,Date TEXT,New INTEGER);
        """)

    ##
    # @brief remet a 0 le champ New
    # @details Python help
    def Reset_New(self):
        """Met a 0 le champ New en BDD
        """
        self.MaBdd.write_sc('UPDATE URL_info SET New=0;')


#
#                         Partie Fonction interne
#

    ##
    # @brief Sauvegarde tous les couples Url/CVE trouvés
    # @todo traite que les New
    # @details Python help
    def Flush_cve(self):
        """Transfert de la table TMP vers la table normale
        Selectionne tous les nom_bulletin et CVE où l'URL est commune aux deux tables
        Ajoute ensuite ces informations dans la liste officiel via write_certfr_cve
        """
        wrap_cve=self.MaBdd.get_sc('SELECT Nom,cve_id FROM CERTFR_Url JOIN URL_cve WHERE CERTFR_Url.Url=URL_cve.Url;')
        for w_cve in wrap_cve:
            self.MaBdd.write_certfr_cve(w_cve[0],w_cve[1])

    ##
    # @brief Sauvegarde dans URL_ck
    # @param info liste
    # @details Python help
    def write_url_cve(self,info):
        """Insert en BDD
        info est une liste [nom du bulletin,nom du CVE, date]
        """
        self.MaBdd.write_sc(f'INSERT OR REPLACE INTO URL_cve VALUES("{info[0]}","{info[1]}","{info[2]}",1)')

    ##
    # @brief Sauvegarde en BDD un objet C_wrapper_info
    # @param info C_wrapper_info
    # @details Python help
    def Write_wrapper_info(self,info):
        """Insert en BDD
        info est un C_wrapper_info
        """
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
    # @details Python help
    def Read_wrapper_info(self,Champ,value,strict,New):
        """Lit une liste de C_wrapper_info depuis la Bdd
        Strict(Boolean) permet de choisir entre une recherche '=' ou 'like'
        New(Boolean) permet de choisir que les New=1 ou pas
        """
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
    # @details Python help
    def Url_down_file(self,info):
        """Télécharge un fichier s'il est plus rencent
        - vérifie la date du header vis a vis de la Bdd
        - télécharge le fichiers
        - met à jour la BDD
        """
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
    # @details Python help
    def Url_is_updated(self,info):
        """vérifie si le 'Last-Modified' est different de la Bdd.
        Si l'URL n'est pas en BDD revoie True
        """
        h_web=requests.head(info.Url)
        date=h_web.headers['Last-Modified']
        print("url_is_update : "+date)
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
    # @details Python help
    def check_regex(self,info):
        """check_regex permet de parcourir une page unique avec des liens
        info doit être un C_wrapper_info
            - Lit la page Url
            - cherche chaque sous-page avec le Regex
            - parse les sous-pages pour les CVE
        """
        if self.Url_is_updated(info):
            print ("info.Url : "+info.Url)
            r_web= requests.get(info.Url)
            if r_web.ok:
                info.Date=r_web.headers['Last-Modified']
                info.New=1
                self.Write_wrapper_info(info)
                l_info=copy.copy(info)
                feed=re.findall(info.Regex,r_web.text)
                for url in feed:
                    full_url=info.S_Url+url
                    print ("full_url : "+full_url)
                    if full_url[-1]=='/':
                        pass #rien a faire
                    else:
                        full_url=full_url+'/'
                        l_info.Url=full_url
                    c_info=self.Read_wrapper_info("Url",full_url,True,False)
                    if c_info:
                        pass #sous page deja traitée
                    else:
                        #connection close a cause trop grand nombre de requêtes
                        try:
                            feed_web=requests.get(full_url,{"Connection": "close"})
                        except:
                            print ("trop de connection sur le serveur distant")
                            break
                        if feed_web.ok:
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
    # @details Python help
    def Download_Certfr(self,EndDate):
        """Télécharge les fichiers année.tar du CERTFR
        EndDate est l'année en cours
        """
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
                info.Date="unjour"
                info.Url="https://www.cert.ssi.gouv.fr/tar/"+fichier
            self.Url_down_file(info)

    ##
    # @brief Télécharge les ZIP CVE NIST si plus récent
    # @details Python help
    def Download_CVE(self):
        """Télécharge les fichiers nvdcve-1.1-année.zip du NIST
        """
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
                info.Date="un jour au soleil"
                info.Url="https://nvd.nist.gov/feeds/json/cve/1.1/"+fichier
            self.Url_down_file(info)
        r_feed.close()

    ##
    # @brief Verifie les release de la page about.gitlab.com
    # @details Python help
    def Check_Gitlab(self):
        """Verifie les release de la page about.gitlab.com
        """
        inf=C_wrapper_info()
        inf.Url='https://about.gitlab.com/releases/categories/releases/'
        inf.Module="Gitlab"
        inf.Regex=r'<a class=cover href=\'(/releases/\d{4}/\d{2}/\d{2}/.*-released/)\''
        inf.S_Url='https://about.gitlab.com'
        self.check_regex(inf)

    ##
    # @brief Verifie les release de la page https://usn.ubuntu.com/months/
    # @details Python help
    def Check_Ubuntu(self):
        """Verifie les release de la page https://usn.ubuntu.com/months/
        """
        inf=C_wrapper_info()
        inf.Url='https://usn.ubuntu.com/months/'
        inf.Module='Ubuntu'
        inf.Regex=r'https://usn.ubuntu.com/\d+-\d+/'
        self.check_regex(inf)

    ##
    # @brief Verifie Kaspersky
    # @details Python help
    def Check_Kaspersky(self):
        """Vérifie les mise à jour kaspersky
        On utilise BeautifulSoup pour la page aspx
        """
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
    # @details Python help
    def Check_Xen(self):
        """Verifie le JSON de Xen
        """
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
    # @details Python help
    def Check_ALL_Wapper_Update(self,date):
        """lance tous les wrapper en une seule fonction
        cela evite de devoir modifier RIA.py si l'on rajoute un nouveau.
        """
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

    ##
    # @brief extrait les info CVE d'un zip
    # @param file le nom du fichier.zip
    # @diafile RIA_load_zip_cve.dia
    # @todo netoyer le code
    # @details Python help
    def Load_ZIP_cve(self,file):
        """Extrait toutes les informations d'un zip CVE nist
        file est avec son extension "nom_du_fichier.zip"
        """
        moncve=C_cve()
        moncpe=C_cpe()
        archive = zipfile.ZipFile(os.path.join("nvd/", file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        for cve in cve_dict['CVE_Items']:
            moncve.reset()
            moncve.id=cve['cve']['CVE_data_meta']['ID']
            if 'baseMetricV3' in cve['impact']:
                moncve.cvssV3=cve['impact']['baseMetricV3']['cvssV3']['vectorString']
                moncve.cvssV3base=cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            if 'baseMetricV2' in cve['impact']:
                moncve.cvssV2=cve['impact']['baseMetricV2']['cvssV2']['vectorString']
                moncve.cvssV2base=cve['impact']['baseMetricV2']['cvssV2']['baseScore']
            moncve.dateOrigine=cve['publishedDate']
            moncve.dateUpdate=cve['lastModifiedDate']
            moncve.set_crc()
            moncve.New=1
            self.MaBdd.write_cve_tmp(moncve)
            cve_node=cve['configurations']['nodes']
            if len(cve_node)>0:
                conf=0
                for cpelist in cve_node:
                    conf+=1
                    if len(cpelist)==2:
                        opt,dict_cpe=cpelist
                        if dict_cpe=='cpe_match':
                            for cpe in cpelist[dict_cpe]:
                                moncpe.reset()
                                moncpe.cve=moncve.id
                                moncpe.conf=conf
                                moncpe.operateur=cpelist.get(opt)
                                moncpe.vulnerable=cpe['vulnerable']
                                moncpe.cpe23uri=cpe['cpe23Uri'].replace('"',"'")
                                if 'versionStartExcluding' in cpe:
                                    moncpe.versionStartExcluding=cpe['versionStartExcluding'].replace('"',"'")
                                if 'versionStartIncluding' in cpe:
                                    moncpe.versionStartIncluding=cpe['versionStartIncluding'].replace('"',"'")
                                if 'versionEndExcluding' in cpe:
                                    moncpe.versionEndExcluding=cpe['versionEndExcluding'].replace('"',"'")
                                if 'versionEndIncluding' in cpe:
                                    moncpe.versionEndIncluding=cpe['versionEndIncluding'].replace('"',"'")
                                moncpe.set_crc()
                                moncpe.New=1
                                self.MaBdd.write_cpe_tmp(moncpe)
                        else:
                            child_lst=cpelist[dict_cpe]
                            for child in child_lst:
                                for cpe in child['cpe_match']:
                                    moncpe.reset()
                                    moncpe.cve=moncve.id
                                    moncpe.conf=conf
                                    moncpe.operateur=cpelist.get(opt)
                                    moncpe.cpe23uri=cpe['cpe23Uri'].replace('"',"'")
                                    moncpe.vulnerable=cpe['vulnerable']
                                    if 'versionStartExcluding' in cpe:
                                        moncpe.versionStartExcluding=cpe['versionStartExcluding'].replace('"',"'")
                                    if 'versionStartIncluding' in cpe:
                                        moncpe.versionStartIncluding=cpe['versionStartIncluding'].replace('"',"'")
                                    if 'versionEndExcluding' in cpe:
                                        moncpe.versionEndExcluding=cpe['versionEndExcluding'].replace('"',"'")
                                    if 'versionEndIncluding' in cpe:
                                        moncpe.versionEndIncluding=cpe['versionEndIncluding'].replace('"',"'")
                                    moncpe.set_crc()
                                    moncpe.New=1
                                    self.MaBdd.write_cpe_tmp(moncpe)

    ##
    # @brief Recherche regex pour Load_TAR_certfr
    # @param regex la regex
    # @param obj la chaine a chercher
    # @return la string ou ''
    # @details Python help
    def Search_re(self,regex,obj):
        """cherche la regex avec un group "()" dans obj
        revoie dans tous les cas un String
        """
        result=re.search(regex,obj)
        if result:
            return result.group(1)
        else:
            return ''

    ##
    # @brief extrait les info CERTFR d'un TAR
    # @param file le nom du fichier.tar
    # @diafile RIA_load_tar_certfr.dia
    # @todo nettoyer le code
    # @details Python help
    def Load_TAR_certfr(self,file):
        """Extrait toutes les informations d'un tar CERTFR
        file est avec son extension "nom_du_fichier.tar"
        """
        monbul=C_certfr()
        archive=tarfile.open(os.path.join("certfr/",file),'r')
        for nom in archive.getnames():
            if re.search('CERT(FR|A)\-\d+\-AVI\-\d+\.txt',nom):
                monbul.reset()
                bul_cve=[]
                bultin_tar=archive.extractfile(nom).readlines()
                bultin_list=[x.decode('utf-8') for x in bultin_tar]
                bultin_avi=''.join(bultin_list)
                addre='\n\nSecrétariat général de la défense et de la sécurité nationale – ANSSI – CERT-FR\n\n51, bd de La Tour-Maubourg\n75700 Paris 07 SP\n\nTél.:  +33 1 71 75 84 68\nFax:  +33 1 84 82 40 70\n\nWeb:  https://www.cert.ssi.gouv.fr\nMél:  cert-fr.cossi@ssi.gouv.fr\n'
                bultin_avi=bultin_avi.replace(addre,'')
                bultin_avi=re.sub('\\x0c','',bultin_avi)
                bultin_avi=re.sub('\nPage \d+ / \d+\n','',bultin_avi)
                monbul.link=re.findall(r'http[s]?://[^"\n]*',bultin_avi)
                #http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0985  en http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0985
                bultin_avi=bultin_avi.replace('?name=CAN-','?name=CVE-')
                monbul.file=re.sub('\n\n','\n',bultin_avi)

                #le nom du bulletin
                monbul.nom=self.Search_re('N° (CERT(FR|A)-\d{4}-AVI-\d+)',monbul.file)
                #l'objet   du bulletin
                monbul.obj=self.Search_re('Objet\:\ (.*)',monbul.file)
                #date de creation
                datetmp=self.Search_re('Date de la première version\n*(\d{1,2} \w* \d{4})',monbul.file)
                if len(datetmp)>1:
                    monbul.dateOrigine=datetmp
                else:
                    monbul.dateOrigine=self.Search_re('Paris, le (\d{1,2} \w* \d{4})',monbul.file)
                    #date de modif
                    monbul.dateUpdate=self.Search_re('Date de la dernière version\n*(\d{1,2} \w* \d{4})',monbul.file)
                    #les CVE
                regex=re.findall('http://cve\.mitre\.org/cgi\-bin/cvename\.cgi\?name\=(CVE\-\d{4}\-\d+)',monbul.file)
                if regex:
                    bul_cve=regex
                if len(bul_cve)>0:
                    for nom_cve in bul_cve:
                        self.MaBdd.write_certfr_cve(monbul.nom,nom_cve)
                monbul.set_crc()
                monbul.file=monbul.encode_file()
                monbul.New=1
                self.MaBdd.write_certfr_tmp(monbul)
