import re
import os
from os import listdir,mkdir
from os.path import isfile, join, exists
import zipfile
import tarfile
import json
import datetime
import sqlite3
import hashlib
import requests
import shutil
from tqdm import tqdm
import base64
import logging

from RIA_class import *
from RIA_sql import *

def credit():
    mon_credit="""
                             ____ ____ ____
                            ||R |||I |||A ||
                            ||__|||__|||__||
                            |/__\|/__\|/__\|
    
                              Recherche
                                 d'Information
                                       Automatisée

       /^\\
      | " |
/\\     |_|     /\\
| \\___/' `\\___/ |
 \_/  \\___/  \\_/
  |\\__/   \\__/|               Version 0
  |/  \\___/  \\|              Slow is best 
 ./\\__/   \\__/\\,
 | /  \\___/  \\ |
 \\/     V     \\/
    
    """
    print(mon_credit)


def Search_re(regex,obj):
    result=re.search(regex,obj)
    if result:
        return result.group(1)
    else:
        return ''

def charge_cert():
    monbul=C_certfr()
    MaBdd.clean_tmp()
 
    files = [f for f in listdir("certfr/") if isfile(join("certfr/", f))]
    files.sort()
    pbar=tqdm(total=len(files), unit="file",ascii=True,desc="PARSE CERTFR")
    for file in files:
        pbar.update(1)
        archive=tarfile.open(join("certfr/",file),'r')    
        for nom in archive.getnames():
            if re.search('CERT(FR|A)\-\d+\-AVI\-\d+\.txt',nom):
                monbul.reset()
                bul_cve=[]
                bultin_tar=archive.extractfile(nom).readlines()
                bultin_list=[x.decode('utf-8') for x in bultin_tar]
                bultin_avi=''.join(bultin_list)
                bultin_avi=re.sub('\\x0c','',bultin_avi)
                bultin_avi=re.sub('Page \d+ / \d+','',bultin_avi)            
                #http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0985  en http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0985
                bultin_avi=bultin_avi.replace('?name=CAN-','?name=CVE-')
                monbul.file=re.sub('\n\n','\n',bultin_avi)

                #le nom du bulletin
                monbul.nom=Search_re('N° (CERT(FR|A)-\d{4}-AVI-\d+)',monbul.file)  
                #l'objet   du bulletin
                monbul.obj=Search_re('Objet\:\ (.*)',monbul.file)
                #date de creation
                datetmp=Search_re('Date de la première version\n*(\d{1,2} \w* \d{4})',monbul.file)
                if len(datetmp)>1:
                    monbul.dateOrigine=datetmp
                else:
                    monbul.dateOrigine=Search_re('Paris, le (\d{1,2} \w* \d{4})',monbul.file)
                #date de modif
                monbul.dateUpdate=Search_re('Date de la dernière version\n*(\d{1,2} \w* \d{4})',monbul.file)       
                #les CVE
                regex=re.findall('http://cve\.mitre\.org/cgi\-bin/cvename\.cgi\?name\=(CVE\-\d{4}\-\d+)',monbul.file)
                if regex:
                    bul_cve=regex
                if len(bul_cve)>0:
                    for nom_cve in bul_cve:
                        MaBdd.write_certfr_cve(monbul.nom,nom_cve)
                monbul.set_crc()
                monbul.file=monbul.encode_file()
                MaBdd.write_certfr_tmp(monbul)
                pbar.close()
    
    #mise a jour de la table
    print("Mise a jour de la table CERTFR")
    MaBdd.flush_tmp


def charge_cve():
    moncve=C_cve()
    moncpe=C_cpe()
    sql="DELETE FROM CVE_tmp;"
    mycur.execute(sql)
    sql="DELETE FROM CVE_cpe_tmp;"
    mycur.execute(sql)

    files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
    files.sort()
    pbar = tqdm(total=len(files), unit="file",ascii=True,desc="PARSE JSON")
    pbarcve=tqdm(total=1,ascii=True,unit="node",desc="PARSE CVE")
    for file in files:
        pbar.update(1)
        archive = zipfile.ZipFile(join("nvd/", file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        pbarcve.total=len(cve_dict['CVE_Items'])
        for cve in cve_dict['CVE_Items']:
            moncve.reset()
            pbarcve.update(1)
            moncve.id=cve['cve']['CVE_data_meta']['ID']
            if 'baseMetricV3' in cve['impact']:
                moncve.cvssV3=cve['impact']['baseMetricV3']['cvssV3']['vectorString']
                moncve.cvssV3base=cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            if 'baseMetricV2' in cve['impact']:
                moncve.cvssV2=cve['impact']['baseMetricV2']['cvssV2']['vectorString']
                moncve.cvssV2base=cve['impact']['baseMetricV2']['cvssV2']['baseScore']
            moncve.dateOrigne=cve['publishedDate']
            moncve.dateUpdate=cve['lastModifiedDate']
            moncve.set_crc()
            sql=f'INSERT INTO CVE_tmp VALUES("{moncve.crc}","{moncve.id}","{moncve.cvssV3}",{moncve.cvssV3base},"{moncve.cvssV2}",{moncve.cvssV2base},"{moncve.dateOrigine}","{moncve.dateUpdate}",1);'
            mycur.execute(sql)
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
                                sql=f'INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{moncpe.crc}","{moncpe.cve}",{moncpe.conf},"{moncpe.operateur}","{moncpe.vulnerable}","{moncpe.cpe23uri}","{moncpe.versionStartExcluding}","{moncpe.versionStartIncluding}","{moncpe.versionEndExcluding}","{moncpe.versionEndIncluding}",1);'
                                mycur.execute(sql)
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
                                    sql=f'INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{moncpe.crc}","{moncpe.cve}",{moncpe.conf},"{moncpe.operateur}","{moncpe.vulnerable}","{moncpe.cpe23uri}","{moncpe.versionStartExcluding}","{moncpe.versionStartIncluding}","{moncpe.versionEndExcluding}","{moncpe.versionEndIncluding}",1);'
                                    mycur.execute(sql)
    pbar.close()
    pbarcve.close()
    print ("Mise a jour de la table CVE")
    mycur.executescript("""
     UPDATE CVE SET New=0;
     DELETE FROM CVE_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE);
     INSERT OR replace INTO CVE SELECT * from CVE_tmp;
     DELETE FROM CVE_tmp;
    """)
    print ("Mise a jour de la table CPE")
    mycur.executescript("""
     UPDATE CVE_cpe SET New=0;
     DELETE FROM CVE_cpe_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE_cpe);
     INSERT OR replace INTO CVE_cpe SELECT * from CVE_cpe_tmp;
     DELETE FROM CVE_cpe_tmp;
    """)

#Une jolie sortie formater des info CERTFR
def CERT_to_STR(nom_bultin):
    str_info=f'/------------------------\\\n|{nom_bultin:^24}|\n\\________________________/\n'
    mycur.execute(f"SELECT * FROM CVE WHERE cve_id IN (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}') ORDER BY cve_id;")
    allcve=mycur.fetchall()
    if allcve:
        str_info+="CVE"+" "*17+"|CVSS v3"+" "*38+"|Base V3|CVSS V2"+" "*28+"|Base V2| Pubication | Modification\n"
        for mycve in allcve:
            str_info+=f"{mycve[1]:20}|{mycve[2]:45}|{mycve[3]:^7}|{mycve[4]:35}|{mycve[5]:^7}|{mycve[6][:10]:^12}|{mycve[7][:10]:^12}\n"
        str_info+="\n"
    mycur.execute(f"SELECT max(length(cpe)) FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}');")
    cpe_max=mycur.fetchone()
    mycur.execute(f"SELECT DISTINCT * FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}') ORDER BY cve_id,conf ASC,vuln DESC;")
    allcve=mycur.fetchall()
    if allcve:
       str_info+="\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max[0]-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl\n" 
       test=allcve[0][1]+'+'+str(allcve[0][2])+' '+allcve[0][3]
       for cpe in allcve:
           testlg=cpe[1]+' '+str(cpe[2])+' '+cpe[3]
           if test==testlg:
                str_info+="\t"+" "*32+f"{cpe[4]:^7}|{cpe[5]:{cpe_max[0]}}|{cpe[6]:12}|{cpe[7]:12}|{cpe[8]:12}|{cpe[9]:12}\n"
           else:
                str_info+=f"\t{cpe[1]:^20}|{cpe[2]:^4}|{cpe[3]:^5}|{cpe[4]:^7}|{cpe[5]:{cpe_max[0]}}|{cpe[6]:12}|{cpe[7]:12}|{cpe[8]:12}|{cpe[9]:12}\n"
                test=cpe[1]+' '+str(cpe[2])+' '+cpe[3]
    str_info+="\n"
    return str_info

#les info Microsoft
def MS_to_STR(nom_bultin):
    str_info=''
    mycur.execute(f'select CVE,Value,FIX_ID,Url,type from MS_vuln left JOIN MS_Product ON MS_vuln.ProductID=MS_Product.ProductID WHERE MS_vuln.CVE IN (SELECT CVE from CERTFR_cve WHERE BULTIN="{nom_bultin}");')
    allcve=mycur.fetchall()
    if allcve:
        str_info+='Microsoft info\n'
        str_info+="CVE"+" "*17+"|PRODUIT"+" "*53+"|KB"+" "*13+"|URL|Type\n"
        for row in allcve:
            str_info+=f"{row[0]:^20}|{row[1]:60}|{row[2]:^15}|{row[3]:^15}|{row[4]}\n"
    return str_info

#Télécharge les fichiers si plus récent ou taille différents
def Url_down(nom,rep,url):
    info = MaBdd.get_url_info(nom)
    if info:
        r_file = requests.head(url)
        if r_file.headers['last-modified']==info[1] and r_file.headers['content-length']==info[2]:
            download=False
        else:
            download=True
    else:
        download=True
    if download:
        if not exists(rep):
            mkdir(rep)
        r_file = requests.get(url, stream=True)
        file_date=r_file.headers['last-modified']
        file_taille=r_file.headers['content-length']
        with open(rep + filename, 'wb') as f:
            shutil.copyfileobj(r_file.raw, f)
        MaBdd.set_url_info(r_file,file_date,file_taille)
    return download

#revoie le fichier brut d'un CERTFR
def Get_Certfr_file(nom):
    cert=C_certfr()
    mycur.execute(f'SELECT file FROM CERTFR WHERE nom="{nom}";')
    cert.file=mycur.fetchone()[0]
    return cert.decode_file()


#Ecrit un bultin
def Write_CERTFR(nom,annee):
    if not exists(f"txt/{annee}"):
        mkdir(f"txt/{annee}")   
    file=open(f"txt/{annee}/{nom}",'w',encoding='utf-8')
    bultin_avi=Get_Certfr_file(nom)
    file.writelines(bultin_avi+'\n')
    file.writelines('\n-------------- RIA By HBT --------------\n')
    file.writelines(CERT_to_STR(nom))
    file.writelines(MS_to_STR(nom))
    file.close()


##################
#  LE Script :)  #
##################
credit()
global MaBdd  # Global ou pas global obligatoire ???
MaBdd=C_sql()

if not exists("txt"):
    mkdir("txt")


print ("Vérification de la mise à jour des fichiers CVE ET CERTFR")
mise_a_jour=False
r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
feed=re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text)
pbar = tqdm(total=len(feed),ascii=True,desc="CVE")
for filename in re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text):
    pbar.update(1)
    if Url_down(filename,"nvd/","https://nvd.nist.gov/feeds/json/cve/1.1/" + filename):
        mise_a_jour=True
pbar.close()

# range (2000,2021) = [2000,2020] :)
year = datetime.date.today().year
pbar = tqdm(total=year-2000,ascii=True,desc="CERTFR")
for anne in range(2000,year +1):
    pbar.update(1)
    filename=str(anne)+".tar"
    if Url_down(filename,"certfr/","https://www.cert.ssi.gouv.fr/tar/"+filename):
        mise_a_jour=True
pbar.close()

if mise_a_jour:
    charge_cert()
    charge_cve()
    print ("Vérification des mise à jour CPE ou CVE")
    mycur.executescript("""
     UPDATE CVE SET New=1 WHERE cve_id IN (select cve_id FROM CVE_cpe where new=1);
     INSERT INTO CVE_tmp SELECT * FROM CVE WHERE New=1;
     UPDATE CERTFR SET new=1 WHERE nom IN (SELECT DISTINCT BULTIN FROM CERTFR_cve JOIN CVE_tmp WHERE CERTFR_cve.CVE=CVE_tmp.cve_id);
     DELETE FROM CVE_tmp;
    """)
    #on ecrit le tout :)
    print ("Nettoyage et Sauvegarde sur le disque")
    mycur.execute('VACUUM "main";')
    myBD.commit()
else:
    mycur.executescript("""
     UPDATE CERTFR SET New=0;
     UPDATE CVE SET New=0;
     UPDATE CVE_cpe SET New=0;
    """)

print("Traite les mises a jour de buletin")
mycur.execute("SELECT Nom FROM CERTFR WHERE New=1;")
rows = mycur.fetchall()
logging.basicConfig(filename='Update_certfr.log',level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
pbar = tqdm(total=len(rows),ascii=True,desc="Bultin")
for bul in rows:
    pbar.update(1)
    logging.info(f'mise a jour de {bul[0]}')
    gg=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0]) 
    Write_CERTFR(bul[0],gg.group('an'))
pbar.close()


mycur.executescript("""
  DROP TABLE IF EXISTS CVE_BULTIN;
  CREATE TABLE CVE_BULTIN AS SELECT CVE, group_concat(DISTINCT BULTIN) FROM CERTFR_cve GROUP BY CVE;
  ALTER TABLE CVE_BULTIN RENAME COLUMN 'group_concat(DISTINCT BULTIN)' TO CERTFR;
""")
mycur.execute('SELECT * FROM CVE_BULTIN;')
rows = mycur.fetchall()
fiche=open("txt/CVE_CERTFR.txt",'w', encoding='utf-8')
pbar =  tqdm(total=len(rows),unit="buletin",ascii=True,desc="CVE_CERTFR")
for bul in rows:
    pbar.update(1)
    str_bul=f"{bul[0]:^10}:{bul[1]}\n"
    fiche.writelines(str_bul)
fiche.close()
pbar.close()


myBD.commit()
myBD.close()

print("Bye Bye")
