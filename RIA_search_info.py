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
from RIA_mskb import *

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

def charge_cert(file):
    monbul=C_certfr()
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
            monbul.New=1
            MaBdd.write_certfr_tmp(monbul)


def charge_cve(file):
    moncve=C_cve()
    moncpe=C_cpe()
    pbarcve=tqdm(total=1,ascii=True,unit="node",desc="PARSE CVE")
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
         moncve.New=1
         MaBdd.write_cve_tmp(moncve)
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
                             MaBdd.write_cpe_tmp(moncpe)
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
                                 MaBdd.write_cpe_tmp(moncpe)
    pbarcve.close()


#Une jolie sortie formater des info CERTFR
def CERT_to_STR(Nom):
    str_info=f'/------------------------\\\n|{Nom:^24}|\n\\________________________/\n'
    allcve=MaBdd.get_all_cve_certfr(Nom)
    if allcve:
        str_info+="CVE"+" "*17+"|CVSS v3"+" "*38+"|Base V3|CVSS V2"+" "*28+"|Base V2| Pubication | Modification\n"
        for mycve in allcve:
            str_info+=f"{mycve.id:20}|{mycve.cvssV3:45}|{mycve.cvssV3base:^7}|{mycve.cvssV2:35}|{mycve.cvssV2base:^7}|{mycve.dateOrigine[:10]:^12}|{mycve.dateUpdate[:10]:^12}\n"
        str_info+="\n"
    cpe_max=MaBdd.get_max_lg_uri_cpe(Nom)
    allcpe=MaBdd.get_all_cpe_certfr(Nom)
    if allcpe:
        str_info+="\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl\n" 
        test=allcpe[0].cve+'+'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
        for cpe in allcpe:
            testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
            if test==testlg:
                str_info+="\t"+" "*32+f"{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}\n"
            else:
                str_info+=f"\t{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}\n"
                test=cpe.cve+'+'+str(cpe.conf)+' '+cpe.vulnerable
    str_info+="\n"
    return str_info

#les info Microsoft
def MS_to_STR(Nom):
    str_info=''
    allcve=Ksoft.get_info_certfr(Nom)
    if allcve:
        str_info+='Microsoft info\n'
        str_info+="CVE"+" "*17+"|PRODUIT"+" "*53+"|KB"+" "*13+"|URL|Type\n"
        for row in allcve:
            str_info+=f"{row[0]:^20}|{row[1]:60}|{row[2]:^15}|{row[3]:^15}|{row[4]}\n"
    return str_info

#Télécharge les fichiers si plus récent ou taille différents
def Url_down(nom,rep,url,scr):
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
        MaBdd.set_url_info(nom,file_date,file_taille,scr)


#Ecrit un bultin
def Write_CERTFR(nom,annee):
    cert=MaBdd.get_certfr(nom)
    if not exists(f"txt/{annee}"):
        mkdir(f"txt/{annee}")   
    file=open(f"txt/{annee}/{nom}.txt",'w',encoding='utf-8')
    bultin_avi=cert.decode_file()
    file.writelines(bultin_avi+'\n')
    file.writelines('\n-------------- RIA By HBT --------------\n')
    file.writelines(CERT_to_STR(nom))
    file.writelines(MS_to_STR(nom))
    file.close()


##################
#  LE Script :)  #
##################
logging.basicConfig(filename='Update_certfr.log',level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('Lancement du script')
credit()

MaBdd=C_sql()

print("Mise a jour info Microsoft")
Ksoft=C_mskb(MaBdd)
#Ksoft.update_all_info()

if not exists("txt"):
    mkdir("txt")


print ("Vérification de la mise à jour des fichiers CVE ET CERTFR")
MaBdd.write_sc("UPDATE URL_file SET New=0;")

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
feed=re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text)
pbar = tqdm(total=len(feed),ascii=True,desc="CVE")
for filename in re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text):
    pbar.update(1)
    Url_down(filename,"nvd/","https://nvd.nist.gov/feeds/json/cve/1.1/" + filename,"CVE")
pbar.close()

# range (2000,2021) = [2000,2020] :)
year = datetime.date.today().year
pbar = tqdm(total=year-2000,ascii=True,desc="CERTFR")
for anne in range(2000,year +1):
    pbar.update(1)
    filename=str(anne)+".tar"
    Url_down(filename,"certfr/","https://www.cert.ssi.gouv.fr/tar/"+filename,"CERTFR")
pbar.close()

maj=MaBdd.get_all_new_url()
if maj:
    MaBdd.clean_tmp()
    for fichier in maj:
        if fichier['source']=="CERTFR":
            charge_cert(fichier['Nom'])
        elif fichier['source']=="CVE":
            charge_cve(fichier['Nom'])
    print ("Vérification des mise à jour")    
    MaBdd.flush_tmp()
    print ("Nettoyage et Sauvegarde sur le disque")
    MaBdd.save_db()
else:
    MaBdd.clean_new()

MaBdd.write_sc("UPDATE CERTFR SET New=1 WHERE nom LIKE '%2020%';")


print("Traite les mises a jour de buletin")
rows=MaBdd.get_all_new_certfr()
pbar = tqdm(total=len(rows),ascii=True,desc="Bultin")
for bul in rows:
    pbar.update(1)
    logging.info(f'mise a jour de {bul[0]}')
    gg=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0]) 
    Write_CERTFR(bul[0],gg.group('an'))
pbar.close()

rows = MaBdd.get_all_certfr_by_cve()
fiche=open("txt/CVE_CERTFR.txt",'w', encoding='utf-8')
pbar =  tqdm(total=len(rows),unit="buletin",ascii=True,desc="CVE_CERTFR")
for bul in rows:
    pbar.update(1)
    str_bul=f"{bul[0]:^10}:{bul[1]}\n"
    fiche.writelines(str_bul)
fiche.close()
pbar.close()


MaBdd.close_db()

print("Bye Bye")
