## Mon IA
# @file RIA.py
# @author Frack113
# @date 01/04/2020
# @brief Recherche d'Information Automatisée
# @todo simplifier les imports best practice
#
# @mainpage description
# telecharge et complete automatiquement les bulletins CERTFR_tmp
# Avec les CVE/cpe
#
# Si possible :
#   les KB microsoft
#   les informations éditeurs

import re
import os
from os import listdir,mkdir
from os.path import isfile, join, exists
import zipfile
import tarfile
import json
import datetime
import requests
import shutil
from tqdm import tqdm
import logging

from RIA_class import *
from RIA_sql import *
from RIA_mskb import *
from RIA_wrapper import *

## Affiche simplement le credit
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

##
# @brief Recherche regex
# @param regex la regex
# @param obj la chaine a chercher
# @return la string ou ''
def Search_re(regex,obj):
    result=re.search(regex,obj)
    if result:
        return result.group(1)
    else:
        return ''

##
# @brief extrait les info CERTFR d'un TAR
# @param file le nom du fichier.tar
# @return None
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
            addre='\n\nSecrétariat général de la défense et de la sécurité nationale – ANSSI – CERT-FR\n\n51, bd de La Tour-Maubourg\n75700 Paris 07 SP\n\nTél.:  +33 1 71 75 84 68\nFax:  +33 1 84 82 40 70\n\nWeb:  https://www.cert.ssi.gouv.fr\nMél:  cert-fr.cossi@ssi.gouv.fr\n'
            bultin_avi=bultin_avi.replace(addre,'')
            bultin_avi=re.sub('\\x0c','',bultin_avi)
            bultin_avi=re.sub('\nPage \d+ / \d+\n','',bultin_avi)
            monbul.link=re.findall(r'http[s]?://[^"\n]*',bultin_avi)
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

##
# @brief extrait les info CVE d'un zip
# @param file le nom du fichier.zip
# @return None
def charge_cve(file):
    moncve=C_cve()
    moncpe=C_cpe()
    pbarcve=tqdm(total=1,ascii=True,unit="node",desc=file)
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
         moncve.dateOrigine=cve['publishedDate']
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



##
# @brief Une jolie sortie formater des info CERTFR
# @param Nom le nom du bulletin
# @param tab une liste
# @return None
def CERT_to_STR(Nom,tab):
    allcve=MaBdd.get_all_cve_certfr(Nom)
    if allcve:
        tab.append("CVE"+" "*17+"|CVSS v3"+" "*38+"|Base V3|CVSS V2"+" "*28+"|Base V2| Pubication | Modification")
        for mycve in allcve:
            tab.append(f"{mycve.id:20}|{mycve.cvssV3:45}|{mycve.cvssV3base:^7}|{mycve.cvssV2:35}|{mycve.cvssV2base:^7}|{mycve.dateOrigine[:10]:^12}|{mycve.dateUpdate[:10]:^12}")
        tab.append('')
    cpe_max=MaBdd.get_max_lg_uri_cpe(Nom)
    allcpe=MaBdd.get_all_cpe_certfr(Nom)
    if allcpe:
        tab.append("\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl" )
        test=allcpe[0].cve+'_'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
        for cpe in allcpe:
            testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
            if test==testlg:
                tab.append("\t"+" "*32+f"{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
            else:
                tab.append(f"\t{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                test=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
    tab.append('')



##
# @brief Une jolie sortie formater des info Microsoft
# @param Nom le nom du bulletin
# @param tab une liste
# @return None
def MS_to_STR(Nom,tab):
    allcve=Ksoft.get_info_certfr(Nom)
    if allcve:
        tab.append('Microsoft info')
        tab.append("CVE"+" "*17+"|PRODUIT"+" "*53+"|KB"+" "*13+"|URL|Type")
        for row in allcve:
            tab.append(f"{row[0]:^20}|{row[1]:60}|{row[2]:^15}|{row[3]:^15}|{row[4]}")

##
# @brief Télécharge les fichiers si plus récent ou taille différents
# @param nom le nom du fichier
# @param rep son repertoire de sortie
# @param url son url
# @param scr sa cle de reference
# @return None
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
        with open(rep + nom, 'wb') as f:
            shutil.copyfileobj(r_file.raw, f)
        MaBdd.set_url_info(nom,file_date,file_taille,scr)

##
# @brief Télécharge les fichiers si plus récent ou taille différents
# @param nom le nom du bulletin
# @param annee repertoire de sortie
def Write_CERTFR(nom,annee):
    reponse=[]
    cert=MaBdd.get_certfr(nom)
    if not exists(f"txt/{annee}"):
        mkdir(f"txt/{annee}")
    file=open(f"txt/{annee}/{nom}.txt",'w',encoding='utf-8')
    bultin_avi=cert.decode_file()
    reponse.append(bultin_avi)
    reponse.append('----------------------------------------')
    reponse.append('-------------- RIA By HBT --------------')
    reponse.append('----------------------------------------')
    CERT_to_STR(nom,reponse)
    MS_to_STR(nom,reponse)
    file.writelines('\n'.join(reponse))
    file.close()

##
# @brief Télécharge les fichiers si plus récent ou taille différents
# @param Nom dans les objets et non du fichier de sortie
# @param uri chaine a chercher dans les uri23
def URI_to_FILE(Nom,uri):
    tab=[]
    certs=MaBdd.get_orphan_by_obj(Nom)
    if certs:
        for cert in certs:
            tab.append(cert[0]+' : '+cert[1])
    tab.append('Les CVE')
    allcpe=MaBdd.get_all_cpe_uri(uri)
    cpe_max=50
    if allcpe:
        tab.append("\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl" )
        test=allcpe[0].cve+'_'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
        for cpe in allcpe:
            testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
            if test==testlg:
                tab.append("\t"+" "*32+f"{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
            else:
                tab.append(f"\t{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                test=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
    file=file=open(f"txt/{Nom}.txt",'w',encoding='utf-8')
    file.writelines('\n'.join(tab))
    file.close()

##
# @brief Télécharge au bessoin les CERTFR ET CVE
def Check_update_file():
    MaBdd.write_sc("UPDATE URL_file SET New=0;")
    r_feed = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    feed=re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r_feed.text)
    pbar = tqdm(total=len(feed),ascii=True,desc="CVE")
    for filename in feed:
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
        print ("Pas de mise a jour")
        MaBdd.clean_new()


## Core
# @brief le script
logging.basicConfig(filename='Update_certfr.log',level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('Lancement du script')
today=datetime.datetime.now().strftime("%Y%m%d")

if not exists("txt"):
    mkdir("txt")
    logging.info('manque le repertoire de sortie txt')

credit()

if os.path.exists('RIA.db'):
    logging.info('RIA.db ok')
else:
    dest = shutil.copyfile('RIA_init.db','RIA.db')

MaBdd=C_sql()

if os.path.exists('RIA_mogs.txt'):
    logging.info('Les mogs sont la')
    file=open('RIA_mogs.txt','r')
    lignes=file.read().splitlines()
    for ligne in lignes:
        info=ligne.split(";")
        MaBdd.write_certfr_cve(info[0],info[1])
    file.close()

print("Mise a jour info API Microsoft")
Ksoft=C_mskb(MaBdd)
if os.path.exists('RIA_mskb.key'):
    if MaBdd.get_Info_date("Microsoft")==today:
        print ("Déjà fait aujourd'hui")
    else:
        Ksoft.update_all_info()
        MaBdd.set_Info_date("Microsoft",today)
else:
    print("Manque le fichier RIA_mskb.key")
    logging.warning('Pas de key api MICROSOFT')

print("Mise a jour info Wrapper")
Wrapper=C_wrapper(MaBdd)

print("Check Gitlab")
if MaBdd.get_Info_date("Gitlab")== today:
    print ("Déjà fait aujourd'hui")
else:
    Wrapper.check_Gitlab()
    MaBdd.set_Info_date("Gitlab",today)

print("Check Ubuntu")
if MaBdd.get_Info_date("Ubuntu")== today:
    print ("Déjà fait aujourd'hui")
else:
    Wrapper.check_Ubuntu()
    MaBdd.set_Info_date("Ubuntu",today)

print("Check Kaspersky")
if MaBdd.get_Info_date("Kaspersky")== today:
    print ("Déjà fait aujourd'hui")
else:
    Wrapper.check_Kaspersky()
    MaBdd.set_Info_date("Kaspersky",today)

print("Check Xen")
if MaBdd.get_Info_date("Xen")== today:
    print ("Déjà fait aujourd'hui")
else:
    Wrapper.check_Xen()
    MaBdd.set_Info_date("Xen",today)

Wrapper.Flush_cve()
MaBdd.save_db()

print ("Vérification de la mise à jour des fichiers CVE ET CERTFR")
Check_update_file()


#       Pour verifier la sortie sans avoir de mise a jour :)
#MaBdd.write_sc("UPDATE CERTFR SET New=1 WHERE nom LIKE '%2020%';")

print("Traite les mises a jour de buletin")
rows=MaBdd.get_all_new_certfr()
pbar = tqdm(total=len(rows),ascii=True,desc="Bultin")
for bul in rows:
    pbar.update(1)
    logging.info(f'mise a jour de {bul[0]}')
    re_result=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0])
    Write_CERTFR(bul[0],re_result.group('an'))
pbar.close()

rows = MaBdd.get_all_certfr_by_cve()
fiche=open("txt/CVE_CERTFR.txt",'w', encoding='utf-8')
pbar =  tqdm(total=len(rows),unit="buletin",ascii=True,desc="CVE_CERTFR")
for bul in rows:
    pbar.update(1)
    fiche.writelines(f"{bul[0]:^10}:{bul[1]}\n")
fiche.close()
pbar.close()

rows = MaBdd.get_all_orphan()
fiche=open("txt/Orphan.txt",'w', encoding='utf-8')
pbar =  tqdm(total=len(rows),unit="buletin",ascii=True,desc="Orphan")
for bul in rows:
    pbar.update(1)
    fiche.writelines(f"{bul[0]:^10}:{bul[1]}\n")
fiche.close()
pbar.close()


URI_to_FILE("Wireshark","Wireshark:Wireshark")
URI_to_FILE("Drupal","drupal:drupal")

MaBdd.close_db()

print("Bye Bye")
