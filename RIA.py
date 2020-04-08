##
# @file RIA.py
# @author Frack113
# @date 07/04/2020
# @brief Recherche d'Information Automatisée
# @todo utiliser les best practice Python
#
# @mainpage
# @section Description
# Télécharge et complète automatiquement les bulletins CERTFR avec les CVE/cpe
#\n
#Si possible :\n
#\li les KB microsoft
#\li les informations éditeurs
#
# @section schéma
# @diafile RIA_main.dia

import re
import os
import datetime
import requests
import shutil
from tqdm import tqdm
import logging

from RIA_class import *
from RIA_sql import *
from RIA_mskb import *
from RIA_wrapper import *

##
#@brief Affiche simplement le credit
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
# @brief Ecrit dans un fichier text les informations du bulletin
# @param nom le nom du bulletin
# @param annee repertoire de sortie
def Write_CERTFR(nom,annee):
    reponse=[]
    cert=MaBdd.get_certfr(nom)
    if not os.path.exists(f"txt/{annee}"):
        os.mkdir(f"txt/{annee}")
    file=open(f"txt/{annee}/{nom}.txt",'w',encoding='utf-8')
    bultin_avi=cert.decode_file()
    reponse.append(bultin_avi)
    reponse.append('----------------------------------------')
    reponse.append('----------- RIA By Frack113 ------------')
    reponse.append('----------------------------------------')
    CERT_to_STR(nom,reponse)
    MS_to_STR(nom,reponse)
    file.writelines('\n'.join(reponse))
    file.close()

##
# @brief Ecrit un fichiers avec bulletins et URI23 pour une recherche
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
    file=file=open(f"mogs/{Nom}.txt",'w',encoding='utf-8')
    file.writelines('\n'.join(tab))
    file.close()


## Core du scripts
# @brief le coeur du scripts
# @todo simplifier les repetitions
def mon_script():
    global MaBdd
    global Ksoft
    logging.basicConfig(filename='Update_certfr.log',level=logging.INFO,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    logging.info('Lancement du script')
    today=datetime.datetime.now().strftime("%Y%m%d")

    credit()

    if os.path.exists("txt"):
        pass
    else:
        os.mkdir("txt")
        logging.warning('manque le repertoire de sortie txt')

    if os.path.exists("mogs"):
        pass
    else:
        os.mkdir("mogs")
        logging.warning('manque le repertoire de sortie mogs')

    if os.path.exists('RIA.db'):
        logging.info('RIA.db ok')
    else:
        logging.warning('manque le fihier de bdd initial')
        dest = shutil.copyfile('RIA_init.db','RIA.db')

    MaBdd=C_sql()
    MaBdd.clean_new()
    MaBdd.clean_tmp()

    if os.path.exists('RIA_mogs.txt'):
        logging.info("Traitement de l'aide des mogs")
        MaBdd.load_mogs()

    print("Mise à jour info API Microsoft")
    Ksoft=C_mskb(MaBdd)
    reponse=Ksoft.Check_Mskb_Update(today)
    # on log pour le moment un peu fiu
    logging.warning(reponse)

    print("Un peu de data mining sur le Web")
    Wrapper=C_wrapper(MaBdd)
    Wrapper.Reset_New()
    Wrapper.Check_ALL_Wapper_Update(today)
    Wrapper.Flush_cve()

    print ("Téléchargement des nouveaux fichiers CVE ET CERTFR")
    Wrapper.Download_Certfr(int(today[:4]))
    Wrapper.Download_CVE()

    print ("Chargement des mise à jour CERTFR")
    updates=Wrapper.Read_wrapper_info("Module","CERTFR",True,True)
    logging.info("Update CERTFR : "+str(len(updates)))
    for update in updates:
        Wrapper.Load_TAR_certfr(update.Fichier)
        logging.warning(update.Fichier+ " mis a jour")

    print ("Chargement des mise à jour CVE")
    updates=Wrapper.Read_wrapper_info("Module","CVE",True,True)
    logging.info("Update CVE : "+str(len(updates)))
    for update in updates:
        Wrapper.Load_ZIP_cve(update.Fichier)
        logging.warning(update.Fichier+ " mis a jour")

    cves=MaBdd.get_all_cve_orphan()
    if cves:
        logging.info(str(len(cves))+" CVE non present sur le NIST cré(s)")
        moncve=C_cve()
        moncve.New=1
        for strcve in cves:
            moncve.id=strcve[0]
            moncve.set_crc()
            MaBdd.write_cve_tmp(moncve)

    # On sauvegarde le tout
    MaBdd.flush_tmp()
    MaBdd.flush_url()
    MaBdd.save_db()


#       Pour verifier la sortie sans avoir de mise a jour :)
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 WHERE nom LIKE '%2020%';")
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 ;")

    print("Traite les mises a jour de bulletin")
    rows=MaBdd.get_all_new_certfr()
    pbar = tqdm(total=len(rows),ascii=True,desc="Bulletin")
    for bul in rows:
        pbar.update(1)
        logging.info(f'mise a jour de {bul[0]}')
        re_result=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0])
        Write_CERTFR(bul[0],re_result.group('an'))
    pbar.close()

    rows = MaBdd.get_all_certfr_by_cve()
    fiche=open("txt/CVE_CERTFR.txt",'w', encoding='utf-8')
    pbar =  tqdm(total=len(rows),unit="bulletin",ascii=True,desc="CVE_CERTFR")
    for bul in rows:
        pbar.update(1)
        fiche.writelines(f"{bul[0]:^10}:{bul[1]}\n")
    fiche.close()
    pbar.close()

    rows = MaBdd.get_all_orphan()
    fiche=open("txt/Orphan.txt",'w', encoding='utf-8')
    pbar =  tqdm(total=len(rows),unit="bulletin",ascii=True,desc="Orphan")
    for bul in rows:
        pbar.update(1)
        fiche.writelines(f"{bul[0]:^10}:{bul[1]}\n")
    fiche.close()
    pbar.close()


    if os.path.exists('RIA_uri_manual.txt'):
        print ("traitement des fichiers de recherche URI manuelle")
        logging.info('Sortie pour les futurs mogs')
        file=open("RIA_uri_manual.txt")
        lignes=file.read().splitlines()
        pbar =  tqdm(total=len(lignes),unit="Fichier",ascii=True,desc="Uri")
        for ligne in lignes:
            pbar.update(1)
            info=ligne.split(";")
            URI_to_FILE(info[0],info[1])
        fiche.close()
        pbar.close()

    MaBdd.close_db()

    print("Bye Bye")
    logging.info('fin de traitement')

##
# Brief A cause de Doxygen pour la docs
mon_script()
