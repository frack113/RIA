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
from RIA_out import *

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


## Core du scripts
# @brief le coeur du scripts
# @todo simplifier les repetitions
def mon_script():
    global MaBdd
    global Ksoft
    logging.basicConfig(filename='Update_certfr.log',
                        level=logging.INFO,
                        format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    logging.info('-------------------------------------')
    logging.info('        Lancement du script')

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

#       Pour verifier la sortie sans avoir de mise a jour :)
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 WHERE nom LIKE '%2020%';")
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 ;")

    print("Traite les sorties")
    R_out=C_out(MaBdd,Ksoft)

    rows=MaBdd.get_all_new_certfr()
    logging.info("Get_all_new_certfr :"+str(len(rows)))
    pbar = tqdm(total=len(rows),ascii=True,desc="Bulletin")
    for bul in rows:
        pbar.update(1)
        logging.info(f'mise a jour de {bul[0]}')
        re_result=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0])
        R_out.Write_CERTFR(bul[0],re_result.group('an'))
    pbar.close()

    print("Le Json ...")
    R_out.Export_certfr_json("new.json",'LIKE "%" AND New=1')

    rows = MaBdd.get_all_certfr_by_cve()
    R_out.tab2_to_txt("txt/CVE_CERTFR.txt",rows)

    rows = MaBdd.get_all_orphan()
    R_out.tab2_to_txt("txt/Orphan.txt",rows)


    if os.path.exists('RIA_uri_manual.txt'):
        print ("traitement des fichiers de recherche URI manuelle")
        logging.info('Sortie pour les futurs mogs')
        file=open("RIA_uri_manual.txt")
        lignes=file.read().splitlines()
        pbar =  tqdm(total=len(lignes),unit="Fichier",ascii=True,desc="Uri")
        for ligne in lignes:
            pbar.update(1)
            info=ligne.split(";")
            R_out.URI_to_FILE(info[0],info[1])
        file.close()
        pbar.close()

    MaBdd.close_db()

    print("Bye Bye")
    logging.info('fin de traitement')

##
# Brief A cause de Doxygen pour la docs
mon_script()
