##Le coeur
# @file RIA.py
# @author Frack113
# @date 14/04/2020
# @brief Recherche d'Informations Automatisées
# @todo utiliser les best practice Python
# @todo ajouter des options en cmd --forceupdate --help ...
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
import sys
import datetime
import requests
import shutil
from tqdm import tqdm
import logging
import argparse

sys.path.append ('./package')
from RIA_class import *
from RIA_sql import *
from RIA_mskb import *
from RIA_wrapper import *
from RIA_out import *

##
#@brief Affiche simplement le crédit
def credit():
    mon_credit="""
                             ____ ____ ____
                            ||R |||I |||A ||
                            ||__|||__|||__||
                            |/__\|/__\|/__\|

                              Recherche
                                 d'Informations
                                       Automatisées

       /^\\
      | " |
/\\     |_|     /\\
| \\___/' `\\___/ |
 \_/  \\___/  \\_/
  |\\__/   \\__/|               Version 1.1
  |/  \\___/  \\|              Slow is best
 ./\\__/   \\__/\\,
 | /  \\___/  \\ |
 \\/     V     \\/

    lancer "RIA.py -h" pour plus d'options
    """
    print(mon_credit)

## 
# @brief initialisation des variables
def Init_env ():
    global MaBdd
    global Ksoft
    logging.basicConfig(filename='Update_certfr.log',
                        level=logging.INFO,
                        format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    logging.info('-------------------------------------')
    logging.info('        Lancement du script')
    if os.path.exists("txt"):
        pass
    else:
        os.mkdir("txt")
        logging.warning('Manque le répertoire de sortie txt')

    if os.path.exists("mogs"):
        pass
    else:
        os.mkdir("mogs")
        logging.warning('Manque le répertoire de sortie mogs')

    if os.path.exists('RIA.db'):
        logging.info('RIA.db ok')
    else:
        logging.warning('Manque le fichier de bdd initial')
        dest = shutil.copyfile('RIA_init.db','RIA.db')
    
    MaBdd=C_sql()
    
## 
# @brief le coeur du script
# @todo simplifier les répétitions
def mon_IA():
    today=datetime.datetime.now().strftime("%Y%m%d")
   
    credit()
 
    MaBdd.clean_new()
    MaBdd.clean_tmp()

    if os.path.exists('RIA_mogs.txt'):
        logging.info("Traitement avec l'aide des mogs")
        MaBdd.load_mogs()

    if args.ForceWrapper :
       MaBdd.Reset_Info_date()
    
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

    print ("Chargement des mises à jour CERTFR")
    updates=Wrapper.Read_wrapper_info("Module","CERTFR",True,True)
    logging.info("Update CERTFR : "+str(len(updates)))
    for update in updates:
        Wrapper.Load_TAR_certfr(update.Fichier)
        logging.warning(update.Fichier+ " mis à jour")

    print ("Chargement des mises à jour CVE")
    updates=Wrapper.Read_wrapper_info("Module","CVE",True,True)
    logging.info("Update CVE : "+str(len(updates)))
    for update in updates:
        Wrapper.Load_ZIP_cve(update.Fichier)
        logging.warning(update.Fichier+ " mis à jour")
 
    # On met à jour les informations trouvées
    logging.warning("Couple URL/CVE trouvé :"+ str(Wrapper.Count_New_urlcve()))
    
    #Il y a des CVE manquantes ?
    cves=MaBdd.get_all_cve_orphan()
    if cves:
        logging.info(str(len(cves))+" CVE non présente sur le NIST")
        moncve=C_cve()
        moncve.New=1
        for strcve in cves:
            moncve.id=strcve[0]
            moncve.set_crc()
            MaBdd.write_cve_tmp(moncve)
    
    MaBdd.flush_tmp()
    MaBdd.flush_url()

 #       Pour vérifier la sortie sans avoir de mise à jour :)
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 WHERE nom LIKE '%2020%';")
    #MaBdd.write_sc("UPDATE CERTFR SET New=1 ;")

    print("Traitement des sorties")
    R_out=C_out(MaBdd,Ksoft)

    rows=MaBdd.get_all_new_certfr()
    logging.info("Get_all_new_certfr :"+str(len(rows)))
    pbar = tqdm(total=len(rows),ascii=True,desc="Bulletin")
    for bul in rows:
        pbar.update(1)
        logging.info(f'mise à jour de {bul[0]}')
        re_result=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul[0])
        R_out.Write_CERTFR(bul[0],re_result.group('an'))
    pbar.close()

    if args.Json:
        print("Sortie Json ...")
        R_out.Export_certfr_json("new.json",'LIKE "%" AND New=1')

    rows = MaBdd.get_all_certfr_by_cve()
    R_out.tab2_to_txt("txt/CVE_CERTFR.txt",rows)

    rows = MaBdd.get_all_orphan()
    R_out.tab2_to_txt("txt/Orphan.txt",rows)


    if args.Uri and os.path.exists('RIA_uri_manual.txt'):
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


def Close_env():
    MaBdd.close_db()
    print("Bye Bye")
    logging.info('fin de traitement')


def affiche_etat():
    dict=MaBdd.Get_DB_info()
    print ("Informations de la BDD")
    for key,values in dict.items():
        print(f"{key:^20} : {values}")
    
##
# Brief la ligne de commande
parser = argparse.ArgumentParser(description='Les options')
parser.add_argument('--ForceWrapper', dest='ForceWrapper',action='store_true',default=False,help='Force la mise à jour du Wrapper')
parser.add_argument('--Etat', dest='Etat',action='store_true',default=False,help='Etat de la BDD')
parser.add_argument('--Uri', dest='Uri',action='store_true',default=False,help='Ecrit les fichiers uri')
parser.add_argument('--Json', dest='Json',action='store_true',default=False,help='Ecrit les fichiers json')
args = parser.parse_args()

Init_env ()

if args.Etat:
    affiche_etat()
else:
    mon_IA()

Close_env()
