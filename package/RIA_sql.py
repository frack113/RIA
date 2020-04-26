## La gestion de la base de données
# @file RIA_sql.py
# @author Frack113
# @date 14/04/2020
# @brief Class pour les interactions avec la Bdd
# @details Python help
from  RIA_class import *
import sqlite3
import copy
import hashlib

##
# @brief Manipulation de la BDD
# @details Python help
class C_sql:
    """ Class pour interagir avec la BDD en sqlite3
    """
    ##
    # @brief constructors
    # @details Python help
    def __init__ (self):
        """ le constructor
        on utilise PRAGMA pour optimiser les écritures
        ouvre le fichier RIA.db
        Crée les tables de travail
        """
        ## le fichier MaBdd
        self.Localdb=sqlite3.Connection("RIA.db")
        ## le curseur dans la Bdd
        self.moncur=self.Localdb.cursor()
        self.moncur.executescript("""
          PRAGMA journal_mode = 'MEMORY';
          PRAGMA secure_delete = '0';
          PRAGMA temp_store = '2';
          CREATE TABLE IF NOT EXISTS Info (Quoi TEXT UNIQUE,Date TEXT);
          CREATE TABLE IF NOT EXISTS CERTFR_Url (Hkey TEXT UNIQUE,Nom TEXT,Url TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS CERTFR (Hkey TEXT UNIQUE,
                                             Nom TEXT UNIQUE NOT NULL,
                                             Obj TEXT,
                                             Dateo TEXT,
                                             Datem TEXT,
                                             New integer,
                                             file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_tmp (Hkey TEXT UNIQUE,
                                                 Nom TEXT UNIQUE NOT NULL,
                                                 Obj TEXT,
                                                 Dateo TEXT,
                                                 Datem TEXT,
                                                 New integer,
                                                 file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_cve (Hkey TEXT UNIQUE,
                                                 BULTIN TEXT NOT NULL,
                                                 cve_id TEXT);
          CREATE TABLE IF NOT EXISTS CVE (Hkey TEXT UNIQUE,
                                          cve_id TEXT,
                                          cve_cvss3 TEXT,
                                          cve_cvss3base INTEGER,
                                          cve_cvss2 TEXT,
                                          cve_cvss2base INTEGER,
                                          cve_pdate TEXT,
                                          cve_ldate TEXT,
                                          new INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_tmp (Hkey TEXT UNIQUE,
                                              cve_id TEXT,
                                              cve_cvss3 TEXT,
                                              cve_cvss3base INTEGER,
                                              cve_cvss2 TEXT,
                                              cve_cvss2base INTEGER,
                                              cve_pdate TEXT,
                                              cve_ldate TEXT,
                                              new INTERGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe (Hkey TEXT UNIQUE,
                                              cve_id TEXT,
                                              conf INTERGER,
                                              ope TEXT,
                                              vuln TEXT,
                                              cpe TEXT,
                                              versionStartExcluding TEXT,
                                              versionStartIncluding TEXT,
                                              versionEndExcluding TEXT,
                                              versionEndIncluding TEXT,
                                              New INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe_tmp (Hkey TEXT UNIQUE,
                                                  cve_id TEXT,
                                                  conf INTEGER,
                                                  ope TEXT,
                                                  vuln TEXT,
                                                  cpe TEXT,
                                                  versionStartExcluding TEXT,
                                                  versionStartIncluding TEXT,
                                                  versionEndExcluding TEXT,
                                                  versionEndIncluding TEXT,
                                                  New INTEGER);
        """)

    ##
    # @brief fermeture
    # @details Python help
    def close_db (self):
        """ fonction de sauvegarde et fermeture
        """
        self.moncur.execute('PRAGMA integrity_check;')
        self.moncur.execute('VACUUM "main";')
        self.Localdb.commit()
        self.Localdb.close()

    ##
    # @brief Sauvegarde
    # @details Python help
    def save_db (self):
        """ fonction de sauvegarde des transactions en cours
        """
        self.Localdb.commit()

    ##
    # @brief cherche une date dans la table information
    # @param quoi ce que l'on recherche
    # @todo changer le nom des champs en plus explicite
    # @details Python help
    def get_Info_date(self,quoi):
        """ Renvoie la date ou '' pour la recherche 'quoi' dans la table Info
        """
        self.moncur.execute(f'SELECT Date FROM Info WHERE Quoi="{quoi}";')
        row=self.moncur.fetchone()
        if row:
            return row[0]
        else:
            return ""

    ##
    # @brief écrit dans la table information
    # @param quoi  le champ
    # @param date  la date
    # @details Python help
    def set_Info_date (self,quoi,date):
        """ Sauvegarde la date pour la recherche 'quoi' dans la table Info
        """
        self.moncur.execute(f'INSERT OR REPLACE INTO Info VALUES("{quoi}","{date}");')

    ##
    # @brief remet à zéro la table information
    # @details Python help
    def Reset_Info_date (self):
        """ Remet la date pour la recherche au '19750101' dans la table Info
        """
        self.moncur.execute("UPDATE Info SET date='19750101';")
    ##
    # @brief efface les tables temporaires
    # @details Python help
    def clean_tmp (self):
        """Efface les tables temporaires CERTFR_tmp,CVE_tmp et CVE_cpe_tmp
        """
        self.moncur.executescript("""
         DELETE FROM CERTFR_tmp;
         DELETE FROM CVE_tmp;
         DELETE FROM CVE_cpe_tmp;
        """)

    ##
    # @brief Met New à "0"
    # @details Python help
    def clean_new (self):
        """ Met à 0 le champ New pour CERTFR,CVE et CVE_cpe
        """
        self.moncur.executescript("""
         UPDATE CERTFR SET New=0;
         UPDATE CVE SET New=0;
         UPDATE CVE_cpe SET New=0;
        """)
    ##
    # @brief Exécute un script sqlite sans retour
    # @param script le sql
    # @details Python help
    def write_sc (self,script):
        """Exécute le "script" SQL sans retour
        """
        self.moncur.executescript(script)

    ##
    # @brief Exécute un script sqlite
    # @param script le sql
    # @return une liste
    # @details Python help
    def get_sc (self,script):
        """ Exécute le "script" SQL et renvoie une liste de tous les résultats
        """
        self.moncur.execute(script)
        return self.moncur.fetchall()

    ##
    # @brief Ecrit en BDD un bulletin
    # @param monbul un C_certfr
    # @details Python help
    def write_certfr_tmp (self,monbul):
        """ Ecrit un bulletin dans la table CERTFR_tmp 
        Ecrit les liens dans la table CERTFR_Url
        monbul est un C_certfr
        """
        self.moncur.execute(f'''INSERT INTO CERTFR_tmp VALUES("{monbul.crc}",
                                                              "{monbul.nom}",
                                                              "{monbul.obj}",
                                                              "{monbul.dateOrigine}",
                                                              "{monbul.dateUpdate}",
                                                               {monbul.New},
                                                              "{monbul.file}");''')
        for url in monbul.link:
            str_hkey=f'{monbul.nom}_{url}'
            crc=hashlib.sha1(str_hkey.encode()).hexdigest()
            self.moncur.execute(f'''INSERT OR IGNORE INTO CERTFR_Url VALUES("{crc}",
                                                                            "{monbul.nom}",
                                                                            "{url}",
                                                                             1);''')

    ##
    # @brief Ecrit en BDD un binône CERTFR/CVE
    # calcul le CRC automatiquement
    # @param certfr nom du bulletin
    # @param cve nom du cve
    # @details Python help
    def write_certfr_cve (self,certfr,cve):
        """ Ecrit en BDD une CVE dans la table CERTFR_tmp
        Et calcule la Hkey UNIQUE
        """
        Hkey=certfr+'_'+cve
        self.moncur.execute(f'''INSERT OR IGNORE INTO CERTFR_CVE VALUES("{Hkey}",
                                                                        "{certfr}",
                                                                        "{cve}");''')

    ##
    # @brief Ecrit en BDD un CVE
    # @param moncve un C_cve
    # @details Python help
    def write_cve_tmp (self,moncve):
        """Ecrit en BDD un CVE dans la table CVE_tmp
        moncve est un C_cve
        """
        self.moncur.execute(f'''INSERT INTO CVE_tmp VALUES("{moncve.crc}",
                                                           "{moncve.id}",
                                                           "{moncve.cvssV3}",
                                                            {moncve.cvssV3base},
                                                           "{moncve.cvssV2}",
                                                            {moncve.cvssV2base},
                                                           "{moncve.dateOrigine}",
                                                           "{moncve.dateUpdate}",
                                                            {moncve.New});''')

    ##
    # @brief Ecrit en BDD un CPE
    # @param moncpe un C_cpe
    # @details Python help
    def write_cpe_tmp (self,moncpe):
        """ Ecrit en BDD un CPE dans la table CVE_cpe_tmp
        moncpe est un C_cpe
        """
        self.moncur.execute(f'''INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{moncpe.crc}",
                                                                         "{moncpe.cve}",
                                                                          {moncpe.conf},
                                                                         "{moncpe.operateur}",
                                                                         "{moncpe.vulnerable}",
                                                                         "{moncpe.cpe23uri}",
                                                                         "{moncpe.versionStartExcluding}",
                                                                         "{moncpe.versionStartIncluding}",
                                                                         "{moncpe.versionEndExcluding}",
                                                                         "{moncpe.versionEndIncluding}",
                                                                          {moncpe.New});''')

    ##
    # @brief Tranfère les tables tmp vers les mains
    # @details Python help
    def flush_tmp (self):
        """ Transfère les données de
            CERTFR_tmp vers CERTFR
            CVE_tmp vers CVE
            CVE_cpe_tmp vers CVE_cpe
        gestion des doublons :
         1 Hkey déjà présente
         2 suppression des ancients enregistrements table officielle
         3 copie des données restantes
         4 efface les tables temporaires
        """
        self.moncur.executescript("""
          DELETE FROM CERTFR_tmp WHERE Hkey IN (SELECT Hkey FROM CERTFR);
          DELETE FROM CERTFR WHERE nom IN (SELECT nom FROM CERTFR_tmp);
          INSERT INTO CERTFR SELECT * FROM CERTFR_tmp;
          DELETE FROM CERTFR_tmp;

          DELETE FROM CVE_tmp WHERE hkey IN (SELECT DISTINCT Hkey FROM CVE);
          DELETE FROM CVE WHERE cve_id IN (SELECT cve_id FROM CVE_tmp);
          INSERT OR replace INTO CVE SELECT * from CVE_tmp;
          DELETE FROM CVE_tmp;

          DELETE FROM CVE_cpe_tmp WHERE hkey IN (SELECT DISTINCT Hkey FROM CVE_cpe);
          INSERT OR replace INTO CVE_cpe SELECT * from CVE_cpe_tmp;
          DELETE FROM CVE_cpe_tmp;

          UPDATE CVE SET New=1 WHERE cve_id IN (select cve_id FROM CVE_cpe where New=1);
          INSERT INTO CVE_tmp SELECT * FROM CVE WHERE New=1;
          UPDATE CERTFR SET New=1 WHERE nom IN (SELECT DISTINCT BULTIN FROM CERTFR_cve JOIN CVE_tmp WHERE CERTFR_cve.cve_id=CVE_tmp.cve_id);
          DELETE FROM CVE_tmp;
        """)

    ##
    # @brief Cherche tous les CERTFR mis à jour par les URL
    # @details Python help
    def flush_url (self):
        """ Mise à jour du champ New des CERTFR par rapport au wrapper URL
        1 URL_info(wrapper URL) vers CERTFR_Url (wrapper CERTFR)
        2 CERTFR_Url vers CERTFR
        3 URL_cve (wrapper URL) vers CVE (wrapper NIST CVE)
        4 CVE vers CERTFR
        """
        self.moncur.executescript("""
            UPDATE CERTFR_Url SET New=1 WHERE Url IN (SELECT Url from URL_info WHERE New=1);
            UPDATE URL_info SET New=0;

            UPDATE CERTFR SET new=1 WHERE nom IN (SELECT DISTINCT Nom FROM CERTFR_URL WHERE New=1);
            UPDATE CERTFR_URL SET New=0;

            UPDATE CVE SET New=1 WHERE cve_id IN (SELECT DISTINCT cve_id FROM URL_cve WHERE New=1);
            UPDATE URL_cve SET New=0;

            INSERT INTO CVE_tmp SELECT * FROM CVE WHERE New=1;
            UPDATE CERTFR SET new=1 WHERE nom IN (SELECT DISTINCT BULTIN FROM CERTFR_cve JOIN CVE_tmp WHERE CERTFR_cve.cve_id=CVE_tmp.cve_id);
            DELETE FROM CVE_tmp;
        """)

    ##
    # @brief convertie un retour sql en list C_certfr
    # @details Python help
    def Certfr_tab_to_liste(self,tab):
        ''' Help me'''
        allcert=[]
        monbul=C_certfr()
        for row in tab:
            monbul.crc=row[0]
            monbul.nom=row[1]
            monbul.obj=row[2]
            monbul.dateOrigine=row[3]
            monbul.dateUpdate=row[4]
            monbul.New=row[5]
            monbul.file=row[6]
            self.moncur.execute(f'SELECT Url FROM CERTFR_Url WHERE Nom="{monbul.nom}";')
            monbul.link=self.moncur.fetchall()
            allcert.append(copy.copy(monbul))
        return allcert

    ##
    # @brief Renvoie tous les bulletins mis à jour
    # @return liste de C_certfr
    # @details Python help
    def get_all_new_certfr (self):
        """ renvoie une liste de C_certfr de tous de bulletins avec New=1
        """
        self.moncur.execute("SELECT * FROM CERTFR WHERE New=1;")
        allnewtab=self.moncur.fetchall()
        return self.Certfr_tab_to_liste(allnewtab)


    ##
    # @brief lit un bulletin en BDD
    # @param nom
    # @return C_certfr
    # @details Python help
    def get_certfr (self,nom):
        """ lit un bulletin dont le Nom ="nom"
        nom est une String
        renvoie un C_certfr (vide si pas trouvé en BDD)
        """
        monbul=C_certfr()
        self.moncur.execute(f'SELECT * FROM CERTFR WHERE Nom="{nom}";')
        row=self.moncur.fetchone()
        if row:
            monbul.crc=row[0]
            monbul.nom=row[1]
            monbul.obj=row[2]
            monbul.dateOrigine=row[3]
            monbul.dateUpdate=row[4]
            monbul.New=row[5]
            monbul.file=row[6]
            self.moncur.execute(f'SELECT Url FROM CERTFR_Url WHERE Nom="{nom}";')
            monbul.link=self.moncur.fetchall()
        return monbul

    ##
    # @brief renvoie tous les CVE d'un bulletin
    # @param certfr nom du bulletin
    # @return liste de C_cve ou une liste vide
    # @details Python help
    def get_all_cve_certfr (self,certfr):
        """Renvoie tous les CVE d'un bulletin ou une liste vide
        certfr est un string
        """
        all_cve=[]
        moncve=C_cve()
        self.moncur.execute(f"SELECT DISTINCT * FROM CVE WHERE cve_id IN (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{certfr}') ORDER BY cve_id;")
        rows=self.moncur.fetchall()
        if rows:
            for row in rows:
                moncve.reset()
                moncve.crc=row[0]
                moncve.id=row[1]
                moncve.cvssV3=row[2]
                moncve.cvssV3base=row[3]
                moncve.cvssV2=row[4]
                moncve.cvssV2base=row[5]
                moncve.dateOrigine=row[6]
                moncve.dateUpdate=row[7]
                moncve.New=row[8]
                all_cve.append(copy.copy(moncve))
        return all_cve

    ##
    # @brief lit un liste de bulletins en BDD
    # @param sql la requête SQL
    # @return liste de C_certfr
    # @details Python help
    def Get_Liste_certfr (self,sql):
        """ lit un liste de bulletins en BDD depuis la requête sql
        sql est un string sql
        renvoie une liste de C_certfr
        """
        self.moncur.execute(sql)
        rows=self.moncur.fetchall()
        allcert=self.Certfr_tab_to_liste(rows)
        return allcert
        
    ##
    # @brief lit les N derniers bulletins en BDD
    # @param nom
    # @return liste de C_certfr
    # @details Python help
    def Get_Last_N_certfr (self,nb):
        """ lit les N dernier bulletins avec ROWID DESC LINIT 'NB';
        nb est un interger
        renvoie un C_certfr vide si pas trouvé en BDD par securité
        """
        return self.Get_Liste_certfr(f'SELECT * FROM (SELECT * FROM CERTFR ORDER BY ROWID DESC LIMIT {nb}) ORDER BY Nom;')
 
    
    ##
    # @brief Taille max des uri23 d'un bulletin
    # @param certfr nom du bulletin
    # @return la taille (nb de caractères)
    # @todo gérer les erreurs
    # @details Python help
    def get_max_lg_uri_cpe (self,certfr):
        """Donne la taille max des uri23 pour un bulletin
        certfr est une string
        """
        self.moncur.execute(f"SELECT max(length(cpe)) FROM CVE_cpe WHERE cve_id IN (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{certfr}');")
        return self.moncur.fetchone()[0]

    ##
    # @brief renvoie tous les CPE d'un bulletin
    # @param certfr nom du bulletin
    # @return liste de C_cpe ou None
    # @details Python help
    def get_all_cpe_certfr (self,certfr):
        """Renvoie une liste de C_cpe pour un bulletin
        certfr est une string
        """
        all_cpe=[]
        moncpe=C_cpe()
        self.moncur.execute(f"SELECT DISTINCT * FROM CVE_cpe WHERE cve_id IN (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{certfr}') ORDER BY cve_id,conf ASC,vuln DESC;")
        rows=self.moncur.fetchall()
        if rows:
            for row in rows:
                moncpe.reset()
                moncpe.crc=row[0]
                moncpe.cve=row[1]
                moncpe.conf=row[2]
                moncpe.operateur=row[3]
                moncpe.vulnerable=row[4]
                moncpe.cpe23uri=row[5]
                moncpe.versionStartExcluding=row[6]
                moncpe.versionStartIncluding=row[7]
                moncpe.versionEndExcluding=row[8]
                moncpe.versionEndIncluding=row[9]
                moncpe.New=row[10]
                all_cpe.append(copy.copy(moncpe))
        return all_cpe

    ##
    # @brief renvoie tous les cpe pour un uri23
    # @param uri une partie de l'URI à chercher
    # @return liste 
    # @details Python help
    def get_tab_all_cpe_uri (self,uri):
        """Renvoie une liste de liste de tous les cpe pour un uri23
        recherche sql like %uri%
        uri est une String
        """
        self.moncur.execute(f'SELECT * FROM CVE_cpe WHERE cve_id IN (SELECT DISTINCT cve_id FROM CVE_cpe WHERE cpe LIKE "%{uri}%") ORDER BY cve_id')
        return self.moncur.fetchall()
        
    ##
    # @brief renvoie tous les cpe pour un uri23
    # @param uri une partie de l'URI à chercher
    # @return liste de C_cpe ou None
    # @details Python help
    def get_all_cpe_uri (self,uri):
        """Renvoie tous les cpe pour un uri23
        recherche sql like %uri%
        uri est une String
        """
        all_cpe=[]
        moncpe=C_cpe()
        rows=self.get_tab_all_cpe_ur(uri)
        if rows:
            for row in rows:
                moncpe.reset()
                moncpe.crc=row[0]
                moncpe.cve=row[1]
                moncpe.conf=row[2]
                moncpe.operateur=row[3]
                moncpe.vulnerable=row[4]
                moncpe.cpe23uri=row[5]
                moncpe.versionStartExcluding=row[6]
                moncpe.versionStartIncluding=row[7]
                moncpe.versionEndExcluding=row[8]
                moncpe.versionEndIncluding=row[9]
                moncpe.New=row[10]
                all_cpe.append(copy.copy(moncpe))
        return all_cpe


        
    ##
    # @brief Les bulletins par obj sans CVE
    # @param obj chaîne à chercher
    # @return liste ou []
    # @details Python help
    def get_orphan_by_obj (self,obj):
        """Renvoie une liste des noms de bulletins et objets sans CVE
         obj chaîne à chercher dans les objets des bulletins
         utilise la fonction SQL LIKE
        """
        self.moncur.execute(f'SELECT Nom,Obj FROM CERTFR WHERE Nom NOT IN (SELECT DISTINCT BULTIN FROM CERTFR_cve) AND Obj LIKE "%{obj}%";')
        return self.moncur.fetchall()

    ##
    # @brief Les bulletins par CVE
    # @return liste ou []
    # @details Python help
    def get_all_certfr_by_cve (self):
        """Renvoie une liste de tous les couples CVE/Bulletins
        """
        self.moncur.executescript("""
         DROP TABLE IF EXISTS CVE_BULTIN;
         CREATE TABLE CVE_BULTIN AS SELECT cve_id, group_concat(DISTINCT BULTIN) FROM CERTFR_cve GROUP BY cve_id;
         ALTER TABLE CVE_BULTIN RENAME COLUMN 'group_concat(DISTINCT BULTIN)' TO CERTFR;
        """)
        self.moncur.execute('SELECT * FROM CVE_BULTIN;')
        return self.moncur.fetchall()

    ##
    # @brief Bulletin par obj sans CVE
    # @return liste ou []
    # @details Python help
    def get_all_orphan (self):
        """ Renvoie une liste de tous les bulletins et Objets sans CVE
        """
        self.moncur.execute("SELECT Nom,Obj FROM CERTFR WHERE Nom NOT IN (SELECT DISTINCT BULTIN FROM CERTFR_cve);")
        return self.moncur.fetchall()

    ##
    # @brief Les CVE non présentes sur le NIST
    # @return liste ou []
    # @details Python help
    def get_all_cve_orphan (self):
        """ Renvoie une liste de toutes les CVE des bulletins non présentes sur le nist
        Soit elles ne sont pas encore valides soit le CERTFR a mal formaté son bulletin
        """
        self.moncur.execute("SELECT DISTINCT cve_id FROM CERTFR_cve WHERE cve_id NOT IN (SELECT DISTINCT cve_id from CVE);")
        return self.moncur.fetchall()

    ##
    # @brief Charge en BDD les couples CERTFR;CVE trouvés manuellement
    # @details Python help
    def load_mogs (self):
        """ Charge en BDD les couples CERTFR;CVE trouvés manuellement
        les informations sont dans 'RIA_mogs.txt'
        1 ligne par CERTFR;CVE
        """
        file=open('RIA_mogs.txt','r')
        lignes=file.read().splitlines()
        for ligne in lignes:
            info=ligne.split(";")
            self.write_certfr_cve(info[0],info[1])
        file.close()


    ##
    # @brief Info de la BDD pour l'aide en ligne
    # @details Python help
    def Get_DB_info(self):
        """ Récupère les informations pour l'aide
        """
        dict={}
        self.moncur.execute("SELECT count(*) FROM CERTFR;")
        dict['CERTFR']=self.moncur.fetchone()[0]
        self.moncur.execute("SELECT count(*) FROM CVE;")
        dict['CVE']=self.moncur.fetchone()[0]
        self.moncur.execute("SELECT count(*) FROM CVE_cpe;")
        dict['CPE']=self.moncur.fetchone()[0]
        self.moncur.execute("SELECT count(*) FROM Ms_Vuln;")
        dict['CVE Microsoft']=self.moncur.fetchone()[0]    
        self.moncur.execute("SELECT count(*) FROM URL_info;")
        dict['URL wrapper']=self.moncur.fetchone()[0]        
        self.moncur.execute("SELECT DISTINCT cve_id,count(*) FROM URL_cve;")
        dict['CVE wrapper']=self.moncur.fetchone()[1]         
        return dict
