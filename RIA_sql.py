from  RIA_class import *
import sqlite3
import copy

class C_sql:
    def __init__(self):
        self.Localdb=sqlite3.Connection("RIA.db")
        self.moncur=self.Localdb.cursor()
        self.moncur.executescript("""
          PRAGMA journal_mode = 'OFF';
          PRAGMA secure_delete = '0';
          PRAGMA temp_store = '2';
          CREATE TABLE IF NOT EXISTS Info (Quoi TEXT UNIQUE,Date TEXT);
          CREATE TABLE IF NOT EXISTS URL_file (Nom text UNIQUE NOT NULL,date text,taille text,source text,New integer);
          CREATE TABLE IF NOT EXISTS CERTFR_Url (Nom TEXT,Url TEXT);          
          CREATE TABLE IF NOT EXISTS CERTFR (Hkey TEXT UNIQUE,Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_tmp (Hkey TEXT UNIQUE,Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_cve (Hkey TEXT UNIQUE,BULTIN text NOT NULL,CVE text);
          CREATE TABLE IF NOT EXISTS CVE (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_tmp (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTERGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe (Hkey TEXT UNIQUE,cve_id TEXT,conf INTERGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe_tmp (Hkey TEXT UNIQUE,cve_id TEXT,conf INTEGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
        """)
        
    def close_db(self):
        self.moncur.execute('PRAGMA integrity_check;')
        self.moncur.execute('VACUUM "main";')
        self.Localdb.commit()
        self.Localdb.close()
        
    def save_db(self):
        self.Localdb.commit()

    def get_Info_date(self,quoi):
        self.moncur.execute(f'SELECT Date FROM Info WHERE Quoi="{quoi}";')
        row=self.moncur.fetchone()
        if row:
            return row[0]
        else:
            return ""
    
    def set_Info_date(self,quoi,date):
        self.moncur.execute(f'INSERT OR REPLACE INTO Info VALUES("{quoi}","{date}");')
    
    def clean_tmp(self):
        self.moncur.executescript("""
         DELETE FROM CERTFR_tmp;
         DELETE FROM CVE_tmp;
         DELETE FROM CVE_cpe_tmp;
        """)
        
    def clean_new(self):
        self.moncur.executescript("""
         UPDATE CERTFR SET New=0;
         UPDATE CVE SET New=0;
         UPDATE CVE_cpe SET New=0;
        """)
        
    def write_sc(self,script):
        self.moncur.executescript(script)

    def get_sc(self,script):
        self.moncur.execute(script)
        return self.moncur.fetchall()
    
    def write_certfr_tmp(self,monbul):
        self.moncur.execute(f'INSERT INTO CERTFR_tmp VALUES("{monbul.crc}","{monbul.nom}","{monbul.obj}","{monbul.dateOrigine}","{monbul.dateUpdate}",{monbul.New},"{monbul.file}");')
        for url in monbul.link:
            self.moncur.execute(f'INSERT OR IGNORE INTO CERTFR_Url VALUES("{monbul.nom}","{url}");')
        
    def write_certfr_cve(self,certfr,cve):
        Hkey=certfr+'_'+cve
        self.moncur.execute(f'INSERT OR IGNORE INTO CERTFR_CVE VALUES("{Hkey}","{certfr}","{cve}");')

    def write_cve_tmp(self,moncve):
        self.moncur.execute(f'INSERT INTO CVE_tmp VALUES("{moncve.crc}","{moncve.id}","{moncve.cvssV3}",{moncve.cvssV3base},"{moncve.cvssV2}",{moncve.cvssV2base},"{moncve.dateOrigine}","{moncve.dateUpdate}",{moncve.New});')

    def write_cpe_tmp(self,moncpe):
        self.moncur.execute(f'INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{moncpe.crc}","{moncpe.cve}",{moncpe.conf},"{moncpe.operateur}","{moncpe.vulnerable}","{moncpe.cpe23uri}","{moncpe.versionStartExcluding}","{moncpe.versionStartIncluding}","{moncpe.versionEndExcluding}","{moncpe.versionEndIncluding}",{moncpe.New});')

    def flush_tmp(self):
        self.moncur.executescript("""
          UPDATE CERTFR SET New=0;
          DELETE FROM CERTFR_tmp WHERE Hkey IN (SELECT Hkey FROM CERTFR);
          DELETE FROM CERTFR WHERE nom IN (SELECT nom FROM CERTFR_tmp);
          INSERT INTO CERTFR SELECT * FROM CERTFR_tmp;
          DELETE FROM CERTFR_tmp;

          UPDATE CVE SET New=0;
          DELETE FROM CVE_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE);
          DELETE FROM CVE WHERE cve_id IN (SELECT cve_id FROM CVE_tmp);
          INSERT OR replace INTO CVE SELECT * from CVE_tmp;
          DELETE FROM CVE_tmp;

          UPDATE CVE_cpe SET New=0;
          DELETE FROM CVE_cpe_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE_cpe);
          INSERT OR replace INTO CVE_cpe SELECT * from CVE_cpe_tmp;
          DELETE FROM CVE_cpe_tmp;

          UPDATE CVE SET New=1 WHERE cve_id IN (select cve_id FROM CVE_cpe where new=1);
          INSERT INTO CVE_tmp SELECT * FROM CVE WHERE New=1;
          UPDATE CERTFR SET new=1 WHERE nom IN (SELECT DISTINCT BULTIN FROM CERTFR_cve JOIN CVE_tmp WHERE CERTFR_cve.CVE=CVE_tmp.cve_id);
          DELETE FROM CVE_tmp;
        """)

    def get_url_info(self,nom):
        self.moncur.execute(f'SELECT * FROM URL_file WHERE Nom="{nom}";')
        return self.moncur.fetchone()

    def get_all_new_url(self):
        url=[]
        self.moncur.execute("SELECT * FROM URL_file WHERE New=1;")
        rows=self.moncur.fetchall()
        if rows:
            for row in rows:
                rep={'Nom' :row[0],'date':row[1],'taille':row[2],'source':row[3],'New':row[4]}
                url.append(rep)
        return url
    
    def set_url_info(self,nom,date,taille,scr):
        self.moncur.execute(f'INSERT OR REPLACE INTO URL_file VALUES("{nom}","{date}","{taille}","{scr}",1);')

    def get_all_new_certfr(self):
        self.moncur.execute("SELECT Nom FROM CERTFR WHERE New=1;")
        return self.moncur.fetchall()
    
    def get_certfr(self,nom):
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

    def get_all_cve_certfr(self,certfr):
        all_cve=[]
        moncve=C_cve()
        self.moncur.execute(f"SELECT DISTINCT * FROM CVE WHERE cve_id IN (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{certfr}') ORDER BY cve_id;")
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
        else:
            return None

    def get_max_lg_uri_cpe(self,certfr):
         self.moncur.execute(f"SELECT max(length(cpe)) FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{certfr}');")
         return self.moncur.fetchone()[0]
    
    def get_all_cpe_certfr(self,certfr):
        all_cpe=[]
        moncpe=C_cpe()
        self.moncur.execute(f"SELECT DISTINCT * FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{certfr}') ORDER BY cve_id,conf ASC,vuln DESC;")
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
        else:
            return None

    def get_all_cpe_uri(self,uri):
        all_cpe=[]
        moncpe=C_cpe()
        self.moncur.execute(f'SELECT DISTINCT * FROM CVE_cpe WHERE cpe LIKE "%{uri}%" ORDER BY cve_id;')
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
        else:
            return None

    def get_orphan_by_obj(self,obj):
        self.moncur.execute(f'SELECT Nom,Obj FROM CERTFR WHERE Nom NOT IN (SELECT DISTINCT BULTIN FROM CERTFR_cve) AND Obj LIKE "%{obj}%";')
        return self.moncur.fetchall()
    
    def get_all_certfr_by_cve(self):
        self.moncur.executescript("""
         DROP TABLE IF EXISTS CVE_BULTIN;
         CREATE TABLE CVE_BULTIN AS SELECT CVE, group_concat(DISTINCT BULTIN) FROM CERTFR_cve GROUP BY CVE;
         ALTER TABLE CVE_BULTIN RENAME COLUMN 'group_concat(DISTINCT BULTIN)' TO CERTFR;
        """)
        self.moncur.execute('SELECT * FROM CVE_BULTIN;')
        return self.moncur.fetchall()

    def get_all_orphan(self):
        self.moncur.execute("SELECT Nom,Obj FROM CERTFR WHERE Nom NOT IN (SELECT DISTINCT BULTIN FROM CERTFR_cve);")
        return self.moncur.fetchall()
