from  RIA_class import *
import sqlite3

class C_sql:
    def __init__(self):
        self.Localdb=sqlite3.Connection("RIA.db")
        self.moncur=self.Localdb.cursor()
        self.moncur.executescript("""
          PRAGMA journal_mode = 'OFF';
          PRAGMA secure_delete = '0';
          PRAGMA temp_store = '2';
          CREATE TABLE IF NOT EXISTS URL_file (Nom text UNIQUE NOT NULL,date text,taille text);
          CREATE TABLE IF NOT EXISTS CERTFR (Hkey TEXT UNIQUE,Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_tmp (Hkey TEXT UNIQUE,Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
          CREATE TABLE IF NOT EXISTS CERTFR_cve (BULTIN text NOT NULL,CVE text);
          CREATE TABLE IF NOT EXISTS CVE (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_tmp (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTERGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe (Hkey TEXT UNIQUE,cve_id TEXT,conf INTERGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
          CREATE TABLE IF NOT EXISTS CVE_cpe_tmp (Hkey TEXT UNIQUE,cve_id TEXT,conf INTEGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
        """)
        
    def close_db(self):
        self.moncur.commit()
        self.moncur.close()

    def clean_tmp(self):
        self.moncur.executescript("""
         DELETE FROM CERTFR_tmp;
         DELETE FROM CVE_tmp;
         DELETE FROM CVE_cpe_tmp;
        """)
        
    def write_certfr_tmp(self,monbul):
        self.moncur.execute(f'INSERT INTO CERTFR_tmp VALUES("{monbul.crc}","{monbul.nom}","{monbul.obj}","{monbul.dateOrigine}","{monbul.dateUpdate}",{monbul.New},"{monbul.file}");')

    def write_certfr_cve(self,certfr,cve):
        self.moncur.execute(f'INSERT INTO CERTFR_CVE VALUES("{certfr}","{cve}");')

    def flush_tmp(self):
        self.moncur.executescript("""
          UPDATE CERTFR SET New=0;
          DELETE FROM CERTFR_tmp WHERE Hkey IN (SELECT Hkey FROM CERTFR);
          UPDATE CERTFR_tmp SET New=1;
          INSERT OR replace INTO CERTFR SELECT * FROM CERTFR_tmp;
          DELETE FROM CERTFR_tmp; 
        """)

    def get_url_info(self,nom):
        self.moncur.execute(f'SELECT * FROM URL_file WHERE Nom="{nom}";')
        return self.moncur.fetchone()
    
    def set_url_info(self,nom,date,taille):
        self.moncur.execute(f'INSERT OR REPLACE INTO URL_file VALUES("{nom}","{date}","{taille}");')
