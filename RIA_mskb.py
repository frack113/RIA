# Version 0
# fonctionne 
# TODO :
#   ne telecharger que les nouvelles url
#   separer la api_key
#Wsus cab http://go.microsoft.com/fwlink/?linkid=74689

import requests
import json
import re
from RIA_sql import *

class C_mskb:
    def __init__(self,MaBdd):
        self.api_key='dans le fichier RIA_mskb.key '

        file=open('RIA_mskb.key','r')
        key=file.readline()
        file.close()
        self.api_key=key.replace('\n','')
        
        self.api_type='application/json'
        self.api_url='https://api.msrc.microsoft.com/updates?api-version=2017'
        self.header={'Accept': self.api_type,'api-key': self.api_key}
        self.MaBdd=MaBdd
        self.MaBdd.write_sc("""
         CREATE TABLE IF NOT EXISTS MS_Product (ProductID TEXT UNIQUE NOT NULL,Value text);
         CREATE TABLE IF NOT EXISTS MS_Vuln (CVE TEXT,FIX_ID TEXT UNIQUE,ProductID TEXT,URL TEXT,Supercedence TEXT,Type TEXT);
        """)



    def reset_db(self):
        self.MaBdd.write_sc("""
         DELETE FROM MS_Product;
         DELETE FROM MS_Vuln;
        """)

    def update_all_url(self):
        rep= requests.get(self.api_url,headers=self.header)
        jsontmp=json.loads(rep.text)
        rep.close()
        return jsontmp['value']
    
    def write_product(self,ProductID,Value):
        self.MaBdd.write_sc(f'INSERT OR IGNORE INTO MS_Product VALUES("{ProductID}","{Value}");')
       
    def write_cve_kb(self,ms_cve,fix_id,product,ms_url,fix_Supercedence,typekb):
        self.MaBdd.write_sc(f'INSERT OR IGNORE INTO MS_Vuln VALUES("{ms_cve}","{fix_id}","{product}","{ms_url}","{fix_Supercedence}","{typekb}");')

    def update_all_info(self):
        for security_update in self.update_all_url():
            url=security_update['CvrfUrl']
            rep=requests.get(url,headers=self.header)
            jsoncve=json.loads(rep.text)
            rep.close()
    
            if 'FullProductName' in jsoncve['ProductTree']:
                for ref in jsoncve['ProductTree']['FullProductName']:
                    self.write_product(ref["ProductID"],ref["Value"])
            
            if 'Vulnerability' in jsoncve:
                for data in jsoncve['Vulnerability']:
                    ms_cve=data['CVE']
                for kb in data['Remediations']:
                    if kb['Type']==2:  #2 vendor Fix
                        fix_id=kb['Description']['Value']
                    ms_url=''
                    if 'URL' in kb:
                        ms_url=kb['URL']
                    fix_Supercedence=''
                    if 'Supercedence' in kb:
                        fix_Supercedence=kb['Supercedence']
                    typekb=''
                    if 'SubType' in kb:
                        typekb=kb['SubType']
                        for product in kb['ProductID']:
                            self.write_cve_kb(ms_cve,fix_id,product,ms_url,fix_Supercedence,typekb)

    def get_info_certfr(self,certfr):
        return self.MaBdd.get_sc(f'select CVE,Value,FIX_ID,Url,type from MS_vuln left JOIN MS_Product ON MS_vuln.ProductID=MS_Product.ProductID WHERE MS_vuln.CVE IN (SELECT CVE from CERTFR_cve WHERE BULTIN="{certfr}");')
