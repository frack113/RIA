import requests
import re
import sqlite3
from bs4 import BeautifulSoup
import json

Localdb=sqlite3.Connection("RIA_wrapper.db")
cursor=Localdb.cursor()
cursor.executescript("""
          PRAGMA journal_mode = 'OFF';
          PRAGMA secure_delete = '0';
          PRAGMA temp_store = '2';
          CREATE TABLE IF NOT EXISTS URL_ck (Url TEXT UNIQUE,Date TEXT,Mod TEXT);
          CREATE TABLE IF NOT EXISTS URL_cve (Url TEXT UNIQUE,CVE BLOB,Date TEXT);
        """)

def check_update(table,url):
    h_web=requests.head(url)
    date=h_web.headers['Last-Modified']
    if table=='cve':
        tab='URL_cve'
    else:
        tab='URL_ck'
    cursor.execute(f'SELECT Date FROM {tab} WHERE Url="{url}"')
    row=cursor.fetchone()
    if row :
        if date==row[0]:
            return None
        else:
            return date
    else:
        return date

def check_regex(info):
    info[1]=check_update('ck',info[0])
    print(info[1])
    if info[1]:
        r_web= requests.get(info[0])
        cursor.execute(f'INSERT OR REPLACE INTO URL_CK VALUES("{info[0]}","{info[1]}","{info[2]}")')
        feed=re.findall(info[3],r_web.text)
        print(info[3])
        print(feed)
        for url in feed:
            full_url=info[4]+url
            if full_url[-1]=='/':
                pass
            else:
                full_url=full_url+'/'
                
            print(full_url)
            date=check_update('cve',full_url)
            if date:
                feed_web=requests.get(full_url)
                cve=re.findall('CVE-\d+-\d+',feed_web.text)
                str_cve=str(cve)
                cursor.execute(f'INSERT OR IGNORE INTO URL_cve VALUES ("{full_url}","{str_cve}","{date}");')
                feed_web.close()
            r_web.close()



    
def check_Gitlab():
    info=['https://about.gitlab.com/releases/categories/releases/','date','Gitlab',r'<a class=cover href=\'(/releases/\d{4}/\d{2}/\d{2}/.*-released/)\'','https://about.gitlab.com']
    check_regex(info)

def check_Ubuntu():
    info=['https://usn.ubuntu.com/months/','date','Ubuntu',r'https://usn.ubuntu.com/\d+-\d+/','']
    check_regex(info)

def check_Kaspersky():
    info=['https://support.kaspersky.com/general/vulnerability.aspx?el=12430','date','Kaspersky']
    r_web=requests.get(info[0])
    info[1]=r_web.headers['Date']
    cursor.execute(f'INSERT OR REPLACE INTO URL_CK VALUES("{info[0]}","{info[1]}","{info[2]}")')
    soup=BeautifulSoup(r_web.text,'html.parser')
    for div in soup.findAll("div",class_="wincont_c3"):
        F_open=div.findAll(attrs={"class":"open"})
        F_cve=div.findAll(string=re.compile("CVE"))
        if F_open:
            g=re.findall(r'href="(.*)" id',str(F_open))
            full_url=info[0]+g[0]
            h=re.findall(r'CVE-\d+-\d+',str(F_cve))
            cve=str(h)
            cursor.execute(f'INSERT OR REPLACE INTO URL_cve VALUES("{full_url}","{cve}","{info[1]}")')
    r_web.close()

def check_Xen():
   info=['http://xenbits.xen.org/xsa/xsa.json','date','Xen']
   r_web=requests.get(info[0])
   info[1]=r_web.headers['Last-Modified']
   cursor.execute(f'INSERT OR REPLACE INTO URL_CK VALUES("{info[0]}","{info[1]}","{info[2]}")')
   r_json=json.loads(r_web.text)
   for node in r_json[0]['xsas']:
       ref=node['xsa']
       full_url="http://xenbits.xen.org/xsa/advisory-"+str(ref)+".html"
       if 'cve' in node:
           cve=node['cve']
       else:
           cve=[]
       cursor.execute(f'INSERT OR REPLACE INTO URL_cve VALUES("{full_url}","{cve}","{info[1]}")')

##############
# start
##############

check_Gitlab()
check_Ubuntu()
check_Kaspersky()
check_Xen()


Localdb.commit()
Localdb.close()
