import requests
import re
import sqlite3

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

def check_git():
    update=True
    cursor.execute('SELECT * FROM URL_CK WHERE Mod="gitlab";')
    row=cursor.fetchone()
    if row :
        r_web= requests.head(row[0])
        if r_web.headers['Last-Modified']==row[1]:
            update=False
    else:
        row=['https://about.gitlab.com/releases/categories/releases/','date','gitlab']
    if update:
        r_web= requests.get(row[0])
        row[1]= r_web.headers['Last-Modified']
        cursor.execute(f'INSERT OR REPLACE INTO URL_CK VALUES("{row[0]}","{row[1]}","{row[2]}")')
        feed=re.findall("href='(/releases/\d{4}/\d{2}/\d{2}/.*-released)",r_web.text)
        for url in feed:
            git_web=requests.get('https://about.gitlab.com'+url+'/')
            cve=re.findall('CVE-\d+-\d+',git_web.text)
            str_cve=str(cve)
            date=git_web.headers['Last-Modified']
            cursor.execute(f'INSERT OR IGNORE INTO URL_cve VALUES ("{url}","{str_cve}","{date}");')
            git_web.close()
        r_web.close()


##############
# start
##############
check_git()


#kasper https://support.kaspersky.com/general/vulnerability.aspx?el=12430
from bs4 import BeautifulSoup
r_web=requests.get('https://support.kaspersky.com/general/vulnerability.aspx?el=12430')
soup=BeautifulSoup(r_web.text)
for div in soup.findAll("div",class_="wincont_c3"):
    break
    #print ('<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>')
    #print (div)

r_web.close()



# Ubuntu https://usn.ubuntu.com/months/
info=['https://usn.ubuntu.com/months/','date','Ubuntu']
info[1]=check_update('ck','https://usn.ubuntu.com/months/')
if info[1]:
    r_web=requests.get('https://usn.ubuntu.com/months/')
    cursor.execute(f'INSERT OR REPLACE INTO URL_CK VALUES("{info[0]}","{info[1]}","{info[2]}")')
    feed=re.findall('https://usn.ubuntu.com/\d+-\d+/',r_web.text)
    for url in feed:
        date=check_update('cve',url)
        if date:
            kas_web=requests.get(url)
            cve=re.findall('CVE-\d+-\d+',kas_web.text)
            str_cve=str(cve)
            cursor.execute(f'INSERT OR IGNORE INTO URL_cve VALUES ("{url}","{str_cve}","{date}");')
            kas_web.close()
    r_web.close()
               
#cursor.execute('VACUUM "main";')
Localdb.commit()
Localdb.close()
