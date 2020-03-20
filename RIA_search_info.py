import re
from os import listdir,mkdir
from os.path import isfile, join, exists
import zipfile
import tarfile
import json
import datetime
import sqlite3
import hashlib
import requests
import shutil
from tqdm import tqdm
from prompter import yesno
import base64
    

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


        Lecture des bulletin CERTFR depuis archive rar
        Lecture des cve depuis les json
        Gestion en SQLITE
        liste des KB microsoft API depuis 2016 
    
    """
    print(mon_credit)

def initBDD(mom_bdd):
    global myBD
    global mycur
    myBD=sqlite3.Connection(mom_bdd)
    mycur=myBD.cursor()
    mycur.executescript("""
    PRAGMA journal_mode = 'OFF';
    PRAGMA secure_delete = '0';
    PRAGMA temp_store = '2';
    CREATE TABLE IF NOT EXISTS URL_file (Nom text UNIQUE NOT NULL,date text,taille text);
    CREATE TABLE IF NOT EXISTS CERTFR (Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
    CREATE TABLE IF NOT EXISTS CERTFR_tmp (Nom text UNIQUE NOT NULL,Obj text,Dateo text,Datem text,New integer,file BLOB);
    CREATE TABLE IF NOT EXISTS CERTFR_cve (BULTIN text NOT NULL,CVE text);
    CREATE TABLE IF NOT EXISTS CVE (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTEGER);
    CREATE TABLE IF NOT EXISTS CVE_tmp (Hkey TEXT UNIQUE,cve_id TEXT,cve_cvss3 TEXT,cve_cvss3base INTEGER,cve_cvss2 TEXT,cve_cvss2base INTEGER,cve_pdate TEXT,cve_ldate TEXT,new INTERGER);
    CREATE TABLE IF NOT EXISTS CVE_cpe (Hkey TEXT UNIQUE,cve_id TEXT,conf INTERGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
    CREATE TABLE IF NOT EXISTS CVE_cpe_tmp (Hkey TEXT UNIQUE,cve_id TEXT,conf INTEGER,ope TEXT,vuln TEXT,cpe TEXT,versionStartExcluding TEXT,versionStartIncluding,versionEndExcluding TEXT,versionEndIncluding TEXT,New INTEGER);
    """) 

def charge_cert():
    sql="DELETE FROM CERTFR_tmp;"
    mycur.execute(sql)  
    files = [f for f in listdir("certfr/") if isfile(join("certfr/", f))]
    files.sort()
    pbar=tqdm(total=len(files), unit="file",ascii=True,desc="PARSE CERTFR")
    for file in files:
        pbar.update(1)
        archive=tarfile.open(join("certfr/",file),'r')    
        for nom in archive.getnames():
            if re.search('CERT(FR|A)\-\d+\-AVI\-\d+\.txt',nom):
               
                bul_nom=''
                bul_obj=''
                bul_date1=''
                bul_date2=''
                bul_cve=[]
                bultin_tar=archive.extractfile(nom).readlines()
                bultin_list=[x.decode('utf-8') for x in bultin_tar]
                bultin_avi=''.join(bultin_list)
                bultin_avi=re.sub('\\x0c','',bultin_avi)
                bultin_avi=re.sub('Page \d+ / \d+','',bultin_avi)
                bultin_avi=re.sub('\n\n','\n',bultin_avi)
                #paris le {date} 
                regex=re.search('Paris, le (\d{1,2} \w* \d{4})',bultin_avi)
                if regex:
                    bul_date1=regex.group(1)
                #le nom du bulletin
                regex=re.search('N° (CERT(FR|A)-\d{4}-AVI-\d+)',bultin_avi)  
                if regex:
                    bul_nom=regex.group(1)
                #l'objet   du bulletin
                regex=re.search('Objet\:\ (.*)',bultin_avi)
                if regex:
                    bul_obj=regex.group(1)
                #date de creation
                regex=re.search('Date de la première version\n*(\d{1,2} \w* \d{4})',bultin_avi)
                if regex:
                    bul_date1=regex.group(1)
                #date de modif
                regex=re.search('Date de la dernière version\n*(\d{1,2} \w* \d{4})',bultin_avi)
                if regex:
                    bul_date2=regex.group(1)         
                #les CVE
                #http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0985  en http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0985
                bultin_avi=bultin_avi.replace('?name=CAN-','?name=CVE-')
                regex=re.findall('http://cve\.mitre\.org/cgi\-bin/cvename\.cgi\?name\=(CVE\-\d{4}\-\d+)',bultin_avi)
                if regex:
                    bul_cve=regex
                if len(bul_cve)>0:
                    for nom_cve in bul_cve:
                        mycur.execute(f'INSERT INTO CERTFR_CVE VALUES("{bul_nom}","{nom_cve}");')
                
                textb=base64.b64encode(bultin_avi.encode()).decode()
                mycur.execute(f'INSERT INTO CERTFR_tmp VALUES("{bul_nom}","{bul_obj}","{bul_date1}","{bul_date2}",0,"{textb}");')
    pbar.close()
    
    #mise a jour de la table
    print("Mise a jour de la table CERTFR")
    mycur.executescript("""
    UPDATE CERTFR SET New=0;
    DELETE FROM CERTFR_tmp WHERE Nom in (SELECT Nom FROM CERTFR NATURAL JOIN CERTFR_tmp);
    UPDATE CERTFR_tmp SET New=1;
    INSERT OR replace INTO CERTFR SELECT * from CERTFR_tmp;
    DELETE FROM CERTFR_tmp;
    """)

def charge_cve():
    sql="DELETE FROM CVE_tmp;"
    mycur.execute(sql)
    sql="DELETE FROM CVE_cpe_tmp;"
    mycur.execute(sql)

    files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
    files.sort()
    pbar = tqdm(total=len(files), unit="file",ascii=True,desc="PARSE JSON")
    pbarcve=tqdm(total=1,ascii=True,unit="cve",desc="PARSE CVE")
    for file in files:
        pbar.update(1)
        archive = zipfile.ZipFile(join("nvd/", file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        pbarcve.total=len(cve_dict['CVE_Items'])
        for cve in cve_dict['CVE_Items']:
            pbarcve.update(1)
            cve_id=cve['cve']['CVE_data_meta']['ID']
            if 'baseMetricV3' in cve['impact']:
                cve_cvss3=cve['impact']['baseMetricV3']['cvssV3']['vectorString']
                cve_cvss3base=cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            else:
                cve_cvss3='NA'
                cve_cvss3base=0
            if 'baseMetricV2' in cve['impact']:
                cve_cvss2=cve['impact']['baseMetricV2']['cvssV2']['vectorString']
                cve_cvss2base=cve['impact']['baseMetricV2']['cvssV2']['baseScore']
            else:
                cve_cvss2='NA'
                cve_cvss2base=0
            cve_node=cve['configurations']['nodes']
            cve_pdate=cve['publishedDate']
            cve_ldate=cve['lastModifiedDate']
            str_hkey=f"{cve_id}_{cve_cvss3}_{cve_cvss3base}_{cve_cvss2}_{cve_cvss2base}_{cve_pdate}_{cve_ldate}"
            hkey=hashlib.sha1(str_hkey.encode()).hexdigest()
            sql=f'INSERT INTO CVE_tmp VALUES("{hkey}","{cve_id}","{cve_cvss3}",{cve_cvss3base},"{cve_cvss2}",{cve_cvss2base},"{cve_pdate}","{cve_ldate}",1);'
            mycur.execute(sql)
            if len(cve_node)>0:
                conf=0
                for cpelist in cve_node:
                    conf+=1
                    if len(cpelist)==2:
                        opt,dict_cpe=cpelist
                        if dict_cpe=='cpe_match':
                            for cpe in cpelist[dict_cpe]:
                                lecpe=cpe['cpe23Uri'].replace('"',"'")
                                vuln=cpe['vulnerable']
                                if 'versionStartExcluding' in cpe:
                                    VStartex=cpe['versionStartExcluding'].replace('"',"'")
                                else:
                                    VStartex=''
                                if 'versionStartIncluding' in cpe:
                                    VStartin=cpe['versionStartIncluding'].replace('"',"'")
                                else:
                                     VStartin=''
                                if 'versionEndExcluding' in cpe:
                                    VEndex=cpe['versionEndExcluding'].replace('"',"'")
                                else:
                                    VEndex=''
                                if 'versionEndIncluding' in cpe:
                                    VEndin=cpe['versionEndIncluding'].replace('"',"'")
                                else:
                                    VEndin=''
                                str_hkey=f"{cve_id}_{conf}_{cpelist.get(opt)}_{vuln}_{lecpe}_{VStartex}_{VStartin}_{VEndex}_{VEndin}"
                                hkey=hashlib.sha1(str_hkey.encode()).hexdigest()
                                sql=f'INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{hkey}","{cve_id}",{conf},"{cpelist.get(opt)}","{vuln}","{lecpe}","{VStartex}","{VStartin}","{VEndex}","{VEndin}",1);'
                                mycur.execute(sql)
                        else:
                            child_lst=cpelist[dict_cpe]
                            for child in child_lst:
                                for cpe in child['cpe_match']:
                                    lecpe=cpe['cpe23Uri'].replace('"',"'")
                                    vuln=cpe['vulnerable']
                                    if 'versionStartExcluding' in cpe:
                                        VStartex=cpe['versionStartExcluding'].replace('"',"'")
                                    else:
                                        VStartex=''
                                    if 'versionStartIncluding' in cpe:
                                        VStartin=cpe['versionStartIncluding'].replace('"',"'")
                                    else:
                                        VStartin=''
                                    if 'versionEndExcluding' in cpe:
                                        VEndex=cpe['versionEndExcluding'].replace('"',"'")
                                    else:
                                        VEndex=''
                                    if 'versionEndIncluding' in cpe:
                                        VEndin=cpe['versionEndIncluding'].replace('"',"'")
                                    else:
                                        VEndin=''
                                    str_hkey=f"{cve_id}_{conf}_{cpelist.get(opt)}_{vuln}_{lecpe}"
                                    hkey=hashlib.sha1(str_hkey.encode()).hexdigest()
                                    sql=f'INSERT OR IGNORE INTO CVE_cpe_tmp VALUES("{hkey}","{cve_id}",{conf},"{cpelist.get(opt)}","{vuln}","{lecpe}","{VStartex}","{VStartin}","{VEndex}","{VEndin}",1);'
                                    mycur.execute(sql)
    pbar.close()
    pbarcve.close()
    print ("Mise a jour de la table CVE")
    mycur.executescript("""
     UPDATE CVE SET New=0;
     DELETE FROM CVE_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE);
     INSERT OR replace INTO CVE SELECT * from CVE_tmp;
     DELETE FROM CVE_tmp;
    """)
    print ("Mise a jour de la table CPE")
    mycur.executescript("""
     UPDATE CVE_cpe SET New=0;
     DELETE FROM CVE_cpe_tmp WHERE hkey in (SELECT DISTINCT Hkey FROM CVE_cpe);
     INSERT OR replace INTO CVE_cpe SELECT * from CVE_cpe_tmp;
     DELETE FROM CVE_cpe_tmp;
    """)

#Une jolie sortie formater des info CERTFR
def CERT_to_STR(nom_bultin):
    str_info=''
    str_info+='/'+'-'*24+'\\'+"\n"
    str_info+=f"|{nom_bultin:^24}|\n"
    str_info+='\\'+'-'*24+'/'+"\n"
    mycur.execute(f"SELECT * FROM CVE WHERE cve_id IN (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}') ORDER BY cve_id;")
    allcve=mycur.fetchall()
    if allcve:
        str_info+="CVE"+" "*17+"|CVSS v3"+" "*38+"|Base V3|CVSS V2"+" "*28+"|Base V2| Pubication | Modification\n"
        for mycve in allcve:
            str_info+=f"{mycve[1]:20}|{mycve[2]:45}|{mycve[3]:^7}|{mycve[4]:35}|{mycve[5]:^7}|{mycve[6][:10]:^12}|{mycve[7][:10]:^12}\n"
        str_info+="\n"
    mycur.execute(f"SELECT max(length(cpe)) FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}');")
    cpe_max=mycur.fetchone()
    mycur.execute(f"SELECT DISTINCT * FROM CVE_cpe WHERE cve_id in (SELECT CVE FROM CERTFR_cve WHERE BULTIN='{nom_bultin}') ORDER BY cve_id,conf ASC,vuln DESC;")
    allcve=mycur.fetchall()
    if allcve:
       str_info+="\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max[0]-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl\n" 
       test=allcve[0][1]+'+'+str(allcve[0][2])+' '+allcve[0][3]
       for cpe in allcve:
           testlg=cpe[1]+' '+str(cpe[2])+' '+cpe[3]
           if test==testlg:
                str_info+="\t"+" "*32+f"{cpe[4]:^7}|{cpe[5]:{cpe_max[0]}}|{cpe[6]:12}|{cpe[7]:12}|{cpe[8]:12}|{cpe[9]:12}\n"
           else:
                str_info+=f"\t{cpe[1]:^20}|{cpe[2]:^4}|{cpe[3]:^5}|{cpe[4]:^7}|{cpe[5]:{cpe_max[0]}}|{cpe[6]:12}|{cpe[7]:12}|{cpe[8]:12}|{cpe[9]:12}\n"
                test=cpe[1]+' '+str(cpe[2])+' '+cpe[3]
    str_info+="\n"
    return str_info

#les info Microsoft
def MS_to_STR(nom_bultin):
    str_info=''
    mycur.execute(f'select CVE,Value,FIX_ID,Url,type from MS_vuln left JOIN MS_Product ON MS_vuln.ProductID=MS_Product.ProductID WHERE MS_vuln.CVE IN (SELECT CVE from CERTFR_cve WHERE BULTIN="{nom_bultin}");')
    allcve=mycur.fetchall()
    if allcve:
        str_info+='Microsoft info\n'
        str_info+="CVE"+" "*17+"|PRODUIT"+" "*53+"|KB"+" "*13+"|URL|Type\n"
        for row in allcve:
            str_info+=f"{row[0]:^20}|{row[1]:60}|{row[2]:^15}|{row[3]:^15}|{row[4]}\n"
    return str_info

#Télécharge les fichiers si plus récent ou taille différents
def Url_down(nom,rep,url):
    mycur.execute(f'SELECT * FROM URL_file WHERE Nom="{nom}";')
    info = mycur.fetchone()
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
        with open(rep + filename, 'wb') as f:
            shutil.copyfileobj(r_file.raw, f)
        mycur.execute(f'INSERT OR REPLACE INTO URL_file VALUES("{nom}","{file_date}","{file_taille}");')
    return download

##################
#  LE Script :)  #
##################
credit()
initBDD("RIA.db")

print ("Vérification de la mise à jour des fichiers CVE ET CERTFR")
mise_a_jour=False
r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
feed=re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text)
pbar = tqdm(total=len(feed),ascii=True,desc="CVE")
for filename in re.findall("nvdcve-1.1-[0-9]{4}\.json\.zip",r.text):
    pbar.update(1)
    if Url_down(filename,"nvd/","https://nvd.nist.gov/feeds/json/cve/1.1/" + filename):
        mise_a_jour=True
pbar.close()

# range (2000,2021) = [2000,2020] :)
year = datetime.date.today().year
pbar = tqdm(total=year-2000,ascii=True,desc="CERTFR")
for anne in range(2000,year +1):
    pbar.update(1)
    filename=str(anne)+".tar"
    if Url_down(filename,"certfr/","https://www.cert.ssi.gouv.fr/tar/"+filename):
        mise_a_jour=True
pbar.close()

if mise_a_jour:
    charge_cert()
    charge_cve()
    print ("Vérification des mise à jour CPE ou CVE")
    mycur.executescript("""
     UPDATE CVE SET New=1 WHERE cve_id IN (select cve_id FROM CVE_cpe where new=1);
     INSERT INTO CVE_tmp SELECT * FROM CVE WHERE New=1;
     UPDATE CERTFR SET new=1 WHERE nom IN (SELECT DISTINCT BULTIN FROM CERTFR_cve JOIN CVE_tmp WHERE CERTFR_cve.CVE=CVE_tmp.cve_id);
     DELETE FROM CVE_tmp;
    """)
    #on ecrit le tout :)
    print ("Nettoyage et Sauvegarde sur le disque")
    mycur.execute('VACUUM "main";')
    myBD.commit()
else:
    mycur.executescript("""
     UPDATE CERTFR SET New=0;
     UPDATE CVE SET New=0;
     UPDATE CVE_cpe SET New=0;
    """)

print("Traite les mises a jour de buletin")
mycur.execute("SELECT Nom FROM CERTFR WHERE New=1;")
rows = mycur.fetchall()
fiche=open("txt/new.txt",'w')
pbar = tqdm(total=len(rows),ascii=True,desc="Bultin")
for bul in rows:
    pbar.update(1)
    str_bul=CERT_to_STR(bul[0])
    fiche.writelines(str_bul)
fiche.close()
pbar.close()

year = datetime.date.today().year
rep=yesno("Listing des bultin avant "+str(year)+" ?",default='no')
if rep==False:
    depart=2000
else:
    depart=year

for annee in range(depart,year+1):
    if not exists(f"txt/{annee}"):
        mkdir(f"txt/{annee}")
    archive=tarfile.open(join("certfr/",str(annee)+".tar"),'r')
    mycur.execute(f"SELECT Nom,file FROM CERTFR WHERE nom LIKE '%{annee}%';")
    allcertfr = mycur.fetchall()
    pbar =  tqdm(total=len(allcertfr),ascii=True,desc=str(annee))
    for rows_bul in allcertfr:
        pbar.update(1)
        nom=rows_bul[0]+".txt"
        bultin_avi=base64.b64decode(rows_bul[1]).decode()
        file=open(f"txt/{annee}/{nom}",'w',encoding='utf-8')
        file.writelines(bultin_avi+'\n')
        file.writelines('\n-------------- RIA By HBT --------------\n')
        file.writelines(CERT_to_STR(rows_bul[0]))
        file.writelines(MS_to_STR(rows_bul[0]))
        file.close()
    pbar.close()


mycur.executescript("""
  DROP TABLE IF EXISTS CVE_BULTIN;
  CREATE TABLE CVE_BULTIN AS SELECT CVE, group_concat(DISTINCT BULTIN) FROM CERTFR_cve GROUP BY CVE;
  ALTER TABLE CVE_BULTIN RENAME COLUMN 'group_concat(DISTINCT BULTIN)' TO CERTFR;
""")
mycur.execute('SELECT * FROM CVE_BULTIN;')
rows = mycur.fetchall()
fiche=open("txt/CVE_CERTFR.txt",'w', encoding='utf-8')
pbar =  tqdm(total=len(rows),unit="buletin",ascii=True,desc="CVE_CERTFR")
for bul in rows:
    pbar.update(1)
    str_bul=f"{bul[0]:^10}:{bul[1]}\n"
    fiche.writelines(str_bul)
fiche.close()
pbar.close()


myBD.commit()
myBD.close()

print("Bye Bye")
#
