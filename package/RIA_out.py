## Gestion des sorties
# @file RIA_out.py
# @author Frack113
# @date 09/04/2020
# @brief Class pour les sorties fichier
#

from  RIA_class import *
import os
import json
import re


##
# @brief Gestion des sorties
# @details Python help
class C_out:

    ## constructors
    # @param MaBdd C_sql
    # @param Ksoft C_mskb
    # @details Python help
    def __init__ (self,MaBdd,Ksoft):
        """le constructor
        MaBdd est un objet C_sql déjà existant
        Ksoft est un objet C_mskb déjà existant
        """
        ##la Bdd via C_sql
        self.MaBdd=MaBdd
        self.Ksoft=Ksoft
    ##
    # @brief calcul la taille max en caractere de chaque case
    # @param malist une liste de liste
    # @return un liste des tailles max
    # @details Python help
    def Get_max_lg(self,malist,title=[]):
        ''' Renvoie dans une liste[x,x,x] la taillle max de chaque colonne de [['a','b','c'],['z',4,7888],..] '''
        if title:
            taille=[len(str(x)) for x in title]
        else:
            taille=[len(str(x)) for x in malist[0]]
        for row in malist:
            for x in range(len(row)):
                if len(str(row[x]))> taille[x]:
                    taille[x]=len(str(row[x]))
        return taille

    ##
    # @brief Une jolie sortie formatée des infos Microsoft
    # @param Nom le nom du bulletin
    # @param tab une liste
    # @details Python help
    def MS_to_TAB(self,Nom,tab):
        """ ajoute à liste tab les informations Microsoft
        Nom string avec le nom du bulletin
        """
        allcve=self.Ksoft.get_info_certfr(Nom)
        if allcve:
            taille=self.Get_max_lg(allcve)
            tab.append('----------- INFO Microsoft ------------')
            tab.append(f"{'CVE':{taille[0]}}|{'PRODUIT':{taille[1]}}|{'KB':{taille[2]}}|{'URL':{taille[3]}}|{'Type':{taille[4]}}")
            for row in allcve:
                tab.append(f"{row[0]:{taille[0]}}|{row[1]:{taille[1]}}|{row[2]:{taille[2]}}|{row[3]:{taille[3]}}|{row[4]:{taille[4]}}")

    ##
    # @brief Une jolie sortie formatée des info CERTFR
    # @param Nom le nom du bulletin
    # @param tab une liste
    # @details Python help
    def CERT_to_TAB(self,Nom,tab):
        """ Ajoute à liste tab les informations CVE cpe
        Nom string nom du Bulletin
        """
        allcve=self.MaBdd.get_all_cve_certfr(Nom)
        tab.append("Les CVE")
        if allcve:
            tab.append(f"{'CVE':^20}|{'CVSS v3':^45}|Base V3|{'CVSS V2':^35}|Base V2| Pubication | Modification")
            for mycve in allcve:
                tab.append(f"{mycve.id:20}|{mycve.cvssV3:45}|{mycve.cvssV3base:^7}|{mycve.cvssV2:35}|{mycve.cvssV2base:^7}|{mycve.dateOrigine[:10]:^12}|{mycve.dateUpdate[:10]:^12}")
            tab.append('')
        cpe_max=self.MaBdd.get_max_lg_uri_cpe(Nom)
        allcpe=self.MaBdd.get_all_cpe_certfr(Nom)
        tab.append("Les CPE")
        if allcpe:
            tab.append(f"{'CVE':^20}|Conf| OPE |  Vuln |{'CPE':^{cpe_max}}| Start_incl | Start_excl |  End_incl  |  End_excl")
            test=allcpe[0].cve+'_'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
            for cpe in allcpe:
                testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
                if test==testlg:
                    tab.append(f"{' ':32}{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                else:
                    tab.append(f"{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                    test=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
        tab.append('')


    ##
    # @brief Ecrit dans un fichier text les informations du bulletin
    # @param nom le nom du bulletin
    # @param rep répertoire de sortie
    # @details Python help
    def Write_CERTFR(self,nom,rep):
        """Ecrit les informations du bulletin 'nom' dans le répertoire txt/'rep'
        """
        reponse=[]
        cert=self.MaBdd.get_certfr(nom)
        if not os.path.exists(f"txt/{rep}"):
            os.mkdir(f"txt/{rep}")
        file=open(f"txt/{rep}/{nom}.txt",'w',encoding='utf-8')
        bultin_avi=cert.decode_file()
        reponse.append(bultin_avi)
        reponse.append('----------------------------------------')
        reponse.append('----------- RIA By Frack113 ------------')
        reponse.append('----------------------------------------')
        self.CERT_to_TAB(nom,reponse)
        self.MS_to_TAB(nom,reponse)
        file.writelines('\n'.join(reponse))
        file.close()

    ##
    # @brief Ecrit un fichier avec bulletins et URI23 pour une recherche
    # @param Nom recherche dans les objets et aussi le nom du fichier de sortie
    # @param uri chaîne à chercher dans les uri23
    # @details Python help
    def URI_to_FILE(self,Nom,uri):
        """ Ecrit dans un fichier tous les bulletins avec 'Nom' dans l'objet
        et toutes les uri23 SQL LIKE %uri%
        """
        tab=[]
        certs=self.MaBdd.get_orphan_by_obj(Nom)
        if certs:
            for cert in certs:
                tab.append(cert[0]+' : '+cert[1])
        tab.append('Les CVE')
        allcpe=self.MaBdd.get_tab_all_cpe_uri(uri)
        
        if allcpe:
            title=['CRC','CVE','Conf','OPE','Vuln','CPE','Start_excl','Start_incl','End_excl','End_incl','New']
            lgmax=self.Get_max_lg(allcpe,title)
            #0 c'est le CRC 
            tab.append("|".join([f"{title[x]:{lgmax[x]}}" for x in range(1,10)]))
            delta=lgmax[1]+lgmax[2]+lgmax[3] + 3
            test="test de repetition"
            for cpe in allcpe:
                testlg=cpe[1]+'_'+str(cpe[2])+'_'+cpe[3]
                if test==testlg:
                    mini="|".join([f"{cpe[x]:{lgmax[x]}}" for x in range(4,10)])
                    tab.append(f"{' ':{delta}}{mini}")
                else:
                    tab.append("|".join([f"{cpe[x]:{lgmax[x]}}" for x in range(1,10)]))
                    test=cpe[1]+'_'+str(cpe[2])+'_'+cpe[3]
        file=file=open(f"mogs/{Nom}.txt",'w',encoding='utf-8')
        file.writelines('\n'.join(tab))
        file.close()
    ##
    # @brief Ecrit dans un fichier une liste à 2 champs
    # @param Nom_sortie nom du fichier
    # @param tab la liste à ecrire
    # @details Python help
    def tab2_to_txt(self,Nom_sortie,tab):
        """ Ecrit un fichier txt une liste 2 champs """
        fiche=open(Nom_sortie,'w', encoding='utf-8')
        taille=self.Get_max_lg(tab)
        out=[f"{row[0]:{taille[0]}};{row[1]}" for row in tab]
        fiche.writelines('\n'.join(out))
        fiche.close()

    ##
    # @brief Export Json une liste de C_certfr
    # @param liste la liste de C_certfr
    # @param file_out le fichier de sortie
    # @details Python help
    def Write_certfr_json(self,liste,file_out):
        '''   help me       '''
        l_cert=[{"Nom":row.nom,"Obj":row.obj,'Origine':row.dateOrigine,'Modif':row.dateUpdate} for row in liste]
        l_full=[]
        for cert in l_cert:
            cve=[]
            cves=self.MaBdd.get_sc(f"""SELECT DISTINCT
                                            cve_id,
                                            cve_cvss3,
                                            cve_cvss3base,
                                            cve_cvss2,
                                            cve_cvss2base
                                              FROM CVE WHERE cve_id IN
                                              (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{cert['Nom']}')
                                              ORDER BY cve_id;""")
            if cves:
                cve=[{"id":row[0],
                      "Cvss_v3":row[1],
                      "Cvss_v3_base":row[2],
                      "Cvss_v2":row[3],
                      "Cvss_v2_base":row[4]
                     } for row in cves]
            cert['CVE']=cve

            cpe=[]
            cpes=self.MaBdd.get_sc(f"""SELECT DISTINCT
                                          cve_id,
                                          conf,
                                          ope,
                                          vuln,
                                          cpe,
                                          versionStartExcluding,
                                          versionStartIncluding,
                                          versionEndExcluding,
                                          versionEndIncluding
                                            FROM CVE_cpe WHERE cve_id IN
                                              (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{cert['Nom']}')
                                              ORDER BY cve_id,conf ASC,vuln DESC;""")
            if cpes:
                cpe=[{"Cve":row[0],
                      "Conf":row[1],
                      "Ope":row[2],
                      "Vuln":row[3],
                      "Uri":row[4],
                      "Start_exc":row[5],
                      "Start_inc":row[6],
                      "End_exc":row[7],
                      "End_inc":row[8]
                     } for row in cpes]
            cert['CPE']=cpe
            l_full.append(cert)

        file=open("json/"+file_out,"w",encoding='utf-8')
        json.dump(l_full,file,indent=2)
        file.close()
 
    ##
    # @brief Export html une liste de C_certfr
    # @param liste la liste de C_certfr
    # @param file_out le fichier de sortie
    # @details Python help
    def Write_certfr_html(self,liste,file_out):
        '''   help me       '''
        l_cert=[{"Nom":row.nom,"Obj":row.obj,'Origine':row.dateOrigine,'Modif':row.dateUpdate} for row in liste]
        l_full=['<!DOCTYPE html><html><head><link rel="stylesheet" type="text/css" href="Ria.css"></head><body>']
        for cert in l_cert:
            l_full.append(f'<button class="collapsible">{cert["Nom"]}</button>')
            l_full.append('<div class="content">')
            l_full.append(f'<table class="cert"><thead><tr><th colspan="2">{cert["Nom"]}</th></tr></thead>')
            l_full.append(f"<tr><td>Objet</td><td>{cert['Obj']}</td></tr>")
            l_full.append(f"<tr><td>Date origine</td><td>{cert['Origine']}</td></tr>")
            l_full.append(f"<tr><td>Date modification</td><td>{cert['Modif']}</td></tr>")
            l_full.append(f"</table>")

            cves=self.MaBdd.get_sc(f"""SELECT DISTINCT
                                            cve_id,
                                            cve_cvss3,
                                            cve_cvss3base,
                                            cve_cvss2,
                                            cve_cvss2base,
                                            cve_ldate
                                              FROM CVE WHERE cve_id IN
                                              (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{cert['Nom']}')
                                              ORDER BY cve_id;""")
            if cves:
                titre=["id",
                       "Cvss3",
                       "Note",
                       "Cvss2",
                       "note",
                       "Modif"]
                l_full.append('<table class="cve"><thead><tr>'+''.join([f"<th>{x}</th>" for x in titre])+'</tr></thead>')
                for cve in cves:
                    l_full.append("<tr>"+''.join([f"<td>{x}</td>" for x in cve])+"</tr>")
                l_full.append("</table>")

            cpes=self.MaBdd.get_sc(f"""SELECT DISTINCT
                                          cve_id,
                                          conf,
                                          ope,
                                          vuln,
                                          cpe,
                                          versionStartExcluding,
                                          versionStartIncluding,
                                          versionEndExcluding,
                                          versionEndIncluding
                                            FROM CVE_cpe WHERE cve_id IN
                                              (SELECT cve_id FROM CERTFR_cve WHERE BULTIN='{cert['Nom']}')
                                              ORDER BY cve_id,conf ASC,vuln DESC;""")
            if cpes:
                titre=["Cve",
                      "Conf",
                      "Ope",
                      "Vuln",
                      "Uri",
                      "Start_exc",
                      "Start_inc",
                      "End_exc",
                      "End_inc"]
                l_full.append('<table class="cpe"><thead><tr>'+''.join([f"<th>{x}</th>" for x in titre])+'</tr></thead>')
                for cpe in cpes:
                    l_full.append("<tr>"+''.join([f"<td>{x}</td>" for x in cpe])+"</tr>")
                l_full.append("</table>")
           
            if "MICROSOFT" in cert['Obj'].upper():
                ms=self.Ksoft.get_info_certfr(cert["Nom"])
                titre=["cve_id",
                           "Value",
                           "FIX_ID",
                           "Url",
                           "type"]
                l_full.append('<table class="mskb"><thead><tr>'+''.join([f"<th>{x}</th>" for x in titre])+'</tr></thead>')
                for kb in ms:
                    l_full.append("<tr>"+''.join([f"<td>{x}</td>" for x in kb])+"</tr>")
                l_full.append("</table>")
            l_full.append("</div>") 
            
        l_full.append('''
        <script> var coll = document.getElementsByClassName("collapsible");var i;
        for (i = 0; i < coll.length; i++) {
          coll[i].addEventListener("click", function() {
           this.classList.toggle("active");
           var content = this.nextElementSibling;
           if (content.style.maxHeight){ content.style.maxHeight = null;
           } else {content.style.maxHeight = content.scrollHeight + "px";} 
                                                       });
                                          }
        </script>''')
        file=open("html/"+file_out,"w",encoding='utf-8')
        file.writelines('\n'.join(l_full))
        file.close()
    
    ##
    # @brief Export Json
    # @param Outname nom du fichier
    # @param sql la fin de la requête
    # @details Python help
    def Export_certfr_json (self,Outname,sql):
        """Export en json tous les bulletins requête SQL: WHERE Non {sql} dans le fichier 'Outname' 
        Exemples :
        Un bulletin sql= '="CERTFR-2020-AVI-001"'
        les 2020    sql= 'LIKE "%2020%"'
        """
        liste=self.MaBdd.Get_Liste_certfr(f'SELECT * FROM CERTFR WHERE Nom {sql};')
        self.Write_certfr_json(liste,Outname)

    ##  
    # @brief sortie en txt des bulletins
    # @param liste la liste des C_certfr
    # @rep le repertoire de sortie sinon l'année
    # @details Python help
    def Write_certfr_txt(self,liste,rep=''):
        ''' Help me '''
        for bul in liste:
            if rep:
                sortie=rep
            else:
                re_result=re.fullmatch('CERT(FR|A)\-(?P<an>\d+)\-AVI\-\d+',bul.nom)
                sortie=re_result.group('an')
            self.Write_CERTFR(bul.nom,sortie)

