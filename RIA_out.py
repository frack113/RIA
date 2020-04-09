from  RIA_class import *
import os

##
# @brief Gestion des sortie
# @details Python help
class C_out:

    ## constructors
    # @param MaBdd C_sql
    # @details Python help
    def __init__ (self,MaBdd,Ksoft):
        """le constructor
        MaBdd est un C_sql déjà ouvert
        Ksoft est un C_mskb déjà ouvert
        """
        ##la Bdd via C_sql
        self.MaBdd=MaBdd
        self.Ksoft=Ksoft

    ##
    # @brief Une jolie sortie formater des info Microsoft
    # @param Nom le nom du bulletin
    # @param tab une liste
    def MS_to_STR(self,Nom,tab):
        allcve=self.Ksoft.get_info_certfr(Nom)
        if allcve:
            tab.append('Microsoft info')
            tab.append("CVE"+" "*17+"|PRODUIT"+" "*53+"|KB"+" "*13+"|URL|Type")
            for row in allcve:
                tab.append(f"{row[0]:^20}|{row[1]:60}|{row[2]:^15}|{row[3]:^15}|{row[4]}")

    ##
    # @brief Une jolie sortie formater des info CERTFR
    # @param Nom le nom du bulletin
    # @param tab une liste
    def CERT_to_STR(self,Nom,tab):
        allcve=self.MaBdd.get_all_cve_certfr(Nom)
        if allcve:
            tab.append("CVE"+" "*17+"|CVSS v3"+" "*38+"|Base V3|CVSS V2"+" "*28+"|Base V2| Pubication | Modification")
            for mycve in allcve:
                tab.append(f"{mycve.id:20}|{mycve.cvssV3:45}|{mycve.cvssV3base:^7}|{mycve.cvssV2:35}|{mycve.cvssV2base:^7}|{mycve.dateOrigine[:10]:^12}|{mycve.dateUpdate[:10]:^12}")
            tab.append('')
        cpe_max=self.MaBdd.get_max_lg_uri_cpe(Nom)
        allcpe=self.MaBdd.get_all_cpe_certfr(Nom)
        if allcpe:
            tab.append("\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl" )
            test=allcpe[0].cve+'_'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
            for cpe in allcpe:
                testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
                if test==testlg:
                    tab.append("\t"+" "*32+f"{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                else:
                    tab.append(f"\t{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                    test=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
        tab.append('')


    ##
    # @brief Ecrit dans un fichier text les informations du bulletin
    # @param nom le nom du bulletin
    # @param rep repertoire de sortie
    def Write_CERTFR(self,nom,rep):
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
        self.CERT_to_STR(nom,reponse)
        self.MS_to_STR(nom,reponse)
        file.writelines('\n'.join(reponse))
        file.close()

    ##
    # @brief Ecrit un fichiers avec bulletins et URI23 pour une recherche
    # @param Nom dans les objets et non du fichier de sortie
    # @param uri chaine a chercher dans les uri23
    def URI_to_FILE(self,Nom,uri):
        tab=[]
        certs=self.MaBdd.get_orphan_by_obj(Nom)
        if certs:
            for cert in certs:
                tab.append(cert[0]+' : '+cert[1])
        tab.append('Les CVE')
        allcpe=self.MaBdd.get_all_cpe_uri(uri)
        cpe_max=50
        if allcpe:
            tab.append("\tCVE"+" "*17+"|Conf| OPE |  Vuln | CPE"+" "*(cpe_max-4)+"| Start_incl | Start_excl |  End_incl  |  End_excl" )
            test=allcpe[0].cve+'_'+str(allcpe[0].conf)+' '+allcpe[0].vulnerable
            for cpe in allcpe:
                testlg=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
                if test==testlg:
                    tab.append("\t"+" "*32+f"{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                else:
                    tab.append(f"\t{cpe.cve:^20}|{cpe.conf:^4}|{cpe.operateur:^5}|{cpe.vulnerable:^7}|{cpe.cpe23uri:{cpe_max}}|{cpe.versionStartExcluding:12}|{cpe.versionStartIncluding:12}|{cpe.versionEndExcluding:12}|{cpe.versionEndIncluding:12}")
                    test=cpe.cve+' '+str(cpe.conf)+' '+cpe.vulnerable
        file=file=open(f"mogs/{Nom}.txt",'w',encoding='utf-8')
        file.writelines('\n'.join(tab))
        file.close()

    def tab2_to_txt(self,Nom_sortie,tab):
        fiche=open(Nom_sortie,'w', encoding='utf-8')
        for row in tab:
            fiche.writelines(f"{row[0]:^10}:{row[1]}\n")
        fiche.close()

    def Export_certfr_json (Outname,sql):
        #print(f'SELECT Nom,Obj,Dateo,Datem FROM CERTFR WHERE Nom {sql};')
        certs=MaBdd.get_sc(f'SELECT Nom,Obj,Dateo,Datem FROM CERTFR WHERE Nom {sql};')
        l_cert=[{"Nom":row[0],"Obj":row[1],'Origine':row[2],'Modif':row[3]} for row in certs]

        l_full=[]
        for cert in l_cert:
            cve=[]
            cves=MaBdd.get_sc(f"""SELECT DISTINCT
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
            cpes=MaBdd.get_sc(f"""SELECT DISTINCT
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

            file=open(Outname,"w",encoding='utf-8')
            json.dump(l_full,file,indent=2)
            file.close()
