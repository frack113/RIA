import base64

#########################################
#              CERTFR                   #
# pour les bulletins                    #
#########################################
class certfr:
    def __init__(self):
       self.nom=""
       self.obj=""
       self.dateOrigine=""
       self.dateUpdate=""
       self.New=0
       self.file=""
       self.crc=""

    def decode_file(self):
        return base64.b64decode(self.file).decode()
    
    def encode_file(self):
        return base64.b64encode(self.file.encode()).decode()
    
    def reset(self):
       self.nom=""
       self.obj=""
       self.dateOrigine=""
       self.dateUpdate=""
       self.New=0
       self.file=""
       self.crc=""

    def set_crc(self):
        str_hkey=f"{self.nom}_{self.dateOrigine}_{self.dateUpdate}"
        self.crc=hashlib.sha1(str_hkey.encode()).hexdigest()


#########################################
#               CVE                     #
# pour les CVE                          #
#########################################
class cve:
    def __init__(self):
        pass
