import hashlib
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
        self.id=""
        self.cvssV3="NA"
        self.cvssV3base=0
        self.cvssV2="NA"
        self.cvssV2base=0
        self.dateOrigine=""
        self.dateUpdate=""
        self.New=0
        self.crc=""

    def reset(self):
        self.id=""
        self.cvssV3="NA"
        self.cvssV3base=0
        self.cvssV2="NA"
        self.cvssV2base=0
        self.dateOrigine=""
        self.dateUpdate=""
        self.New=0
        self.crc=""

    def set_crc(self):
        str_hkey=f"{self_id}_{self.cvssV3}_{self.cvssV3base}_{self.cvssV2}_{self.cvssV2base}_{self.dateOrigine}_{self.dateUpdate}"
        self.crc=hashlib.sha1(str_hkey.encode()).hexdigest()

#########################################
#               CPE                     #
# pour les CPE                          #
#########################################
class cpe:
    def __init__(self):   
        pass
