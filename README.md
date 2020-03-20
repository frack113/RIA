# RIA
test en Python 3.7

Complete le bulletin du CERTFR

Actuellement
- Telechargement automatique des CERTFR et CVE
- Lecture des bulletin CERTFR depuis archive rar
- Lecture des cve depuis les json
- Gestion en SQLITE
- Liste des KB microsoft API

Dependance
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
