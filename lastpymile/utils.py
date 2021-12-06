import os, stat
from pathlib import Path
import requests, urllib
import re

class Utils():

  @staticmethod
  def sanitizeFolderName(folderName, maxLength=None):
    sanitized=re.sub(r'[^A-Za-z\d\._-]', '', folderName.replace(" ","_"))
    if maxLength is not None and len(sanitized)>maxLength:
      sanitized=sanitized[:maxLength]
    return sanitized

  @staticmethod
  def createFolderForFile(file):
    if os.path.exists(file):
      os.remove(file)
    else:
      Utils.createFolder(Path(file).parent)
    
  @staticmethod
  def createFolder(folder):
    if not os.path.exists(folder):
      os.makedirs(folder)


  @staticmethod
  def rmtree(folder):
    for root, dirs, files in os.walk(folder, topdown=False):
      for name in files:
        filename = os.path.join(root, name)
        os.chmod(filename, stat.S_IWUSR)
        os.remove(filename)
      for name in dirs:
        os.rmdir(os.path.join(root, name))
    os.rmdir(folder)    



  @staticmethod
  def __isUrlAvailable(url):
    resp=requests.head(url)
    return resp.status_code >=200 and resp.status_code<300

  @staticmethod
  def downloadUrl(url,destFile,cheked=False):
    if  not Utils.__isUrlAvailable(url):
      if cheked==True:
        return False
      raise Exception("Url {} not available".format(url))
    Utils.createFolderForFile(destFile)
    try:
      urllib.request.urlretrieve(url, destFile)
      # with requests.get(url, stream=True) as r:
        # with open(destFile, 'wb') as f:
          # shutil.copyfileobj(r.raw, f)
      return True
    except Exception as e:
      if os.path.exists(destFile):
        os.remove(destFile)
        if cheked==True:
          return False
        raise e
