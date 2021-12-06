import os, stat
from pathlib import Path
import requests, urllib
import re

class Utils():
  """
    Utility class with static functions
  """

  @staticmethod
  def sanitizeFolderName(folder_name, max_length=None):
    """
      Sanitize a string to be used as a folder name, and optionally truncate its' lenght to the specified value.
      In particular remove all caharachters except letters,numbers,dot and underscore, and replace all spaces with undersocore

        Parameters:
          folder_name(str): The string to be sanitized
          max_length(int): The max lenght of the returned sanitized name

    """
    sanitized=re.sub(r'[^A-Za-z\d\._-]', '', folder_name.replace(" ","_"))
    if max_length is not None and len(sanitized)>max_length:
      sanitized=sanitized[:max_length]
    return sanitized

  @staticmethod
  def ensureFilePath(file_path:str) -> None:
    """
      Ensure the exitance of a file path. Furthermore it the file exist it's deleted

        Parameters:
          file_name(str): The path of the file to ensure
    """
    if os.path.exists(file_path):
      os.remove(file_path)
    else:
      Utils.ensureFolderPath(Path(file_path).parent)
    
  @staticmethod
  def ensureFolderPath(folder_path):
    """
      Ensure the exitance of a folder path

        Parameters:
          folder_path(str): The path of the folder to ensure
    """
    if not os.path.exists(folder_path):
      os.makedirs(folder_path)


  @staticmethod
  def rmtree(folder_path):
    """
      Custom reimplementation of shutil.rmtree that work under windows.(shutil.rmtree raise exeptions under windows if permissions are not right)

        Parameters:
          folder_path(str): The path of the folder to remove
    """
    for root, dirs, files in os.walk(folder_path, topdown=False):
      for name in files:
        filename = os.path.join(root, name)
        os.chmod(filename, stat.S_IWUSR)
        os.remove(filename)
      for name in dirs:
        os.rmdir(os.path.join(root, name))
    os.rmdir(folder_path)    


  @staticmethod
  def __isUrlAvailable(url:str) -> bool:
    """
      Perform an url HEAD request to test if a url is available

        Parameters:
          url(str): The url to test
        
        Return (bool):
          True if the url is available, False otherwise
    """
    resp=requests.head(url)
    return resp.status_code >=200 and resp.status_code<300

  @staticmethod
  def getUrlContent(url:str, cheked:bool=False) -> bytes:
    """
      Retrieve the content of the specified url

        Parameters:
          url(str): The url to download
          cheked(bool): If True no exception is raised and None is returned
        
        Return (bool):
          True if the url is available, False otherwise
    """
    if  not Utils.__isUrlAvailable(url):
      if cheked==True:
        return False
      raise Exception("Url {} not available".format(url))
    try:
      response=requests.get(url)
      if(response.status_code>=200 and response.status_code<300):
        return response.content
      else:
        raise Exception("Url '{}' response code {}".format(url,response.status_code))
    except Exception as e:
      if cheked==True:
        return None
      raise e

  @staticmethod
  def downloadUrl(url:str, dest_file:str, cheked:bool=False) -> bool:
    """
      Download a file to the specified location

        Parameters:
          url(str): The url to download
          dest_file(str): The path where to save the file
          cheked(bool): If True no exception is raised and False is returned
        
        Return (bool):
          True if the url has successfully downaloded, False otherwise
    """
    if  not Utils.__isUrlAvailable(url):
      if cheked==True:
        return False
      raise Exception("Url {} not available".format(url))
    Utils.ensureFilePath(dest_file)
    try:
      urllib.request.urlretrieve(url, dest_file)
      # with requests.get(url, stream=True) as r:
        # with open(destFile, 'wb') as f:
          # shutil.copyfileobj(r.raw, f)
      return True
    except Exception as e:
      if os.path.exists(dest_file):
        os.remove(dest_file)
      if cheked==True:
        return False
      raise e
