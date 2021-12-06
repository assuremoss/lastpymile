import logging
import os,urllib
import requests
import json
from urllib.parse import quote
from lxml import html

class PyPackage:

  # __RELEASE_TYPE_WHEEL="wheel"
  # __RELEASE_TYPE_SOURCE="source"
  # __RELEASE_TYPE_EGG="egg"
  # __RELEASE_TYPE_UNKNOWN="unknown"

  __PYPI_URL="https://pypi.org"

  __logger=logging.getLogger("lastpymile.PyPackage")

  @staticmethod
  def getAllPackagesList():
    response = requests.get(PyPackage.__PYPI_URL+"/simple")
    tree = html.fromstring(response.content)
    package_list = [package for package in tree.xpath('//a/text()')]
    return package_list
  
  @staticmethod
  def _getPackageMetadata(package_name,package_version=None):
    safe_name=quote(package_name, safe='')
    safe_ver=quote(package_name, safe='')
    partial_url="{}".format(safe_name) if package_version is None else "{}/{}".format(safe_name,safe_ver)
    url="{}/pypi/{}/json".format(PyPackage.__PYPI_URL,partial_url)
    PyPackage.__logger.debug("Downloading package '{}' data from {}".format(package_name,url))
    response = requests.get(url)
    PyPackage.__logger.debug("Response code {}".format(response.status_code))
    if(response.status_code>=200 and response.status_code<300):
      return json.loads(response.content)
    else:
      return None
  
  @staticmethod
  def searchPackage(package_name,package_version=None):
    package_data= PyPackage._getPackageMetadata(package_name,package_version)
    if package_data is not None:
      return PyPackage(package_data)
    else:
      raise PyPackageNotFoundException(package_name)


  def __init__(self,package_data):
    self.package_data=package_data
    self.name=self.package_data["info"]["name"]
    self.version=self.package_data["info"]["version"]
    self.releases=None
    self.gitRepositoryUrl=None

    
  def getName(self):
    return self.name

  def getVersion(self):
    return self.version

  def getRelaeses(self):
    if self.releases==None:
      self.__loadReleases()
    return self.releases

  def getGitRepositoryUrl(self):
    if self.gitRepositoryUrl==None:
      self.__loadSourcesRepository()
    return self.gitRepositoryUrl

  def __loadReleases(self):
    self.releases=[]
    for release in self.package_data["releases"][self.version]:
      if "url" in release:
        self.releases.append(PyPackageRelease(self,release["url"],release["packagetype"] if "packagetype" in release else None))

  def __loadSourcesRepository(self):
    github_link=None
    urls=self.package_data["info"]["project_urls"] if "project_urls" in self.package_data["info"] else None

    if urls is not None:
      for link_name in urls:
        link=urls[link_name]
        if "github" in link and ( github_link == None or len(github_link) > len(link)):
          if github_link == None:
            github_link=link

    self.gitRepositoryUrl=github_link
    
  def __str__(self):
    return "PyPackage[name:{}, version:{}, github:{}, release:({}){}]".format(self.name,self.version,self.githubPageLink,self.releaseLink[1],self.releaseLink[0])


class PyPackageRelease():

  def __init__(self,pypackage,url,type):
    self.pypackage=pypackage
    self.url=url
    self.type=type

  def getPyPackage(self):
    self.pypackage

  def getDownloadUrl(self):
    return self.url

  def getReleaseFileName(self):
    return os.path.basename(urllib.parse.urlparse(self.url).path)

  def getReleaseFileType(self):
    return self.getReleaseFileName().split(".")[-1]

  def getReleaseType(self):
    return self.type


##################################
##  EXCEPTIONS
##################################

class PyPackageNotFoundException(Exception):
  def __init__(self,package_name,package_version=None):
    if package_version is None:            
      super().__init__("Py package '{}' not found".format(package_name))
    else:
      super().__init__("Py package '{}' with version '{}' not found".format(package_name,package_version),False)