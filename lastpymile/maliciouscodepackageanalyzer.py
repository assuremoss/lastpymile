from __future__ import annotations
import logging
import os,tempfile
from shutil import which
from typing import Any, Tuple
import zipfile, tarfile
import hashlib
from subprocess import Popen, PIPE

from .utils import Utils
from .abstractpackageanalysis import AbstractPackageAnalysis, StageStatisticsData, AnalysisException

from .pypackage import *
from .gitrepository import *
from lastpymile import pypackage


###
### Internal support classes
###

class FileDescriptor():
  """
    Abstract file descriptor, describing a general file.
    A file descriptor has a filename and chan be extended to implement the getContent() method
  """

  def __init__(self,filename:str):
    self.filename=filename

  def getFileName(self) -> str:
    return self.filename.replace("\\","/")
  
  def getContent():
    return None

class GitFileDescriptor(FileDescriptor):

  def __init__(self, repository, commit_hexsha, filename):
    super().__init__(filename)
    self.repository=repository
    self.commit_hexsha=commit_hexsha

  def getCommitHexsha(self):
    return self.commit_hexsha
  
  def getContent(self):
    return self.repository.getCommitEntryContent(self.commit,self.filename)

class ReleaseFileDescriptor(FileDescriptor):

  def __init__(self, dir, filename):
    super().__init__(filename)
    self.dir=dir

  def getFullFilePath(self):
    return os.path.join(self.dir,self.filename)

  def getContent(self):
    content=None
    with open(self.getFullFilePath(), "rb") as f:
      content=f.read()
    return content

class ZipFileDescriptor(FileDescriptor):

  def __init__(self, zipFile, zip_info):
    super().__init__(zip_info.filename)
    self.zipFile=zipFile
    self.zip_info=zip_info

  def getContent(self):
    content=None
    try:
      content=self.zipFile.read(self.zip_info)
    except NotImplementedError:
      filename=self.zip_info.filename
      try:
        tmp_dir=tempfile.gettempdir()
        try:
          self.zip_info.filename = filename.split("/")[-1]
          self.zipFile.extract(self.zip_info,tmp_dir)
          with open(os.path.join(tmp_dir,self.zip_info.filename), "rb") as f:
            content=f.read()
        finally:
          try:
            os.remove(os.path.join(tmp_dir,self.zip_info.filename))
          except:
            pass
      finally:
        self.zip_info.filename=filename


    return content

class TarFileDescriptor(FileDescriptor):

  def __init__(self, tar, tar_info):
    super().__init__(tar_info.name)
    self.tar=tar
    self.tar_info=tar_info

  def getContent(self):
    content=None
    try:
      f=self.tar.extractfile(self.tar_info)
      if f is not None:
        content=f.read()
    except Exception:
      filename=self.tar_info.name
      try:
        tmp_dir=tempfile.gettempdir()
        try:
          self.tar_info.name = filename.split("/")[-1]
          self.tar.extract(self.tar_info,tmp_dir)
          with open(os.path.join(tmp_dir,self.tar_info.name), "rb") as f:
            content=f.read()
        finally:
          try:
            os.remove(os.path.join(tmp_dir,self.tar_info.name))
          except:
            pass
      finally:
        self.tar_info.name=filename


    return content


###
### Internal support classes
###

class MaliciousCodePackageAnalyzer(AbstractPackageAnalysis):
  """
    Implementation class of an AbstractPackageAnalysis, that scan and search for malicious code injection in python packages
  """

  __SUPPORTED_RELEASES_TYPES=["whl","zip","tar","gz","bz2","xz","egg"]

  __logger=logging.getLogger("lastpymile.MaliciousCodePackageAnalyzer")
  __report_logger=logging.getLogger("lastpymile_report")


  @classmethod
  def createAnaliysisForPackage(cls, package_name:str, package_version:str=None, checked:bool=False,**options) -> MaliciousCodePackageAnalyzer:
    """
      Static method to create a MaliciousCodePackageAnalyzer object that can be used to analyze a pacakge 
        Parameters:
          package_name (str): the name of the python package to analyze
          package_version (str): the version of the package. May be None, in that case the latest version is automatically chosen
          checked (bool): If True no exception is raised if the package cannot be found (In case of error the method return None). Default False

        Named options:
          tmp_folder (str): A path location that will be used as temporary folder. If None (default) the system temp folder is used
          repo_folder(str): A path location to a git repository that will be used as reference source repository. If None (default) the git repository it's deterimend and cloned from the package metadata

          The following options are mainly used during development or debugging

            keep_tmp_folder (bool): It True the temporary folder is not deleted - Default False
            cache_folder(str): A path location that will be used to store the downloaded artifacts and git repositories (to save bandwidth)
            cache_metadata_folder(str): A path location that will be used to store the package metadata info (to save bandwidth)
          
        Return (MaliciousCodePackageAnalyzer):
          A MaliciousCodePackageAnalyzer that can be used to analyze the requested package 
    """
    cls.__logger.info("Searching package '{}' version:{}".format(package_name,"<LATEST>" if package_version is None else package_version))
    try:
      if "cache_metadata_folder" in options:
        cache_metadata_folder=options["cache_metadata_folder"]
        if not os.path.exists(cache_metadata_folder):
          os.makedirs(cache_metadata_folder)
        data_file=os.path.join(cache_metadata_folder,"{}_{}".format(package_name,package_version if package_version is not None else "LATEST"))
        
        if not os.path.exists(data_file):
          package_data=PyPackage._getPackageMetadata(package_name,package_version)
          with open(data_file,"w") as f:
            f.write(json.dumps(package_data))
        else:
          MaliciousCodePackageAnalyzer.__logger.debug("Loading cashed package data {}".format(data_file))
          with open(data_file, "rb") as f:
            package_data=json.loads(f.read())
            
        pyPackage=PyPackage(package_data)
      else:
        pyPackage=PyPackage.searchPackage(package_name,package_version)
        cls.__logger.info("Package '{}' version:{} FOUND".format(pyPackage.getName(),pyPackage.getVersion()))
      
      return MaliciousCodePackageAnalyzer(pyPackage,**options)
    except PyPackageNotFoundException as e:
      cls.__logger.error("Package '{}' version:{} NOT FOUND {}".format(package_name,"<LATEST>" if package_version is None else package_version,e))
      if checked==True:
        return None
      else:
        raise e

  def __init__(self, pyPackage:PyPackage, **options) -> None:
    super().__init__(pyPackage, **options)
    
  def _checkPrerequisites(self, package:PyPackage) -> str:
    """
      Method called before the analysis start. Here all the prerequisites for the analysis are checked.
        Parameters:
          package (PyPackage): the current package that will be analyzed
        Return (str):
          An error message that describe the error which prevent the analysis execution
    """
    if which("bandit") is None:
        return "Bandit is required but has not benn found!"
  
  def _isReleaseSupported(self, release:pypackage.PyPackageRelease) -> bool:
    """
      Test if the specified release type is supported. If not supported the release is not processed 
        Parameters:
          release (PyPackageRelease): the release object
        Return (bool):
          True if the release is supported, False otherwise
    """
    return release.getReleaseFileType() in MaliciousCodePackageAnalyzer.__SUPPORTED_RELEASES_TYPES

  def __isProcessableFile(self, file_descriptor:FileDescriptor) -> bool:
    """
      Test if the specified file is supported. If the method return False the file is ignored from the analysis
        Parameters:
          file_descriptor (FileDescriptor): a file descriptor object representing the file to test
        Return (bool):
          True if the file is supported, False otherwise
    """
    return file_descriptor.getFileName().endswith(".py")

  def _scanSources(self, repository:GitRepository, statistics:StageStatisticsData) -> map[str:GitFileDescriptor]:
    """
      Scan the sources file from the git repository, and return an object that will be used in the next analysis phase (_analyzeRelease:source_data).
      In particular, scan all the files and commits in the repository and build a map of [file_hash,file]
        Parameters:
          repository (GitRepository): a GitRepository object
          statistics (StageStatisticsData): object that can be used to report statistic data for the current analysis phase

        Return (map[str:GitFileDescriptor]):
          A map of [file_hash,file]
    """
    source_files_hashes={}
    commits=repository.getCommitsList()
    commits_len=len(commits)
    processed_files=0
    i=1
    for commit_hash in commits:
      self.__logger.debug("Processing commit {}/{} ({})".format(i,commits_len,commit_hash))
      i+=1
      commit=repository.checkoutCommit(commit_hash)
      files_at_commit=repository.getFilesAtCommit(commit)
      for cmt_file in commit.stats.files:
        if cmt_file not in files_at_commit:##File has been deleted
            continue
        git_fd=GitFileDescriptor(repository,commit.hexsha,cmt_file)
        if self.__isProcessableFile(git_fd):
          file_hash=self.__computeFileHash(os.path.join(repository.getRepositoryFolder(),cmt_file))
          source_files_hashes[file_hash]=git_fd
          processed_files+=1
    
    statistics.addStatistic("processed_commits",commits_len)
    statistics.addStatistic("processed_files",processed_files)
    return source_files_hashes

  def _scanRelease(self, release:PyPackageRelease, statistics:StageStatisticsData) -> map[str:ReleaseFileDescriptor]:
    """
      Downlaod and scan the release file, and return an object that will be used in the next analysis phase (_analyzeRelease:release_data).
      In particular, extract the release fial and build a map of all supported files [file_hash,file]
        Parameters:
          release (PyPackageRelease): a PyPackageRelease object
          statistics (StageStatisticsData): object that can be used to report statistic data for the current analysis phase

        Return (map[str:ReleaseFileDescriptor]):
          A map of [file_hash,file]
    """
    release_file_name=release.getReleaseFileName()
    
    if self._cache_folder is not None:
      destFile=os.path.join(self._cache_folder,release_file_name)
    else:
      destFile=os.path.join(self._getTempFolder(),release_file_name)
    
    if not os.path.exists(destFile):
      try:
        self.__logger.debug("Downloading release file {} to {}".format(release_file_name,destFile))
        Utils.downloadUrl(release.getDownloadUrl(),destFile)
      except Exception as e:
        raise AnalysisException("Unable to download release file content") from e
    else:
      self.__logger.debug("Using cashed release file {}".format(destFile))
    
    extract_folder=os.path.join(self._getTempFolder(),"release__"+release_file_name+"___"+release.getReleaseFileType())
    self.__logger.debug("Extracting release file {} to {}".format(release_file_name,extract_folder))
    file_count=self.__extractReleaseFile(release.getReleaseFileName(),destFile,extract_folder)
    statistics.addStatistic("processed_files",file_count)
    
    return self.__collectFilesHashes(extract_folder)

  def __extractReleaseFile(self, release_file_name:str, release_archive_file:str, extract_folder:str) -> int:
    """
      Extract all supported files from the release archive
        Parameters:
          release_file_name (str): the name of the release archive
          release_archive_file (str): path of the downlaoded archive file
          extract_folder (str): path where the release archive is extracted

        Return (int):
          The number of extracted files
    """
    try:
      ext=release_archive_file.split('.')[-1]
      if ext=="whl" :
        return self.__extractZip(release_archive_file,extract_folder)
      elif ext=="zip":
        return self.__extractZip(release_archive_file,extract_folder)
      elif ext=="tar":
        return self.__extractTar(release_archive_file,extract_folder)
      elif ext=="gz":
        return self.__extractTar(release_archive_file,extract_folder,"gz")
      elif ext=="bz2":
        return self.__extractTar(release_archive_file,extract_folder,"bz2")
      elif ext=="xz":
        return self.__extractTar(release_archive_file,extract_folder,"xz")
      elif ext=="egg":
        return self.__extractTar(release_archive_file,extract_folder,"xz")
      
    except Exception as e:
      raise AnalysisException("Unable to extract release file content of release {}".format(release_file_name)) from e

  def __extractZip(self, archive_file:str, extract_folder:str) -> int:
    """
      Extract all supported file in the specified release zip file into the specified extract folder
        Parameters:
          archive_file (str): path of the archive file
          extract_folder (str): path where the release archive is extracted

        Return (int):
          The number of extracted files
    """
    file_count=0
    with zipfile.ZipFile(open(archive_file, 'rb')) as fzip:
      for zip_info in fzip.infolist():
        if not zip_info.is_dir():
          fd=ZipFileDescriptor(fzip,zip_info)
          if self.__isProcessableFile(fd):
            fzip.extract(zip_info, extract_folder)
            file_count+=1
    return file_count

  def __extractTar(self, archive_file:str, extract_folder, mode:str=None):
    """
      Extract all supported file in the specified release tar file into the specified extract folder
        Parameters:
          archive_file (str): path of the archive file
          extract_folder (str): path where the release archive is extracted
          mode (str): optional argument that indicate which mode must be used to open the tar archive. See: https://docs.python.org/3/library/tarfile.html

        Return (int):
          The number of extracted files
    """
    file_count=0
    with tarfile.open(archive_file, mode="r"+ (":"+mode if mode is not None else "")) as tar:
      for tar_info in tar.getmembers():
        if tar_info.isfile():
          fd=TarFileDescriptor(tar,tar_info)
          if self.__isProcessableFile(fd):
            tar.extract(tar_info, extract_folder)
            file_count+=1
    return file_count
  
  def __collectFilesHashes(self, folder:str) -> map[str:ReleaseFileDescriptor]:
    """
      Recursively scan all files in the specified folder and compute its hash
        Parameters:
          folder (str): path of the folder to scan

        Return (int):
          The number of extracted files
    """
    file_hashes={}
    for path, subdirs, files in os.walk(folder):
      for name in files:
        full_file_path=os.path.join(path, name)
        relative_file_path=os.path.join(os.path.relpath(path,folder), name)
        file_hash=self.__computeFileHash(full_file_path)
        # with open(full_file_path, 'rb', buffering=0) as f:
        #   file_hash=self.__computeHash(f)
        file_hashes[file_hash]=ReleaseFileDescriptor(folder,relative_file_path)
    return file_hashes

  def _analyzeRelease(self,release:PyPackageRelease, source_data:Any, release_data:Any) ->map[str:Any]:
    """
      Search for phantom files (files that are not found in the git repository) and process them with the bandit4mal tool to found potentially dangerous code
        Parameters:
          release (PyPackageRelease): the current release object that is analyzed
          source_data (map[str:GitFileDescriptor]): the data returned from the "_scanSources" method
          release_data (map[str:ReleaseFileDescriptor]): the data returned from the "_scanRelease" method

        Return (map[str:Any]):
          A json serializable map containing the pakage anlayisi resutls data
    """
    result={
      "release":release.getReleaseFileName(),
      "status":None,
      "coherent_files":[],
      "phantom_files":[],
      "low_risk_files":[],
      "medium_risk_files":[],
      "high_risk_files":[],
    }
    
    for release_hash in release_data:
      rel_fd=release_data[release_hash]
      file_name=rel_fd.getFileName()
      
      if release_hash not in source_data:
        
        risk_level,report=self.__banditCheck(rel_fd.getFullFilePath())
        file_result={
          "file":file_name,
          "file_hash":release_hash,
          "bandit_report":report,
        }
        if risk_level==0:
          result["phantom_files"].append(file_result)
          self.__report_logger.info("Found a phanthom phantom file '{}' in release file {}".format(file_name,release.getReleaseFileName()))
        elif risk_level==1:
          result["low_risk_files"].append(file_result)
          self.__report_logger.warn("Found a LOW risk phantom file '{}' in release file {}".format(file_name,release.getReleaseFileName()))
        elif risk_level==2:
          result["medium_risk_files"].append(file_result)
          self.__report_logger.error("Found a MEDIUM risk phantom file '{}' in release file {}".format(file_name,release.getReleaseFileName()))
        else:
          result["high_risk_files"].append(file_result)
          self.__report_logger.critical("Found a HIGH risk phantom file '{}' in release file {}".format(file_name,release.getReleaseFileName()))
          
      else:
        src_fd=source_data[release_hash]
        result["coherent_files"].append({
          "file":file_name,
          "file_hash":release_hash,
          "commit_hash":src_fd.getCommitHexsha(),
          "commit_file":src_fd.getFileName(),
        })
        self.__report_logger.info("File '{}' in release file {} is coherent".format(file_name,release.getReleaseFileName()))
    
    if len(result["high_risk_files"])>0:
      status="critic"
    elif len(result["medium_risk_files"])>0:
      status="danger"
    if len(result["low_risk_files"])>0:
      status="warning"
    elif len(result["phantom_files"])>0:
      status="stable"
    else:
      status="coherent"
    
    result["status"]=status
    return result  
       
  def __computeFileHash(self, file_name:str) -> str:
    """
      Compute a SHA-512 hash for the sepcified file
        Parameters:
          file_name (str): a path pointing to the file whose hash has to be calculated
        Return (str):
          The file hash
    """
    # TODO: Should this be threaded??? 
    h  = hashlib.sha512()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(file_name, 'rb', buffering=0) as f:
      for n in iter(lambda : f.readinto(mv), 0):
          h.update(mv[:n])
    return h.hexdigest()
    
  def __computeStreamHash(self, stream) ->str:
    """
      Compute a SHA-512 hash for the sepcified stream
        Parameters:
          stream (???): the stream object whose hash has to be calculated
        Return (str):
          The file hash
    """
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
    alg=hashlib.sha512()
    while True:
      data = stream.read(BUF_SIZE)
      if not data:
          break
      alg.update(data)
    return alg.hexdigest()
  
  def __banditCheck(self, file:str) -> Tuple[int,map[str:Any]]:
    """
      Launch the bandit analysis on the specified file.
        Parameters:
          file (str): path of the file to analyze with bandit
        Return (map[str:Any]):
          A json serializable map containing the bandit's file scan results
    """
    self.__logger.debug("Bandit analysis of file {}".format(file))
    proc = Popen(["bandit", file, "-q","-f", "json"], stdout=PIPE, stderr=PIPE)
    output, _ = proc.communicate()
    report=json.loads(output.decode("utf-8"))
    
    result=[]
    risk_level=0
    if len(report["results"]) > 0:
      report_results_allowed_keys=["test_id","test_name","issue_confidence","issue_severity", "issue_text","line_number","line_range","code"]
      for report_result in report["results"]:
        if "issue_severity" in report_result:
          if report_result["issue_severity"].upper() == "LOW":
            rl=1
          elif report_result["issue_severity"].upper() == "MEDIUM":
            rl=2
          elif report_result["issue_severity"].upper() == "HIGH":
            rl=3
        risk_level=max(risk_level,rl)
        res={}
        for key in report_results_allowed_keys:
          if key in report_result:
            res[key]=report_result[key]
        result.append(res)
    return risk_level, result  

