from __future__ import annotations
from abc import ABC, abstractmethod

import logging
import os, tempfile
import time
from datetime import datetime

from .utils import Utils
from .pypackage import PyPackage, PyPackageRelease
from .gitrepository import GitRepository

class AbstractPackageAnalysis(ABC):

  def __init__(self, pyPackage:PyPackage, **options):
    self.pyPackage=pyPackage
    self.__logger=logging.getLogger("lastpymile."+type(self).__name__)
    self.__options=options
    self.__analysis_in_progress=False
    self._tmp_folder=None
    
    cache_folder=self.__getOption("cache_folder",None)
    if cache_folder is not None:
      cache_folder=os.path.join(cache_folder,pyPackage.getName()+"_"+pyPackage.getVersion())
      if not os.path.exists(cache_folder):
        os.makedirs(cache_folder)
    self._cache_folder=cache_folder
    

  def __getOption(self,name,default_value=None):
    return self.__options[name] if name in self.__options else default_value

  def _getTempFolder(self):
    if self._tmp_folder is None:
      raise Exception("Invalid call to _getTempFolder")
    return self._tmp_folder

  def startAnalysis(self):
    
    if self.__analysis_in_progress==True:
      raise AnalysisException("Analysis already in progress")
    self.__analysis_in_progress=True

    analysis_report=AbstractPackageAnalysis.AnalysisReport(self.pyPackage)

    prerequisite_error=self._checkPrerequisites(self.pyPackage)
    if prerequisite_error!=True:
      if isinstance(prerequisite_error,str):
        self.__logger.critical(prerequisite_error)
        analysis_report.failed(prerequisite_error)
      return analysis_report.getReport()

    
    try:
      self._tmp_folder=self.__setupTempFolder(self.__getOption("tmp_folder"))
      try:
        self.__doAnalysis(analysis_report)
        analysis_report.terminated()
      finally:
        if not self.__getOption("keep_tmp_folder",False) and os.path.exists(self._getTempFolder()):
          self.__logger.debug("Deleting temp folder {}".format(self._getTempFolder()))
          Utils.rmtree(self._getTempFolder())
    finally:
      self._tmpFolder=None
      self.__analysis_in_progress=False
      
    self.__logger.info("Package {} version:{} Analysis TERMINATED in {} seconds".format(self.pyPackage.getName(),self.pyPackage.getVersion(),analysis_report.getAnalysisDurationMs()/1000))
    return analysis_report.getReport()

  def __doAnalysis(self,analysis_report:AnalysisReport):
    self.__logger.info("Package '{}' version:{} Analysis STARTED".format(self.pyPackage.getName(),self.pyPackage.getVersion()))
    
    releases=[]
    for release in self.pyPackage.getRelaeses():
      if self._isReleaseSupported(release)==True:
        releases.append(release)

    if len(releases)==0:
      analysis_report.failed("No supported or selected releases found")
      return

    ###
    ### SOURCES PROCESSING
    ###
    try:
      self.__logger.info("Sources processing for package '{}' STARTED".format(self.pyPackage.getName(),self.pyPackage.getVersion()))
      stats_data=StageStatisticsData("processing_sources")
      sources_stage_data=self.__prepareSources(stats_data)
      stats_data.stageCompleted()
      analysis_report.addStatistics(stats_data)
      self.__logger.info("Sources processing for package '{}' TERMINATED".format(self.pyPackage.getName()))
    except AnalysisException as e:
      if self.__logger.isEnabledFor(logging.DEBUG):
        import traceback
        self.__logger.error("Sources processing for package '{}' TERMINATED with an ERROR:\n{}".format(self.pyPackage.getName(),traceback.format_exc()))
      else:
        self.__logger.error("Sources processing for package '{}' TERMINATED with an ERROR: {}".format(self.pyPackage.getName(),e))
      analysis_report.failed(str(e))
      return
      

    for release in releases:
      
      release_fileName=release.getReleaseFileName()
      try:
        self.__logger.info("Scan of release '{}' STARTED".format(release_fileName))
        package_data=StageStatisticsData("package_{}".format(release.getReleaseFileName()))
        package_stage_data=self._scanRelease(release, package_data)
        package_data.stageCompleted()
        analysis_report.addStatistics(package_data)
        self.__logger.info("Analysis of release '{}' STARTED".format(release_fileName))
       
        result=self._analyzeRelease(release,sources_stage_data,package_stage_data)
        analysis_report.addResult(result)
        
        self.__logger.info("Analysis of release '{}' TERMINATED".format(release_fileName))
        # if result.getStatus()==True:
        #   self.__printColor("Analysis of release '{}' ".format(release_data[release_hash].getFileName()),'\033[91m')
        # else:
        #   self.__printColor("Found same file {} in sources".format(release_data[release_hash].getFileName()),'\033[92m')
        
      except AnalysisException as e:
        if self.__logger.isEnabledFor(logging.DEBUG):
          import traceback
          self.__logger.error("Analysis of release '{}' TERMINATED with an AN ERROR:\n{}".format(release_fileName,traceback.format_exc()))
        else:
          self.__logger.error("Analysis of release '{}' TERMINATED with an AN ERROR: {}".format(release_fileName,e))
        
    
  def __setupTempFolder(self,root_tmp_folder:str) -> str:
    """
    Setup a temporary folder that is used during the analysis
      Parameters:
        root_tmp_folder (str): a path to a folder that is used as temporary folder. May be None, in that case the system temp folder is used
      Return (str):
        The path of the temporary folder created. (This folder may be seafly deleted after the analysis)
    """
    if root_tmp_folder==None:
      tmp_folder= tempfile.mkdtemp()
    else:
      import time
      tmp_folder= os.path.join(root_tmp_folder,"lpm_"+(str(round(time.time() * 1000)).zfill(10))+"_"+Utils.sanitizeFolderName(self.pyPackage.getName(),20)+"_"+Utils.sanitizeFolderName(self.pyPackage.getVersion()))
      if os.path.exists(tmp_folder):
        Utils.rmtree(tmp_folder)
        os.makedirs(tmp_folder)
    
    self.__logger.info("Download folder set to {}".format(tmp_folder))
    return tmp_folder

  @abstractmethod
  def _isReleaseSupported(self,release):
    return False

  def __prepareSources(self,stage_data:StageStatisticsData) -> None:
    repository_fodler=self.__getOption("repo_folder",None)
    clone_folder=os.path.join(self._getTempFolder(),"sources")
    
    if repository_fodler is None and self._cache_folder is not None:
      cached_repo_folder=os.path.join(self._cache_folder,"repo")
      if os.path.exists(cached_repo_folder):
        self.__logger.debug("Using chased repsoitory folder {}".format(cached_repo_folder))
        repository_fodler=cached_repo_folder
      else:
        clone_folder=cached_repo_folder
    
    
    if repository_fodler is not None:
      repository=GitRepository.loadFromPath(repository_fodler)
      git_rep=repository_fodler
    else:
      git_url=self.pyPackage.getGitRepositoryUrl()
      if git_url is None:
        raise AnalysisException("Could not find a valid source repository")
      repository=GitRepository.cloneFromUrl(self.pyPackage.getGitRepositoryUrl(),clone_folder)
      git_rep=self.pyPackage.getGitRepositoryUrl()
      
    stage_data.addStatistic("git_repository",git_rep)     
    return self._scanSources(repository,stage_data)
    

  @abstractmethod
  def _checkPrerequisites(self,package:PyPackage) -> object:
    pass

  @abstractmethod
  def _scanSources(self,repository:GitRepository,stage_data:StageStatisticsData) -> object:
    pass

  @abstractmethod
  def _scanRelease(self,release:PyPackageRelease,stage_data:StageStatisticsData) -> object:
    pass

  @abstractmethod
  def _analyzeRelease(self,release:PyPackageRelease,source_data:object,release_data:object):
    pass

  def __printColor(self,text,color):
    print("{}{}{}".format(color,text,'\033[0m') )
    
  class AnalysisReport():
    
    def __init__(self,pyPackage):
      self.start_time=time.time()
      self.analysis_report={
        "package":{"name":pyPackage.getName(),"version":pyPackage.getVersion()},
        "date":datetime.now().strftime("%d/%m/%Y at %H:%M:%S.%f"),
        "duration_ms":"unknown",
        "completed":None,
        "fail_reason":None,
        "results":[],
        "statistics":[],
      }
    
    def failed(self,reason):
      self.analysis_report["completed"]=False
      self.analysis_report["fail_reason"]=reason
      
    def terminated(self):
      if self.analysis_report["completed"] is None:
        self.analysis_report["completed"]=True
        del self.analysis_report['fail_reason']
      self.analysis_report["duration_ms"]=round((time.time()-self.start_time)*1000)
    
    def addStatistics(self,stage_data:StageStatisticsData):
      self.analysis_report["statistics"].append(stage_data.getStageStatistics())
    
    def addResult(self,result):
      self.analysis_report["results"].append(result)
      
    def getAnalysisDurationMs(self):
      return  self.analysis_report["duration_ms"]
      
    def getReport(self):
      report=dict(self.analysis_report)
      if len(report["results"])==0:
        del report["results"]
      if len(report["statistics"])==0:
        del report["statistics"]
      return report


class StageStatisticsData():

  def __init__(self,stage_name):
    self.start_time=time.time()
    self.statistics={
      "stage_name":stage_name,
      "duration_ms":"unknown"
    }
    
  def stageCompleted(self):
    self.statistics["duration_ms"]=round((time.time()-self.start_time)*1000)

  def addStatistic(self,name:str,value:object):
    self.statistics[name]=value
    
  def getStageStatistics(self):
    return self.statistics

class AnalysisException(Exception):

  def __init__(self, message, trace_on_error=True):            
    super().__init__(message)
    self.trace_on_error=trace_on_error

  def trace_on_error(self):
    return self.trace_on_error