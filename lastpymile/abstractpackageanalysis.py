from __future__ import annotations
from abc import ABC, abstractmethod

import logging
import os, tempfile
import time
from datetime import datetime
from typing import Any

from .utils import Utils
from .pypackage import PyPackage, PyPackageRelease
from .gitrepository import GitRepository

class AbstractPackageAnalysis(ABC):
  """
    Abstarct class that contains the general execution process of an analyis for an PyPackage.
      Mainly the analysis is diveded in 3 major step:
      1- Sources scan: Sources are scanned and all required data for the sources is extrated/computed
      2- Release scan: Release file is scanned and all required data for the release is extrated/computed
      3- Analysis: sources data and release data are used to perform the actual analyisis.

    Methods listed below must be implemented:
    _isReleaseSupported(self,release):
    _checkPrerequisites(self,package:PyPackage) -> object:
    _scanSources(self,repository:GitRepository,stage_data:StageStatisticsData) -> object:
    _scanRelease(self,release:PyPackageRelease,stage_data:StageStatisticsData) -> object:
    _analyzeRelease(self,release:PyPackageRelease,source_data:object,release_data:object):
  """

  def __init__(self, pyPackage:PyPackage, **options) -> None:
    self.pyPackage=pyPackage
    self.__logger=logging.getLogger("lastpymile."+type(self).__name__)
    self.__options=options
    self.__analysis_in_progress=False
    self._tmp_folder=None
    
    cache_folder=self._getOption("cache_folder",None)
    if cache_folder is not None:
      cache_folder=os.path.join(cache_folder,pyPackage.getName()+"_"+pyPackage.getVersion())
      if not os.path.exists(cache_folder):
        os.makedirs(cache_folder)
    self._cache_folder=cache_folder
    
  def _getOption(self, name:str, default_value:Any=None) -> Any:
    """
      Utility method to get a user option if defined, otherwise return the specified default value
        Parameters:
          name (str): name of the option
          default_value (Any): default value to return if the option is not specified (default:None)
        Retrun (Any):
          the specified option or the default value
    """
    return self.__options[name] if name in self.__options else default_value

  def _getTempFolder(self) ->str:
    """
      Get the current temporary folder. This method raise an exception if called otside an analyisis
        Retrun (str):
          the current temporary folder
    """
    if self._tmp_folder is None:
      raise Exception("Invalid call to _getTempFolder")
    return self._tmp_folder

  def startAnalysis(self) -> map[str:Any]:
    """
      Start the analysis of the package
        Retrun (map[str:Any]):
          a json serializable map that contain the results of the analysis
    """
    
    if self.__analysis_in_progress==True:
      raise AnalysisException("Analysis already in progress")
    self.__analysis_in_progress=True

    analysis_report=AbstractPackageAnalysis.AnalysisReport(self.pyPackage)

    prerequisite_error=self._checkPrerequisites(self.pyPackage)
    if prerequisite_error is not None :
      if isinstance(prerequisite_error,str):
        self.__logger.critical(prerequisite_error)
        analysis_report.failed(prerequisite_error)
      return analysis_report.getReport()

    
    try:
      self._tmp_folder=self.__setupTempFolder(self._getOption("tmp_folder"))
      try:
        self.__doAnalysis(analysis_report)
        analysis_report.terminated()
      finally:
        if not self._getOption("keep_tmp_folder",False) and os.path.exists(self._getTempFolder()):
          self.__logger.debug("Deleting temp folder {}".format(self._getTempFolder()))
          Utils.rmtree(self._getTempFolder())
    finally:
      self._tmpFolder=None
      self.__analysis_in_progress=False
      
    self.__logger.info("Package {} version:{} Analysis TERMINATED in {} seconds".format(self.pyPackage.getName(),self.pyPackage.getVersion(),analysis_report.getAnalysisDurationMs()/1000))
    return analysis_report.getReport()

  def __doAnalysis(self, analysis_report:AnalysisReport) ->None:
    """
      Internal method that pratically perform the analysis
        Parameters:
          analysis_report (AnalysisReport): AnalysisReport object used to store and organize the analyis result
    """

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
      
      except AnalysisException as e:
        if self.__logger.isEnabledFor(logging.DEBUG):
          import traceback
          self.__logger.error("Analysis of release '{}' TERMINATED with an AN ERROR:\n{}".format(release_fileName,traceback.format_exc()))
        else:
          self.__logger.error("Analysis of release '{}' TERMINATED with an AN ERROR: {}".format(release_fileName,e))
    
  def __setupTempFolder(self, root_tmp_folder:str) -> str:
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
  def _isReleaseSupported(self, release:PyPackageRelease) -> bool:
    """
      Test if the specified release type is supported. If not supported the release is not processed
      This method mus be sublcassed
        Parameters:
          release (PyPackageRelease): the release object
        Return (bool):
          True if the release is supported, False otherwise
    """
    return False

  def __prepareSources(self, statistics:StageStatisticsData) -> Any:
    """
      Internal method that prepare the sources to be processed and call "_scanSources"
        Parameters:
          statistics (StageStatisticsData): object that can be used to report statistic data for the current analysis phase
        Return (Any):
          the object returned form _scanSources
    """

    repository_fodler=self._getOption("repo_folder",None)
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
      
    statistics.addStatistic("git_repository",git_rep)     
    return self._scanSources(repository,statistics)

  @abstractmethod
  def _checkPrerequisites(self, package:PyPackage) -> str:
    """
      Method called before the analysis start. Here all the prerequisites for the analysis are checked.
      This method mus be sublcassed
        Parameters:
          package (PyPackage): the current package that will be analyzed
        Return (str):
          An error message that describe the error which prevent the analysis execution
    """
    pass

  @abstractmethod
  def _scanSources(self, repository:GitRepository, statistics:StageStatisticsData) -> Any:
    """
      Abstract method where sources are scanned and prepocessed. This method shoud return an object that will be used in the next analysis phase (_analyzeRelease:source_data).
      This method mus be sublcassed
        Parameters:
          repository (GitRepository): a GitRepository object
          statistics (StageStatisticsData): object that can be used to report statistic data for the current analysis phase

        Return (Any):
          any object that can be used in the _analyzeRelease phase
    """
    pass

  @abstractmethod
  def _scanRelease(self,release:PyPackageRelease, statistics:StageStatisticsData) -> Any:
    """
      Abstract method where release file are aextracted and prepocessed. This method shoud return an object that will be used in the next analysis phase (_analyzeRelease:release_data).
      This method mus be sublcassed
        Parameters:
          release (PyPackageRelease): a PyPackageRelease object
          statistics (StageStatisticsData): object that can be used to report statistic data for the current analysis phase

        Return (map[str:ReleaseFileDescriptor]):
          any object that can be used in the _analyzeRelease phase
    """
    pass

  @abstractmethod
  def _analyzeRelease(self,release:PyPackageRelease, source_data:Any, release_data:Any) -> map[str:Any]:
    """
      Process the data from the previous phases and return a report
        Parameters:
          release (PyPackageRelease): the current release object that is analyzed
          source_data (Any): the data returned from the "_scanSources" method
          release_data (Any): the data returned from the "_scanRelease" method

        Return (map[str:Any]):
          A json serializable map containing the pakage anlaysis resutls data
    """
    pass

  class AnalysisReport():
    """
      Conveninece class to store the analyis statistics and resutls
    """

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
  """
    Conveninece class usefult to store each analysis phase statistics data
  """

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
  """
   Exception class that wrap expection captured in this main class
  """
  def __init__(self, message, trace_on_error=True):            
    super().__init__(message)
    self.trace_on_error=trace_on_error

  def trace_on_error(self):
    return self.trace_on_error