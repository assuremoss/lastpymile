from __future__ import annotations
import os
from typing import Callable
from git import Repo
import git

class GitRepository:
  """
    Useful class that wrap the git.Repo class
  """
  
  @staticmethod 
  def cloneFromUrl(repository_url:str, clone_path:str) -> GitRepository:
    """
      Static method to create a GitRepository object, cloning a remote repository
        Parameters:
          repository_url (str): the url of the git repository to clone
          clone_path (str): a disk path where the repository will be cloned.

        Return (GitRepository):
          A GitRepository object to manage the repository 

        Raise (GitException): If the repository cannto be cloned
    """
    try:
      repo=Repo.clone_from(repository_url, clone_path)
      return GitRepository(repo,clone_path,repository_url)
    except Exception as e:
      raise GitException("Error encountered while cloning repository from {}".format(repository_url)) from e
  
  @staticmethod 
  def loadFromPath(repository_path:str) -> GitRepository:
    """
      Static method to create a GitRepository object, loading the repository from a local folder
        Parameters:
          repository_path (str):  a disk path where the repository is located.

        Return (GitRepository):
          A GitRepository object to manage the repository

        Raise (GitException): If the repository cannto be loaded
    """
    try:
      repo=Repo(path=repository_path)
      return GitRepository(repo,repository_path)
    except Exception as e:
      raise GitException("Error encountered while loadin repository from {}".format(repository_path)) from e
  

  def __init__(self, repository:Repo, repository_folder:str, repository_url:str=None):
    self.repo=repository
    self.repository_folder=repository_folder
    self.repository_url=repository_url

  def getRepositoryUrl(self) -> str:
    """
      Return the remote repository url if the repository was cloned from an url

        Return (str):
          the remote repository url or None if the repository was loaded from a local disk folder
    """
    return self.repository_url

  def getRepositoryFolder(self) -> str:
    """
      Return the disk path location where this repository is located

        Return (str):
          the disk path location where this repository is located
    """
    return self.repository_folder
  
  def getCommitsList(self) -> list[str]:
    """
      Return a list of all commit's hashes present in the repository

        Return (str):
          a list of all commit's hashes present in the repository
    """
    return list(self.repo.git.rev_list('--all','--remotes').split("\n"))
  
  def checkoutCommit(self, commit_hash:str) -> git.objects.commit.Commit:
    """
      Checkout the specified commit

        Return (git.objects.commit.Commit):
          a git.objects.commit.Commit Object
    """
    if self.repo.head.object.hexsha!=commit_hash:
      self.repo.git.checkout(commit_hash)
    return self.repo.head.object

  def getCommitEntryContent(self,commit_hash:str,file_path:str) -> bytes:
    """
      Get the content of a file in the specified commit. 

        Return (bytes):
          the file content of the specified file
    """
    self.checkoutCommit(commit_hash)
    with open(os.path.join(self.repository_folder,file_path), 'rb') as f:
      return f.read()
    ##
    ## Important!! DO NOT USE self.repo.git.show since it use the STD_OUT to capture the content of the file and can alter the real file content (remove empty lines/has bad encoing)
    ##
    # return self.repo.git.show('{}:{}'.format(commit_hash, file_path))

  def getFilesAtCommit(self, commit:git.objects.commit.Commit, filter:Callable[[str], bool]=None) -> list[str]:
    """
      Return the list of all files at the specified commit 
        Patameters:
          commit(git.objects.commit.Commit): a commit object
          filter(Callable[[str], bool]=None)): an optional filter function to filter the result. 
                                               The function has a str parameter with the file path (relative to the repository) and must return a bool,
                                               where True will add the file to the result and False will exclude it.
        Return (bytes):
          the file content of the specified file
    """
    commit_files=[]
    for element in commit.tree.traverse():
      if filter is None or filter(element.path)==True:
        commit_files.append(element.path)
    return commit_files

class GitException(Exception):
  def __init__(self,message):            
    super().__init__(message)