import os
from git import Repo

class GitRepository:
  
  
  @staticmethod 
  def cloneFromUrl(repository_url:str, clone_path:str):
    try:
      repo=Repo.clone_from(repository_url, clone_path)
      return GitRepository(repo,clone_path,repository_url)
    except Exception as e:
      raise GitException("Error encountered while cloning repository from {}".format(repository_url)) from e
  
  @staticmethod 
  def loadFromPath(repository_path:str):
    try:
      repo=Repo(path=repository_path)
      return GitRepository(repo,repository_path)
    except Exception as e:
      raise GitException("Error encountered while loadin repository from {}".format(repository_path)) from e
  

  def __init__(self, repository, repository_folder, repository_url=None):
    self.repo=repository
    self.repository_folder=repository_folder
    self.repository_url=repository_url


  # def getBranchesList(self):
  #   self.__checkRepo()
  #   refs=[]
  #   for ref in self.repo.remote().refs:
  #     refs.append(ref.name.replace("origin/",""))
  #   return refs

  def getRepositoryUrl(self):
    return self.repository_url

  def getRepositoryFolder(self):
    return self.repository_folder
  
  def __getBranchesnames(self):
    self.repo.branches
  
  def getCommitsList(self):
    return list(self.repo.git.rev_list('--all','--remotes').split("\n"))
  
  def checkoutCommit(self,commit_hash):
    if self.repo.head.object.hexsha!=commit_hash:
      self.repo.git.checkout(commit_hash)
    return self.repo.head.object

  def getCommitEntryContent(self,commit_hash,file_path):
    self.checkoutCommit(commit_hash)
    with open(os.path.join(self.repository_folder,file_path), 'rb') as f:
      return f.read()
    # return self.repo.git.show('{}:{}'.format(commit_hash, file_path))


  def getFilesAtCommit(self, commit, filter=None):
    commit_files=[]
    for element in commit.tree.traverse():
      if filter is None or filter(element.path)==True:
        commit_files.append(element.path)
    return commit_files

class GitException(Exception):
  def __init__(self,message):            
    super().__init__(message)