use git2::{BranchType, Repository, build::CheckoutBuilder};
use std::path::PathBuf;
use std::{fs::remove_dir_all, env::temp_dir};
use random_string::generate;
use super::{RepositoryProvider, errors::SourceError};

#[cfg(test)]
pub(super) mod mod_test;

pub struct GitRepo {
    is_local: bool, // It is immportant to be set to true for local repo so it is not be flushed.
    repo: Option<Repository>,
}

impl GitRepo {
    #[inline(always)]
    pub(super) fn remote(url: &str) -> Result<Self, SourceError> {
        let mut dir :PathBuf = PathBuf::from(temp_dir().as_path());
        dir.push(format!("{}/{}", super::TEMP_DIR_REPO, generate(12, super::CHARSET)));
        let repo = Repository::clone(url, dir.clone())?;

        Ok(Self {
            is_local: false,
            repo: Some(repo),
        })
    }

    #[inline(always)]
    pub(super) fn local(path: &PathBuf) -> Result<Self, SourceError> {
        let repo = Repository::discover(path)?;

        Ok(Self {
            is_local: true,
            repo: Some(repo),
        })
    }

    #[inline(always)]
    pub(super) fn path(&self) -> Option<PathBuf> {
        let Some(repo) = &self.repo else {
            return None;
        };
        let Some(p) = repo.workdir() else {
            return None;
        };

        Some(PathBuf::from(p))
    }

    #[inline(always)]
    fn get_branches(&self, bt: BranchType) -> Result<Vec<String>, SourceError> {
        let Some(repo) = &self.repo else {
            return Err(SourceError::GitSourceNotReady("Repository is flushed or doesn't exist.".to_string()));
        };
        let mut branches_names = Vec::new();
        let branches = repo.branches(Some(bt))?;
        for branch in branches {
            let (b, _) = branch?;
            let name = b.name()?;

            let name = match name {
                Some(n) => Ok(n),
                None => Err(SourceError::BranchNotAccessible(format!("{:?}", bt).to_string())),
            }?;

            branches_names.push(name.to_string());
        }

        Ok(branches_names)
    }
}

impl RepositoryProvider for GitRepo {
    #[inline(always)]
    fn get_local_branches(&self) -> Result<Vec<String>, SourceError> {
        self.get_branches(BranchType::Local)
    }

    #[inline(always)]
    fn get_remote_branches(&self) -> Result<Vec<String>, SourceError> {
        self.get_branches(BranchType::Remote)
    }

    #[inline(always)]
    fn switch_branch(&self, branch: &str) -> Result<(), SourceError> {
        let Some(repo) = &self.repo else {
            return Err(SourceError::GitSourceNotReady("Repository is flushed or doesn't exist.".to_string()));
        };
        let (object, _reference) = repo.revparse_ext(branch)?;
        repo.checkout_tree(&object, Some(CheckoutBuilder::new().force()))?;

        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<(), SourceError> {
        if self.is_local {
            return Ok(());
        }
        let Some(_) = self.path() else {
            return Err(SourceError::GitSourceNotReady("Repository is flushed or doesn't exist.".to_string()));
        };
        let mut dir :PathBuf = PathBuf::from(temp_dir().as_path());
        dir.push(format!("{}", super::TEMP_DIR_REPO));
        remove_dir_all(dir)?;
        self.repo = None;

        Ok(())
    }
}
