use git2::Repository;
use std::path::PathBuf;
use std::{fs::remove_dir_all, env::temp_dir};
use std::io::{Result, Error, ErrorKind};
use random_string::generate;

#[cfg(test)]
pub mod mod_test;

const TEMP_DIR: &str = "static_scanner";
const CHARSET: &str = "abcdefghijklmnopqrstuwxyz_-";

pub struct GitRepo {
   repo: Option<Repository>,
   dir: PathBuf,
}

impl GitRepo {
    #[inline(always)]
    pub fn remote(url: &str) -> Result<Self> {
        let mut dir :PathBuf = PathBuf::from(temp_dir().as_path());
        dir.push(format!("{}/{}", TEMP_DIR, generate(12, CHARSET)));

        let repo = match Repository::clone(url, dir.clone()) {
            Ok(repo) => Ok(repo),
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
        }?;

        Ok(Self {
            repo: Some(repo),
            dir,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.dir.clone()
    }

    #[inline(always)]
    pub fn flush(&mut self) -> Result<()> {
        remove_dir_all(&self.dir)?;
        self.repo = None;
        Ok(())
    }
}
