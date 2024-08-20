use std::{collections::HashSet, path::PathBuf, sync::Arc};
use crossbeam_channel::{unbounded, Sender, Receiver};
use clap::{error::ErrorKind, Error};
use walkdir::WalkDir;
use crate::{git_source::GitRepo, inspect::Inspector, reporter::Input};
use std::fs::read_to_string;
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
use std::thread::spawn;

const GUESS_OMIT_SIZE: usize = 64;
const FILE_SYSTEM: &str = "------ FILE SYSTEM ------";

/// Provides source functionality like:
///  - path buffer of root directory,
///  - WalkDir,
///  - flushing the source,
///
trait SourceProvider {
    fn path_buf(&self) -> Option<PathBuf>;
    fn flush(&mut self) -> Result<(), Error>;
    fn walk_dir(&self) -> Option<WalkDir>;
    fn get_local_branches(&self) -> Result<Vec<String>, Error>;
    fn get_remote_branches(&self) -> Result<Vec<String>, Error>;
    fn switch_branch(&self, branch: &str) -> Result<(), Error>;
}

enum Source {
    FileSystem(PathBuf),
    Remote(GitRepo),
    Local(GitRepo),
}

impl Source {
    #[inline(always)]
    fn new_git(path: Option<&PathBuf>, url: Option<&String>) -> Result<Self, Error> {
        match url {
            Some(url) => {
                match GitRepo::remote(url) {
                    Ok(gr) => Ok(Source::Remote(gr)),
                    Err(e) => Err(Error::raw(ErrorKind::InvalidValue, e.to_string())),
                }
            },
            None => {
                match path {
                    Some(path) => match GitRepo::local(path) {
                        Ok(gr) => Ok(Source::Local(gr)),
                        Err(e) => Err(Error::raw(ErrorKind::InvalidValue, e.to_string())),
                    },
                    None => Err(Error::raw(ErrorKind::InvalidValue, "Path to a root directory should be specified.")),
                }
            },
        }
    }

    #[inline(always)]
    fn new_filesystem(path: Option<&PathBuf>) -> Result<Self, Error> {
        match path {
            Some(path) => Ok(Source::FileSystem(path.clone())),
            None => Err(Error::raw(ErrorKind::InvalidValue, "Path to a root directory should be specified.")),
        }
    }
}

impl SourceProvider for Source {
    #[inline(always)]
    fn path_buf(&self) -> Option<PathBuf> {
        match self {
            Self::FileSystem(l) => Some(l.to_owned()),
            Self::Remote(gr) => gr.path(),
            Self::Local(gr) => gr.path(),
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            Self::FileSystem(_) => Ok(()),
            Self::Remote(gr) => match gr.flush() {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::raw(ErrorKind::Io, e.to_string())),
            },
            Self::Local(_) => Ok(()),
        }
    }

    #[inline(always)]
    fn walk_dir(&self) -> Option<WalkDir> {
        Some(WalkDir::new(self.path_buf()?))
    }

    #[inline(always)]
    fn get_local_branches(&self) -> Result<Vec<String>, Error> {
        match self {
            Self::FileSystem(_) => Err(Error::raw(ErrorKind::Io, "No access to branches on filesystem")),
            Self::Remote(gr) => gr.get_local_branches().map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
            Self::Local(gr) => gr.get_local_branches().map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
        }
    }

    #[inline(always)]
    fn get_remote_branches(&self) -> Result<Vec<String>, Error> {
        match self {
            Self::FileSystem(_) => Err(Error::raw(ErrorKind::Io, "No access to branches on filesystem")),
            Self::Remote(gr) => gr.get_remote_branches().map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
            Self::Local(gr) => gr.get_remote_branches().map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
        }
    }

    #[inline(always)]
    fn switch_branch(&self, branch: &str) -> Result<(), Error> {
        match self {
            Self::FileSystem(_) => Err(Error::raw(ErrorKind::Io, "No access to branches on filesystem")),
            Self::Remote(gr) => gr.switch_branch(branch).map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
            Self::Local(gr) => gr.switch_branch(branch).map_err(|e| Error::raw(ErrorKind::InvalidSubcommand, e.to_string())),
        }
    }
}

/// Branch level specifies the level at which Git repo is scanned.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchLevel {
    Local,
    Remote,
    All,
    Head,
}

// Source describes source of the data.
//
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    FileSystem,
    Git,
}

struct DataWithInfo {
    data: String,
    file_name: String,
}

/// Config contains full configuration of Executor to run.
///
#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub data_source: DataSource,
    pub path: Option<&'a PathBuf>,
    pub url: Option<&'a String>,
    pub config: Option<&'a PathBuf>,
    pub omit: Option<&'a String>,
    pub nodeps: Option<String>,
    pub branch_level: BranchLevel,
    pub branches: &'a Option<Vec<String>>,
    pub sx_input: Sender<Option<Input>>,
}

/// Executes the scanners with given setup.
///
pub struct Executor {
    source: Source,
    omit: Vec<String>,
    inspector: Arc<Inspector>,
    branch_level: BranchLevel,
    branches: Option<HashSet<String>>,
    sx_input: Sender<Option<Input>>,
}

impl Executor {
    #[inline(always)]
    pub fn new(
        cfg: &Config,
    ) -> Result<Self, Error> {
        let mut source = match cfg.data_source {
            DataSource::Git => Source::new_git(cfg.path, cfg.url)?,
            DataSource::FileSystem => Source::new_filesystem(cfg.path)?,
        };

        let config_path = match cfg.config {
            Some(c) => Ok(c),
            None => {
                let _ = source.flush();
                Err(Error::raw(ErrorKind::InvalidValue, "Config path is not specified."))
            },
        }?;

        let mut omit_patterns: Vec<String> = Vec::with_capacity(GUESS_OMIT_SIZE);
        if let Some(patterns) = &cfg.omit {
            for pattern in patterns.split(" ") {
                omit_patterns.push(pattern.to_string())
            }
        }
        if let Some(patterns) = &cfg.nodeps {
            for pattern in patterns.split(" ") {
                omit_patterns.push(pattern.to_string())
            }
        }

        let inspector = Arc::new(Inspector::try_new(
            config_path.to_str().unwrap_or_default(),
            cfg.sx_input.clone(),
        )?);

        Ok(Self {
            source,
            omit: omit_patterns,
            inspector,
            branch_level: cfg.branch_level,
            branches: if let Some(branches) = cfg.branches { Some(branches.into_iter().map(|v| v.to_owned()).collect::<HashSet<String>>()) } else { None },
            sx_input: cfg.sx_input.clone(),
        })
    }

    #[inline(always)]
    pub fn execute(&mut self) {
        let mut branches_to_scan = Vec::new();
        match &self.branch_level {
           BranchLevel::Head => branches_to_scan.push(FILE_SYSTEM.to_string()),
           BranchLevel::All => {
               branches_to_scan.extend(self.source.get_local_branches().unwrap_or(Vec::new()));
               branches_to_scan.extend(self.source.get_remote_branches().unwrap_or(Vec::new()));
           },
           BranchLevel::Local => {
               branches_to_scan.extend(self.source.get_local_branches().unwrap_or(Vec::new()));
           },
           BranchLevel::Remote => {
               branches_to_scan.extend(self.source.get_remote_branches().unwrap_or(Vec::new()));
           },
        };
        for branch in branches_to_scan.iter() {
            let (sx_data, rx_data): (Sender<Option<DataWithInfo>>, Receiver<Option<DataWithInfo>>) = unbounded();
            if branch == FILE_SYSTEM {
                self.walk_dir(sx_data);
                break;
            }
            if let Some(branches) = &self.branches {
                if !branches.contains(branch) {
                    continue;
                }
            }
            match self.source.switch_branch(branch) {
                Ok(()) => (),
                Err(e) => {
                    println!("{}", e.to_string());
                    continue;
                },
            };
            let branch = branch.to_string().clone();
            self.walk_dir(sx_data);
            self.process(rx_data, &branch)
        }

        let _ = self.sx_input.send(None);
        let _ = self.source.flush();
    }

    #[inline(always)]
    fn walk_dir(&self, sx: Sender<Option<DataWithInfo>>) {
        let Some(walk_dir) = self.source.walk_dir() else {
            let _ = self.sx_input.send(None);
            return;
        };

        let omit = self.omit.clone();

        spawn( move || {
            'walker: for entry in walk_dir {
                let Ok(entry) = entry else {
                    continue 'walker;
                };
                if let Some(dir_name) = entry.path().to_str() {
                    for pattern in omit.iter() {
                        if dir_name.contains(pattern) {
                            continue 'walker;
                        }
                    }
                }
                if entry.file_type().is_dir() {
                    continue 'walker;
                }

                let entry = entry.into_path();
                let Ok(file_data) = read_to_string(&entry) else {
                    break;
                };

                let _ = sx.send(Some(DataWithInfo{data: file_data, file_name: entry.as_path().to_str().unwrap_or_default().to_string()}));
            }
            let _ = sx.send(None);
        });
    }

    #[inline(always)]
    fn process(&mut self, rx: Receiver<Option<DataWithInfo>>, branch: &str) {
        rx.into_iter().par_bridge().for_each( |input| {
            let Some(input) = input else {
                return;
            };
            let inspector = self.inspector.clone();
            let sx_input = self.sx_input.clone();
            let branch = branch.to_string().clone();
            let _ = sx_input.send(Some(Input::Bytes(input.data.as_bytes().len())));
            inspector.inspect(&input.data, &input.file_name, &branch);
        });
    }
}
