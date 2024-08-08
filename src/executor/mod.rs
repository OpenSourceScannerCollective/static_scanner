use std::{path::PathBuf, sync::Arc};
use crossbeam_channel::Sender;
use clap::{error::ErrorKind, Error};
use crossbeam::sync::WaitGroup;
use threadpool::{Builder, ThreadPool};
use walkdir::WalkDir;
use crate::{git_source::GitRepo, inspect::Inspector, result::Secret};
use std::fs::read_to_string;

const THREADS_NUM: usize = 8;
const GUESS_OMIT_SIZE: usize = 64;

/// Provides source functionality like:
///  - path buffer of root directory,
///  - WalkDir,
///  - flushing the source,
///
trait SourceProvider {
    fn path_buf(&self) -> PathBuf;
    fn flush(&mut self) -> Result<(), Error>;
    fn walk_dir(&self) -> Option<WalkDir>;
}

enum Source {
    Local(PathBuf),
    Remote(GitRepo),
}

impl Source {
    #[inline(always)]
    fn new(path: Option<&PathBuf>, url: Option<&String>) -> Result<Self, Error> {
        match url {
            Some(url) => {
                match GitRepo::remote(url) {
                    Ok(gr) => Ok(Source::Remote(gr)),
                    Err(_) => Err(Error::new(ErrorKind::Io)),
                }
            },
            None => {
                match path {
                    Some(path) => Ok(Source::Local(path.clone())),
                    None => Err(Error::new(ErrorKind::Io)),
                }
            },
        }
    }
}

impl SourceProvider for Source {
    #[inline(always)]
    fn path_buf(&self) -> PathBuf {
        match self {
            Self::Local(l) => l.to_owned(),
            Self::Remote(gr) => gr.path(),
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            Self::Local(_) => Ok(()),
            Self::Remote(gr) => match gr.flush() {
                Ok(_) => Ok(()),
                Err(_) => Err(Error::new(ErrorKind::Io)),
            },
        }
    }

    #[inline(always)]
    fn walk_dir(&self) -> Option<WalkDir> {
        Some(WalkDir::new(self.path_buf()))
    }
}

pub struct Executor {
    source: Source,
    pool: ThreadPool,
    omit: Vec<String>,
    inspector: Arc<Inspector>,
}

impl Executor {
    #[inline(always)]
    pub fn new(
        path: Option<&PathBuf>,
        url: Option<&String>,
        config: Option<&PathBuf>,
        omit: Option<&String>,
    ) -> Result<Self, Error> {
        let Ok(mut source) = Source::new(path, url) else {
            return Err(Error::new(ErrorKind::InvalidValue));
        };

        let Some(config_path) = config else {
            let _ = source.flush();
            return Err(Error::new(ErrorKind::InvalidValue));
        };

        let mut omit_patterns: Vec<String> = Vec::with_capacity(GUESS_OMIT_SIZE);
        if let Some(patterns) = omit {
            for pattern in patterns.split(" ") {
                omit_patterns.push(pattern.to_string())
            }
        }

        let inspector = Arc::new(Inspector::try_new(
            config_path.to_str().unwrap_or_default(),
        )?);

        let pool = Builder::new().num_threads(THREADS_NUM - 1).build();

        Ok(Self {
            source,
            pool,
            omit: omit_patterns,
            inspector,
        })
    }

    #[inline(always)]
    pub fn execute(&mut self, sx: Sender<Option<Secret>>) {
        let Some(walk_dir) = self.source.walk_dir() else {
            let _ = sx.send(None);
            return;
        };
        let wg = WaitGroup::new();

        'walker: for entry in walk_dir {
            let Ok(entry) = entry else {
                continue 'walker;
            };
            if let Some(dir_name) = entry.path().to_str() {
                for pattern in self.omit.iter() {
                    if dir_name.contains(pattern) {
                        continue 'walker;
                    }
                }
            }
            if entry.file_type().is_dir() {
                continue 'walker;
            }

            let entry = entry.into_path();
            let inspector = self.inspector.clone();
            let wg = wg.clone();
            let sx = sx.clone();

            self.pool.execute(move || {
                let Ok(file_data) = read_to_string(entry.as_path()) else {
                    // TODO: crate errors handling channel.
                    drop(wg);
                    return;
                };
                let Ok(secrets) = inspector.inspect(&file_data, &format!("{}", entry.as_path().to_str().unwrap_or_default())) else {
                    drop(wg);
                    return;
                };
                if secrets.len() == 0 {
                    drop(wg);
                    return;
                }
                for secret in secrets.iter() {
                    let _ = sx.send(Some(secret.clone()));
                }
                drop(wg);
            });
        }
        wg.wait();
        let _ = sx.send(None);
        let _ = self.source.flush();
    }
}
