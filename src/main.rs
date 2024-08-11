use clap::{arg, command, error::ErrorKind, value_parser, Command, Error};
use crossbeam_channel::{unbounded, Receiver, Sender};
use static_detector::result::Secret;
use static_detector::executor::Executor;
use static_detector::reporter::{Reporter, Output, new as new_reporter};
use crossbeam_utils::sync::WaitGroup;
use std::path::PathBuf;
use std::thread::spawn;
use std::time::Instant;

fn main() {
    let cmd = Command::new("detector")
          .bin_name("detector")
          .subcommand_required(true)
          .about("Detector scans for secrets according to configurations patterns.")
          .subcommand(
              command!("filesystem")
              .about("Scan filesystem")
              .arg(
                  arg!(--"path" <Path> "Path to direcory to scan.")
                      .value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"omit" <String> "Space separated file patterns to ommit").value_parser(value_parser!(String)),
          ))
          .subcommand(
              command!("git")
              .about("Scan remote git repository")
              .arg(
                  arg!(--"url" <String> "URL to git repository to scan.")
                      .value_parser(value_parser!(String)),
              ).arg(
                  arg!(--"config" <Path> "Path to config YAML file used for scanner configuration.").value_parser(value_parser!(PathBuf)),
              ).arg(
                  arg!(--"omit" <String> "Space separated file patterns to ommit").value_parser(value_parser!(String)),
          ));
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("filesystem", matches)) => {
            match scan(
                matches.get_one::<PathBuf>("path"),
                None,
                matches.get_one::<PathBuf>("config"),
                matches.get_one::<String>("omit"),
            ) {
                Ok(s) => println!("[ 📋 Finished ]\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]:\n{}", e.to_string()),
            }
        }
        Some(("git", matches)) => {
            match scan(
                None,
                matches.get_one::<String>("url"),
                matches.get_one::<PathBuf>("config"),
                matches.get_one::<String>("omit"),
            ) {
                Ok(s) => println!("[ 🎉 Success ]\n{s}"),
                Err(e) => println!("[ 🤷 Failure ]:\n{}", e.to_string()),
            }
        }
        _ => println!("Unknown command. Please check help."),
    };
}

fn scan(
    path: Option<&PathBuf>,
    url: Option<&String>,
    config: Option<&PathBuf>,
    omit: Option<&String>,
) -> Result<String, Error> {
    let start = Instant::now();

    let (sx, rx): (Sender<Option<Secret>>, Receiver<Option<Secret>>) = unbounded();

    let Ok(mut executor) = Executor::new(path, url, config, omit) else {
        return Err(Error::new(ErrorKind::InvalidValue));
    };

    let wg_print = WaitGroup::new();
    let wg_print_clone = wg_print.clone();

    spawn(move || {
        let mut reporter = new_reporter(Output::StdOut);
        reporter.receive(rx);
        drop(wg_print_clone);
    });

    executor.execute(sx);

    wg_print.wait();

    let duration = start.elapsed();
    return Ok(format!("Proccessing took {} milliseconds.\n", duration.as_millis()).to_owned());
}
