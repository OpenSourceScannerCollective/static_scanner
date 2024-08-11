use std::collections::HashMap;
use std::iter::Iterator;
use std::rc::Rc;
use std::sync::Mutex;
use std::fmt::{Debug, Display};
use std::io::Write;
use crossbeam_channel::{select, Receiver, Sender};
use crate::result::{Secret, DecoderType, DetectorType};

const REPORT_HEADER: &str = "[ 📋 SCANNING REPORT 📋 ]";
const REPORT_FOOTER: &str = "[ 📋 --------------- 📋 ]";
const GUESS_ANALITICS_CAPACITY: usize = 1024;

/// ReportWrite compounds trait Write and Debug.
///
pub trait ReportWrite : Write + Debug {}

#[derive(Debug)]
/// Output determines the output of the Reporter.
pub enum Output {
    StdOut,
    Writer(Rc<Mutex<Box<dyn ReportWrite>>>),
    Receiver(Sender<Option<String>>)
}

/// Reporter reports received secrets to specified Output.
/// Reporter isn't thread safe. Wrap it in Atomic Referance Counter to deal safely with the concurency.
pub trait Reporter :Debug {
    /// Sets output, shall be used before receive function is run.
    fn set_output(&mut self, output: Output);
    /// Receive reads the output from the channel and formats the output passing it to preset Output.
    fn receive(&mut self, ch: Receiver<Option<Secret>>);
}

#[derive(Debug)]
struct Scribe {
    output: Output,
    detector_type_count: HashMap<DetectorType, usize>,
    decoder_type_counts: HashMap<DecoderType, usize>,
}

impl Reporter for Scribe {
    #[inline(always)]
    fn receive(&mut self, ch: Receiver<Option<Secret>>) {
        self.to_output(&REPORT_HEADER);
        'printer: loop {
            select! {
                recv(ch) -> message => match message {
                    Ok(m) => match m {
                        Some(s) => {
                            self.to_output(&s);
                            self.update_analitics(&s);
                        },
                        None => break 'printer,
                    },
                    Err(_) => break 'printer,
                },
            }
        }

        self.formatted_analitics_to_output();
        self.to_output(&REPORT_FOOTER);
    }

    #[inline(always)]
    fn set_output(&mut self, output: Output) {
        self.output = output;
    }
}

impl Scribe {
    fn to_output(&self, s: &impl Display) {
        match &self.output {
            Output::StdOut => println!("{s}"),
            Output::Writer(b) => {
                if let Ok(mut b) = b.lock() {
                    let _ = b.write(format!("{s}\n").as_bytes());
                }
            },
            Output::Receiver(sx) => {let _ = sx.send(Some(format!("{s}\n").to_string()));},
        };
    }

    fn update_analitics(&mut self, s: &Secret) {
        self.decoder_type_counts.entry(s.decoder_type.to_owned()).and_modify(|v| *v += 1).or_insert(0);
        self.detector_type_count.entry(s.detector_type.to_owned()).and_modify(|v| *v += 1).or_insert(0);
    }

    fn formatted_analitics_to_output(&self) {
        self.formatted_in_loop_to_output(self.decoder_type_counts.iter(), " FOUND SECRETS PER DECODER ", "Decoder Type");
        self.formatted_in_loop_to_output(self.detector_type_count.iter(), " FOUND SECRETS PER DETECTOR ", "Detector Type");
    }

    fn formatted_in_loop_to_output<T, E>(&self, iter: impl Iterator<Item = (T, E)>, heading: &str, title: &str)
    where
        T: Display,
        E: Display,
    {
        self.to_output(&format!("|{0:=^59}|", &format!("{heading}")));
        self.to_output(&format!("|{0:-^59}|", ""));
        self.to_output(&format!("| {0: ^46} | {1: ^8} |", title, "Found"));
        self.to_output(&format!("|{0:-^59}|", ""));
        for (k, v) in iter {
            self.to_output(&format!("| {0: ^46} | {1: ^8} |", format!("{k}"), format!("{v}")));
        }
        self.to_output(&format!("|{0:=^59}|", "="));
        self.to_output(&"");
    }
}

/// Creates new Reporter.
pub fn new(output: Output) -> impl Reporter {
    return Scribe{
        output,
        detector_type_count: HashMap::with_capacity(GUESS_ANALITICS_CAPACITY),
        decoder_type_counts: HashMap::with_capacity(GUESS_ANALITICS_CAPACITY),
    }
}
