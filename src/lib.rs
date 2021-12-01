use enum_iterator::IntoEnumIterator;
use std::collections::HashMap;
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};
use std::{mem, process};

#[derive(Eq, PartialEq, Debug, Ord, PartialOrd, Copy, Clone)]
pub enum State {
    Listen,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    LastAck,
    Established,
    TimeWait,
    CloseWait,
    Closing,
    Closed,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash)]
pub enum Timer {
    Off,
    KeepAlive,
    TimeWait,
    Retransmission,
}

/// Serves as a indicator of what might causing leaks.
/// The user is relied upon to specify this properly.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, IntoEnumIterator)]
pub enum Protocol {
    Tcp,
    Http1,
    Http11,
    Http2,
    Http3,
    WebSocket,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Tcp
    }
}

/// Serves as a indicator of what might causing leaks.
/// The user is relied upon to specify this properly.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, IntoEnumIterator)]
pub enum Encryption {
    Unknown,
    None,
    Tls,
}

impl Default for Encryption {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Serves as a indicator of what might causing leaks.
/// The user is relied upon to specify this properly.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, IntoEnumIterator)]
pub enum Verdict {
    None,
    /// Will never be considered a leak.
    Exempt,
    /// Will be considered a leak if open, even before the leak_threshold.
    /// Set this when finished with a connection, if possible.
    Expired,
}

impl Default for Verdict {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug)]
pub struct ConnectionLeakDetector {
    pid: u32,
    log_path: Option<String>,
    leak_threshold: Duration,
    last_update: Option<Instant>,
    connections: Vec<Connection>,
    pending_markings: Vec<(
        SocketAddr,
        Option<Protocol>,
        Option<Encryption>,
        Option<Verdict>,
    )>,
}

impl ConnectionLeakDetector {
    /// Creates a new connection leak detector for the current PID.
    pub fn new() -> Self {
        Self::for_pid(process::id())
    }

    /// Creates a new connection leak detector for the specified PID.
    pub fn for_pid(pid: u32) -> Self {
        Self {
            pid,
            log_path: None,
            leak_threshold: Duration::from_secs(1 * 3600),
            last_update: None,
            connections: Vec::new(),
            pending_markings: Vec::new(),
        }
    }

    /// When a connection stays open, without making progress, for this long, it is considered
    /// leaked. Defaults to 1 hour.
    pub fn set_leak_threshold(&mut self, leak_threshold: Duration) {
        self.leak_threshold = leak_threshold;
    }

    /// If log path is set, a CSV file will be created and appended to (every update).
    pub fn set_log_path(&mut self, log_path: impl ToString) {
        self.log_path = Some(log_path.to_string());
    }

    /// Returns a mutable reference to the corresponding connection, if any.
    fn connection_mut(&mut self, foreign_addr: &SocketAddr) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| {
            if let Some(last_update) = self.last_update {
                if c.last_seen < last_update {
                    // Connections don't magically disappear and reappear.
                    return false;
                }
            }
            if &c.foreign_addr != foreign_addr {
                // Connections don't magically change addresses.
                return false;
            }
            true
        })
    }

    /// Marks a connection to a foreign address for diagnostic reasons.
    ///
    /// Use None to for protocol, encryption, or verdict to not set it.
    ///
    /// Even if all are none, connection will be marked as updated now.
    pub fn mark_connection(
        &mut self,
        foreign_addr: &SocketAddr,
        protocol: Option<Protocol>,
        encryption: Option<Encryption>,
        verdict: Option<Verdict>,
    ) {
        if self.connection_mut(foreign_addr).is_some() {
            self.mark_connection_internal(foreign_addr, protocol, encryption, verdict);
        } else {
            self.pending_markings
                .push((foreign_addr.clone(), protocol, encryption, verdict));
        }
    }

    /// Never adds to pending.
    fn mark_connection_internal(
        &mut self,
        foreign_addr: &SocketAddr,
        protocol: Option<Protocol>,
        encryption: Option<Encryption>,
        verdict: Option<Verdict>,
    ) {
        if let Some(connection) = self.connection_mut(foreign_addr) {
            if let Some(protocol) = protocol {
                connection.protocol = protocol;
            }
            if let Some(encryption) = encryption {
                connection.encryption = encryption;
            }
            if let Some(verdict) = verdict {
                connection.verdict = verdict;
            }
            connection.last_update = Instant::now();
        }
    }

    /// Returns iterator over presumed leaked connections, or error.
    pub fn update(&mut self) -> Result<(), &'static str> {
        let output = Command::new("netstat")
            .arg("-natpo")
            .output()
            .map_err(|_| "net-tools/netstat must be installed")?;

        let now = Instant::now();

        for s in std::str::from_utf8(&output.stdout)
            .map_err(|_| "could not convert netstat output to utf8")?
            .split('\n')
        {
            if let Some(line) = NetstatLine::parse(s) {
                if line.pid != self.pid {
                    // Connection is of some other process.
                    continue;
                }

                if let Some(old) = self.connection_mut(&line.foreign_addr) {
                    old.last_seen = now;
                    let last_update = &old.history.last().unwrap().1;
                    if line.state > last_update.state {
                        // The state progressed.
                        old.history.push((now, line.summarize()));
                    }
                } else {
                    self.connections.push(Connection {
                        last_seen: now,
                        last_update: now,
                        foreign_addr: line.foreign_addr,
                        history: vec![(now, line.summarize())],
                        protocol: Protocol::default(),
                        encryption: Encryption::default(),
                        verdict: Verdict::default(),
                    })
                }
            }
        }

        self.last_update = Some(now);

        for marking in mem::take(&mut self.pending_markings) {
            self.mark_connection_internal(&marking.0, marking.1, marking.2, marking.3);
        }

        if let Some(log_path) = self.log_path.as_ref() {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .map_err(|_| "could not open log file")?;
            let report = self.get_report();
            let time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| "error getting system time")?;

            let mut buf = format!("{},{},", time.as_secs(), report.total);
            for protocol in Protocol::into_enum_iter() {
                let _ = write!(
                    &mut buf,
                    "{},",
                    report.by_protocol.get(&protocol).map(|n| *n).unwrap_or(0)
                );
            }
            for encryption in Encryption::into_enum_iter() {
                let _ = write!(
                    &mut buf,
                    "{},",
                    report
                        .by_encryption
                        .get(&encryption)
                        .map(|n| *n)
                        .unwrap_or(0)
                );
            }
            let _ = writeln!(&mut buf);

            write!(file, "{}", buf).map_err(|_| "could not write to log file")?;
        }

        Ok(())
    }

    pub fn iter_leaked_connections(&self) -> impl Iterator<Item = &Connection> {
        let last_update = self.last_update.unwrap_or(Instant::now());
        let leak_threshold = self.leak_threshold;
        self.connections
            .iter()
            .filter(move |&c| c.is_leaked(last_update, leak_threshold))
    }

    pub fn get_report(&self) -> LeakReport {
        let mut report = LeakReport::default();

        for connection in self.iter_leaked_connections() {
            report.total += 1;
            *report.by_protocol.entry(connection.protocol).or_insert(0) += 1;
            *report
                .by_encryption
                .entry(connection.encryption)
                .or_insert(0) += 1;
        }

        report
    }
}

#[derive(Debug, Default)]
pub struct LeakReport {
    pub total: usize,
    pub by_protocol: HashMap<Protocol, usize>,
    pub by_encryption: HashMap<Encryption, usize>,
}

#[derive(Debug)]
pub struct Connection {
    last_seen: Instant,
    last_update: Instant,
    foreign_addr: SocketAddr,
    /// Never empty.
    history: Vec<(Instant, NetstatSummary)>,
    protocol: Protocol,
    encryption: Encryption,
    verdict: Verdict,
}

impl Connection {
    fn is_leaked(&self, last_update: Instant, leak_threshold: Duration) -> bool {
        let (last_time, last_summary) = self.history.last().unwrap();
        if self.last_seen < last_update {
            // No longer exists; not a leak.
            return false;
        }
        if last_summary.state == State::Closed {
            // Closed; not a leak.
            return false;
        }
        match self.verdict {
            Verdict::Exempt => return false,
            Verdict::Expired => return true,
            Verdict::None => (),
        }
        if last_time.max(&self.last_update).elapsed() < leak_threshold {
            // Made progress recently; not a leak.
            return false;
        }
        true
    }
}

#[derive(Debug)]
#[allow(unused)]
struct NetstatSummary {
    receive_queue: usize,
    send_queue: usize,
    state: State,
    timer: Timer,
}

#[derive(Debug)]
#[allow(unused)]
struct NetstatLine {
    receive_queue: usize,
    send_queue: usize,
    local_addr: SocketAddr,
    foreign_addr: SocketAddr,
    state: State,
    pid: u32,
    timer: Timer,
}

impl NetstatLine {
    /// Returns None if anything goes wrong while parsing.
    fn parse(line: &str) -> Option<Self> {
        // tcp        0      0 10.19.169.232:34176     162.159.136.234:443     ESTABLISHED 5180/firefox         keepalive (178.92/0/0)

        let mut split = line.split_ascii_whitespace();

        if split.next()? != "tcp" {
            return None;
        }
        let receive_queue = split.next()?.parse::<usize>().ok()?;
        let send_queue = split.next()?.parse::<usize>().ok()?;
        let local_addr = split.next()?.parse::<SocketAddr>().ok()?;
        let foreign_addr = split.next()?.parse::<SocketAddr>().ok()?;
        let state_string = split.next()?.to_ascii_lowercase().replace('_', "");
        let state = match state_string.as_str() {
            "listen" => State::Listen,
            "synsent" => State::SynSent,
            "synreceived" => State::SynReceived,
            "established" => State::Established,
            "finwait1" => State::FinWait1,
            "finwait2" => State::FinWait2,
            "closewait" => State::CloseWait,
            "closing" => State::Closing,
            "lastack" => State::LastAck,
            "timewait" => State::TimeWait,
            "closed" => State::Closed,
            _ => return None,
        };
        let (pid_str, _program_name) = split.next()?.split_once('/')?;
        let pid = pid_str.parse::<u32>().ok()?;
        let timer = match split.next()?.to_ascii_lowercase().as_str() {
            "off" => Timer::Off,
            "keepalive" => Timer::KeepAlive,
            "timewait" => Timer::TimeWait,
            "on" => Timer::Retransmission,
            _ => return None,
        };
        Some(Self {
            receive_queue,
            send_queue,
            local_addr,
            foreign_addr,
            state,
            pid,
            timer,
        })
    }

    fn summarize(&self) -> NetstatSummary {
        NetstatSummary {
            send_queue: self.send_queue,
            receive_queue: self.receive_queue,
            state: self.state,
            timer: self.timer,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConnectionLeakDetector, Encryption};
    use actix_web::web::get;
    use actix_web::{App, HttpResponse, HttpServer};
    use serial_test::serial;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    #[serial]
    fn simple() {
        let mut detector = ConnectionLeakDetector::new();
        detector.update().unwrap();
        assert_eq!(detector.iter_leaked_connections().count(), 0);
    }

    #[test]
    #[serial]
    fn actix_web() {
        actix_rt::System::new().block_on(async move {
            let server = HttpServer::new(|| App::new().route("/", get().to(|| HttpResponse::Ok())))
                .keep_alive(2)
                .client_timeout(2)
                .shutdown_timeout(2)
                .bind("127.0.0.1:8888")
                .unwrap()
                .run();

            let handle = server.handle();

            actix_rt::spawn(async move {
                let mut detector = ConnectionLeakDetector::new();
                detector.set_leak_threshold(Duration::from_secs(1));
                detector.set_log_path("/tmp/connection_leak_detector_test.csv");

                let stream = TcpStream::connect("localhost:8888").unwrap();
                let addr = stream.local_addr().unwrap();
                detector.mark_connection(&addr, None, Some(Encryption::None), None);
                std::mem::forget(stream);

                actix_rt::time::sleep(Duration::from_millis(500)).await;

                detector.update().unwrap();
                assert_eq!(detector.iter_leaked_connections().count(), 0);

                actix_rt::time::sleep(Duration::from_millis(1000)).await;

                detector.update().unwrap();
                assert_eq!(detector.iter_leaked_connections().count(), 2);
                println!("{:?}", detector.get_report());

                handle.stop(false).await;
            });

            server.await.unwrap();
        })
    }
}
