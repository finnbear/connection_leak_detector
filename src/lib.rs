use std::net::SocketAddr;
use std::process;
use std::process::Command;
use std::time::Instant;

#[derive(Eq, PartialEq, Debug, Ord, PartialOrd, Copy, Clone)]
enum State {
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

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
enum Timer {
    Off,
    KeepAlive,
    TimeWait,
    Retransmission,
}

#[derive(Debug)]
struct ConnectionLeakDetector {
    pid: u32,
    last_update: Option<Instant>,
    connections: Vec<Connection>,
}

#[derive(Debug)]
struct Connection {
    last_seen: Instant,
    foreign_addr: SocketAddr,
    history: Vec<(Instant, NetstatSummary)>,
    http2: Option<bool>,
}

impl ConnectionLeakDetector {
    pub fn new() -> Self {
        Self {
            pid: process::id(),
            last_update: None,
            connections: Vec::new(),
        }
    }

    fn connection_mut(&mut self, foreign_addr: &SocketAddr) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| {
            if let Some(last_update) = self.last_update {
                if c.last_seen < last_update {
                    // Connections don't magically disappear and reappear.
                    return false;
                }
            }
            if c.foreign_addr != foreign_addr {
                // Connections don't magically change addresses.
                return false;
            }
            true
        })
    }

    pub fn mark_http2(&mut self, foreign_addr: &SocketAddr, http2: bool) -> Result<(), ()> {
        if let Some(connection) = self.connection_mut(foreign_addr) {
            connection.http2 = Some(http2);
        }
    }

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
                        foreign_addr: line.foreign_addr,
                        history: vec![(now, line.summarize())],
                        http2: None,
                    })
                }
            }
        }

        self.last_update = Some(now);

        Ok(())
    }
}

#[derive(Debug)]
struct NetstatSummary {
    receive_queue: usize,
    send_queue: usize,
    state: State,
    timer: Timer,
}

#[derive(Debug)]
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
    use crate::ConnectionLeakDetector;
    use actix_web::rt::Runtime;
    use actix_web::web::get;
    use actix_web::{App, HttpResponse, HttpServer};
    use core::mem;
    use serial_test::serial;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    #[serial]
    fn simple() {
        let mut detector = ConnectionLeakDetector::new();
        detector.update().unwrap();
        println!("{:?}", detector);
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
                let mut i = 0;
                loop {
                    let stream = TcpStream::connect("localhost:8888").unwrap();
                    mem::forget(stream);

                    detector.update().unwrap();
                    println!("{:?}", detector);
                    i += 1;
                    if i > 4 {
                        handle.stop(true).await;
                        break;
                    }
                    actix_rt::time::sleep(Duration::from_secs(3)).await;
                }
            });

            server.await.unwrap();
        })
    }
}
