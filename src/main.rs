extern crate ansi_term;
extern crate clap;
extern crate fern;
#[macro_use] extern crate log;
#[macro_use] extern crate mioco;
extern crate time;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use clap::{App, Arg};
use mioco::tcp::{TcpListener, TcpStream};


mod detect;
mod logger;


const DEFAULT_LISTEN_ADDR : &'static str = "127.0.0.1:5555";


struct Config {
    listen_addr: SocketAddr,
    upstreams: HashMap<&'static str, SocketAddr>,
    timeout: i64,
}

impl Config {
    fn upstream_for(&self, proto: &'static str) -> Option<SocketAddr> {
        self.upstreams.get(proto).and_then(|s| Some(s.clone()))
    }
}


fn handle_proxy(
    mut client_conn: TcpStream,
    proto: &'static str,
    initial_buf: &[u8],
    config: Arc<Config>
) -> io::Result<()> {

    // If we don't have an upstream, we just skip it.
    // TODO: fallback?
    let addr = match config.upstream_for(proto) {
        Some(us) => us,
        None => {
            warn!("No upstream for protocol '{}', dropping connection...", proto);
            return Ok(());
        },
    };
    let mut server_conn = try!(TcpStream::connect(&addr));

    // Send the initial buffer (the bits we used for protocol detection).
    try!(server_conn.write_all(initial_buf));

    let mut buf = [0u8; 16 * 1024];
    loop {
        select!(
            client_conn:r => {
                let n = try!(client_conn.read(&mut buf));
                if n == 0 {
                    break;
                }

                trace!("copying {} bytes from client --> server", n);
                try!(server_conn.write_all(&buf[..n]));
            },

            server_conn:r => {
                let n = try!(server_conn.read(&mut buf));
                if n == 0 {
                    break;
                }

                trace!("copying {} bytes from server --> client", n);
                try!(client_conn.write_all(&buf[..n]));
            },
        );
    }

    Ok(())
}

fn handle_connection(mut conn: TcpStream, config: Arc<Config>) -> io::Result<()> {
    let mut buf = [0u8; 1024];
    let mut nread = 0usize;

    loop {
        // If our 'nread' value is full (i.e. we can't read more data), we just finish our loop.
        if nread == buf.len() {
            break;
        }

        let mut timer = mioco::timer::Timer::new();
        timer.set_timeout(config.timeout);

        select!(
            conn:r => {
                let n = try!(conn.read(&mut buf[nread..]));
                if n == 0 {
                    // EOF
                    break;
                }

                nread += n;
            },

            timer:r => {
                // Timeout :-(
                trace!("timing out connection");
                conn.shutdown(mioco::tcp::Shutdown::Both).unwrap();
                return Ok(());
            },
        );

        // Run detection on the portion of the buffer we have read into.
        let protocol = match detect::detect(&buf[..nread]) {
            Some(p) => p,
            None => continue,
        };

        debug!("Got protocol: {}", protocol);
        return handle_proxy(conn, protocol, &buf[..nread], config);
    }

    // Run one final detect...
    if let Some(protocol) = detect::detect(&buf[..nread]) {
        debug!("Got protocol: {}", protocol);
        handle_proxy(conn, protocol, &buf[..nread], config)
    } else {
        // TODO: default / fallback?
        Ok(())
    }
}

fn main() {
    // Convert the protocols into a tuple of:
    //      (proto, argument name, help string)
    let arg_names = detect::protocol_names().into_iter()
        .map(|p| {
            let arg_name = format!("{}-upstream", p);
            let help = format!("Sets the upstream address for the protocol '{}'", p);

            (p, arg_name, help)
        })
        .collect::<Vec<_>>();

    let mut config = App::new("demuxrs")
        .version("0.0.1")
        .author("Andrew Dunham <andrew@du.nham.ca>")
        .about("Simple protocol demultiplexer implemented in Rust")
        .arg(Arg::with_name("debug")
             .short("d")
             .multiple(true)
             .help("Sets the level of debugging information"))
        .arg(Arg::with_name("timeout")
             .short("t")
             .long("timeout")
             .help("Timeout (in milliseconds) for reads (only before a protocol is detected)"))
        .arg(Arg::with_name("listen")
             .short("l")
             .long("listen")
             .takes_value(true)
             .help("The listen address in host:port form (default: localhost:5555)"));

    // Manually build up the arguments list for each protocol.
    for &(_, ref arg_name, ref help) in arg_names.iter() {
        config = config.arg(
            Arg::with_name(&*arg_name)
                .long(&*arg_name)
                .takes_value(true)
                .help(&*help)
        );
    }

    // Actually parse
    let matches = config.get_matches();
    logger::init_logger_config(&matches);

    // Parse listen address.
    let listen_addr = {
        let s = matches.value_of("listen").unwrap_or(DEFAULT_LISTEN_ADDR);
        match FromStr::from_str(s) {
            Ok(a) => a,
            Err(e) => {
                error!("Invalid listen address '{}': {}", s, e);
                return;
            },
        }
    };

    // Parse timeout
    let timeout = {
        let s = matches.value_of("timeout").unwrap_or("1000");
        match FromStr::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                error!("Invalid timeout '{}': {}", s, e);
                return;
            },
        }
    };

    // Parse the upstreams into SocketAddrs.
    let mut config = Config {
        listen_addr: listen_addr,
        upstreams: HashMap::new(),
        timeout: timeout,
    };
    for &(proto, ref arg_name, _) in arg_names.iter() {
        let saddr = match matches.value_of(&*arg_name) {
            Some(v) => v,
            None => continue,
        };

        let addr: SocketAddr = match FromStr::from_str(saddr) {
            Ok(a) => a,
            Err(e) => {
                error!("Invalid upstream address for protocol '{}': {}", proto, e);
                continue;
            },
        };

        debug!("Upstream address for protocol '{}': {}", proto, addr);
        config.upstreams.insert(proto, addr);
    }

    mioco::start(move || {
        let config = Arc::new(config);
        let listener = TcpListener::bind(&config.listen_addr).unwrap();

        info!("Starting demux server on {:?}", listener.local_addr().unwrap());

        loop {
            let conn = try!(listener.accept());

            let c = config.clone();
            mioco::spawn(move || {
                handle_connection(conn, c)
            });
        }
    });
}
