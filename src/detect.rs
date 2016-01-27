#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
enum DetectResult {
    Success,
    Failure,
    NotEnoughData,
}

type DetectFn = fn(&[u8]) -> DetectResult;

const PROTOCOLS: &'static [(&'static str, DetectFn)] = &[
    ("tls", detect_is_tls),
    ("http", detect_is_http),
    ("ssh", detect_is_ssh),
    ("xmpp", detect_is_xmpp),
];


fn detect_is_tls(buf: &[u8]) -> DetectResult {
    if buf.len() < 3 {
        return DetectResult::NotEnoughData;
    }

    // TLS packets start with a "Hello" record (type 0x16), followed by the
    // version.
    // TODO: This currently doesn't support SSLv2!
    if buf[0] == 0x16 && buf[1] == 0x03 && (buf[2] <= 0x03) {
        DetectResult::Success
    } else {
        DetectResult::Failure
    }
}


fn detect_is_ssh(buf: &[u8]) -> DetectResult {
    if buf.len() < 4 {
        return DetectResult::NotEnoughData;
    }

    if buf.starts_with(b"SSH-") {
        DetectResult::Success
    } else {
        DetectResult::Failure
    }
}

fn detect_is_http(buf: &[u8]) -> DetectResult {
    if buf.len() < 3 {
        return DetectResult::NotEnoughData;
    }

    // Fast path: search the buffer for 'HTTP'
    if buf.windows(4).any(|b| b == b"HTTP") {
        return DetectResult::Success;
    }

    let methods: &[&'static [u8]] = &[
        b"GET",
        b"PUT",
        b"HEAD",
        b"POST",
        b"TRACE",
        b"DELETE",
        b"CONNECT",
        b"OPTIONS"
    ];
    for method in methods.iter() {
        if buf.windows(method.len()).any(|b| b == *method) {
            return DetectResult::Success;
        }
    }

    DetectResult::Failure
}

fn detect_is_xmpp(buf: &[u8]) -> DetectResult {
    // From SSLH:
    //
    // Sometimes the word 'jabber' shows up late in the initial string, sometimes after a newline.
    // This makes sure we snarf the entire preamble and detect it.
    if buf.len() < 50 {
        return DetectResult::NotEnoughData;
    }

    if buf.windows(6).any(|b| b == b"jabber") {
        DetectResult::Success
    } else {
        DetectResult::Failure
    }
}

pub fn detect(buf: &[u8]) -> Option<&'static str> {
    for &(name, ff) in PROTOCOLS.iter() {
        if ff(buf) == DetectResult::Success {
            return Some(name);
        }
    }

    None
}

pub fn protocol_names() -> Vec<&'static str> {
    PROTOCOLS.iter()
        .map(|&(name, _)| name)
        .collect::<Vec<_>>()
}


#[test]
fn test_detect_is_ssh() {
    assert_eq!(detect_is_ssh(b"notssh"), DetectResult::Failure);
    assert_eq!(detect_is_ssh(b"SSH-1.2"), DetectResult::Success);
    assert_eq!(detect_is_ssh(b"aa"), DetectResult::NotEnoughData);
}

#[test]
fn test_detect_is_http() {
    assert_eq!(detect_is_http(b"nothttp"), DetectResult::Failure);
    assert_eq!(detect_is_http(b"HTTP/1.0 200 OK"), DetectResult::Success);
    assert_eq!(detect_is_http(b"GET /"), DetectResult::Success);
}

#[test]
fn test_detect_is_tls() {
    // First bits of a ClientHello header
    assert_eq!(detect_is_tls(b"\x16\x03\x02\x00\x31\x01\x00\x00\x2d\x03\x02"), DetectResult::Success);
    assert_eq!(detect_is_tls(b"other data"), DetectResult::Failure);
    assert_eq!(detect_is_tls(b"aa"), DetectResult::NotEnoughData);
}
