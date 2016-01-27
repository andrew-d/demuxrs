#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
enum DetectResult {
    Success,
    Failure,
    NotEnoughData,
}

type DetectFn = fn(&[u8]) -> DetectResult;

const PROTOCOLS: &'static [(&'static str, DetectFn)] = &[
    ("tls", detect_is_tls),
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
