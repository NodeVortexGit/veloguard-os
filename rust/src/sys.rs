//! Small system helpers shared by every module: commands with a time limit,
//! users, local time, /proc reads and Pango escaping.

use std::ffi::{CStr, CString};
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, as a float (like Python's time.time()).
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// strftime on local time.
pub fn strftime(fmt: &str, epoch: f64) -> String {
    let t = epoch as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    let cfmt = match CString::new(fmt) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let mut buf = [0u8; 128];
    let n = unsafe { libc::strftime(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), cfmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Same calendar day (local time)?
pub fn same_day(a: f64, b: f64) -> bool {
    strftime("%Y-%m-%d", a) == strftime("%Y-%m-%d", b)
}

fn passwd(uid: u32) -> Option<(String, String)> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    let rc = unsafe {
        libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out)
    };
    if rc != 0 || out.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned();
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) }.to_string_lossy().into_owned();
    Some((name, dir))
}

pub fn user_name(uid: u32) -> String {
    passwd(uid).map(|p| p.0).unwrap_or_else(|| uid.to_string())
}

pub fn home_of(uid: u32) -> Option<String> {
    passwd(uid).map(|p| p.1)
}

pub fn home() -> String {
    std::env::var("HOME").ok().filter(|h| !h.is_empty()).or_else(|| home_of(uid())).unwrap_or_else(|| "/".into())
}

pub fn clk_tck() -> f64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as f64 } else { 100.0 }
}

pub fn page_size() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as u64 } else { 4096 }
}

/// Read at most `limit` bytes of a file as (lossy) text; "" when unreadable.
pub fn read_text(path: &str, limit: usize) -> String {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut buf = Vec::new();
    let _ = (&mut f).take(limit as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn readlink(path: &str) -> Option<String> {
    std::fs::read_link(path).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Run argv with a time limit: (exit code, stdout). 127 = not found, 124 = timed out.
pub fn run(argv: &[&str], timeout: Duration) -> (i32, String) {
    run_env(argv, timeout, &[])
}

pub fn run_env(argv: &[&str], timeout: Duration, env: &[(&str, &str)]) -> (i32, String) {
    if argv.is_empty() {
        return (127, String::new());
    }
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .env("LC_ALL", "C.UTF-8");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return (127, String::new()),
    };
    let mut out = child.stdout.take();
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = o.take(8 << 20).read_to_end(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    let code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().unwrap_or(1),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(15)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break 124;
            }
        }
    };
    let buf = reader.join().unwrap_or_default();
    (code, String::from_utf8_lossy(&buf).into_owned())
}

/// Is a program on PATH?
pub fn which(name: &str) -> Option<String> {
    if name.contains('/') {
        return std::path::Path::new(name).is_file().then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    path.split(':')
        .map(|d| format!("{d}/{name}"))
        .find(|p| std::path::Path::new(p).is_file())
}

/// A character that doesn't show as itself in a dialog: controls, format
/// characters (bidi, zero-width), separators other than the plain space,
/// private use, non-characters, combining marks, blank letters. The set of
/// guardd/approve.py `visible` (which reads categories from unicodedata;
/// std has no category table, so the ranges that matter are listed).
fn hidden(c: char) -> bool {
    c.is_control() || matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F                       // Cf
        | 0x2028 | 0x2029                                                      // Zl, Zp
        | 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000          // Zs but ' '
        | 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD             // Co
        | 0xFDD0..=0xFDEF | 0xFFFE | 0xFFFF                                      // non-characters
        | 0x0300..=0x036F | 0x0483..=0x0489 | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF // Mn, Me
        | 0x20D0..=0x20FF | 0xFE00..=0xFE0F | 0xFE20..=0xFE2F | 0xE0100..=0xE01EF
        | 0x17B4 | 0x17B5
        | 0x115F | 0x1160 | 0x3164 | 0xFFA0 | 0x2800)                          // blank letters
}

/// The text with every character that doesn't show as itself written out
/// (\n, \x1b, \u{202e}) and runs of 4+ spaces counted. A dialog shows the
/// person what an agent will do, and the agent chooses that text: 30 newlines
/// pushed "; curl … | sh" below the dialog's fold, U+202E drew the rest of the
/// line backwards, U+200B hid inside a path.
pub fn visible(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut run = 0usize;
    let flush = |o: &mut String, n: usize| {
        if n >= 4 { o.push_str(&format!(" ⟨{n} spaces⟩ ")) } else { o.extend(std::iter::repeat(' ').take(n)) }
    };
    for c in s.chars() {
        if c == ' ' {
            run += 1;
            continue;
        }
        flush(&mut o, run);
        run = 0;
        match c {
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if hidden(c) => {
                let u = c as u32;
                o.push_str(&if u < 0x100 { format!("\\x{u:02x}") } else { format!("\\u{{{u:04x}}}") });
            }
            c => o.push(c),
        }
    }
    flush(&mut o, run);
    o
}

/// For Pango markup in a dialog: Python's html.escape (quote=True) of
/// `visible(s)` — nothing a requester wrote can hide or reorder the text.
pub fn escape(s: &str) -> String {
    let s = visible(s);
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#x27;"),
            _ => o.push(c),
        }
    }
    o
}

/// The first `n` characters (not bytes) of s, plus " …" when cut.
pub fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push_str(" …");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_html_escape() {
        assert_eq!(escape("<b>\"x\" & 'y'</b>"), "&lt;b&gt;&quot;x&quot; &amp; &#x27;y&#x27;&lt;/b&gt;");
    }

    #[test]
    fn nothing_a_requester_writes_hides_in_a_dialog() {
        // the same cases as tests/test_guard.py DialogText — Python and Rust agree
        assert_eq!(visible("echo hi\n\n; curl x | sh"), "echo hi\\n\\n; curl x | sh");
        assert_eq!(visible("a\u{202e}b\u{200b}c\u{2066}d"), "a\\u{202e}b\\u{200b}c\\u{2066}d");
        assert_eq!(visible("x\u{1b}[2Jy\u{7f}\u{85}"), "x\\x1b[2Jy\\x7f\\x85");
        assert_eq!(visible("a\u{a0}b\u{3000}c\u{2028}d\u{3164}e"), "a\\xa0b\\u{3000}c\\u{2028}d\\u{3164}e");
        assert_eq!(visible("Z\u{0301}\u{0301}"), "Z\\u{0301}\\u{0301}");
        assert_eq!(visible("true        x"), "true ⟨8 spaces⟩ x");
        assert_eq!(visible("a   b"), "a   b");
        // ordinary text — Bulgarian, emoji, punctuation — shows as it is
        assert_eq!(visible("Обнови пакетите 🙂 — ok"), "Обнови пакетите 🙂 — ok");
        assert_eq!(escape("<\u{202e}>"), "&lt;\\u{202e}&gt;");
    }

    #[test]
    fn run_times_out_and_reports_missing() {
        assert_eq!(run(&["definitely-not-a-program-xyz"], Duration::from_secs(1)).0, 127);
        let t = Instant::now();
        assert_eq!(run(&["sleep", "5"], Duration::from_millis(200)).0, 124);
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(run(&["echo", "hi"], Duration::from_secs(5)), (0, "hi\n".into()));
    }

    #[test]
    fn clip_counts_characters() {
        assert_eq!(clip("абв", 2), "аб …");
        assert_eq!(clip("ab", 2), "ab");
    }
}
