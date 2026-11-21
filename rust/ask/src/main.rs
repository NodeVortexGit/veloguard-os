//! veloguard-ask — VeloGuardOS's Approve / Deny dialog.
//!
//! A drop-in for the `zenity --question` the guard used, with the keys the
//! person asked for:
//!   Esc          → Deny            (closing the window is a Deny too)
//!   Ctrl+Enter   → Approve         (also Ctrl+keypad Enter)
//!   Enter        → Deny            (Deny is the focused, default button)
//!   no answer    → Deny, exit 5    (after --timeout seconds, counted down on screen)
//! Approve — the button and Ctrl+Enter — arms only after 1 s: a dialog that
//! pops up while you type (Ctrl+Enter sends a message in many chat apps) can't
//! be approved by the keystroke you were already making.
//! And only once the whole question has been on screen: the requester writes
//! most of the text, and a long command or folder pushed the guard's warning
//! below the fold of the scroll area (560 px) with no sign it was there. Text
//! that doesn't fit gets a real scrollbar and a "scroll to read the rest"
//! line, and Approve stays off until it has been scrolled to the end
//! (wheel, or PageDown / ↓ / End).
//!
//! Same flags and exit codes as zenity, so callers swap the program name:
//!   veloguard-ask --question --title T --text MARKUP --ok-label Approve
//!                 --cancel-label Deny --default-cancel --icon dialog-warning
//!                 --width 600 --timeout 120
//! Exit: 0 Approve · 1 Deny · 5 timed out · 2 bad usage / no display.
//!
//! Run by the root helper as root with a clean environment and a verified
//! WAYLAND_SOCKET (GTK connects through it, no path lookup), and by the user-
//! side pop-ups. No GtkApplication: nothing on D-Bus, nothing to activate.

use gtk4 as gtk;
use gtk::prelude::*;
use gtk::{gdk, glib, pango};
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

const ARM_AFTER: Duration = Duration::from_millis(1000);

/// Whether the scroll area shows its last line now. Before GTK has laid the
/// label out, the adjustment is all zeros — that is "not yet", never "yes".
fn at_end(value: f64, page: f64, upper: f64) -> bool {
    page > 0.0 && upper > 0.0 && value + page >= upper - 1.0
}

/// Approve may answer: armed (1 s passed) and the whole text has been on
/// screen — now, or once, by scrolling to the end.
fn may_approve(armed: bool, reached_end: bool, value: f64, page: f64, upper: f64) -> bool {
    armed && (reached_end || at_end(value, page, upper))
}

struct Opts {
    title: String,
    text: String,
    ok: String,
    cancel: String,
    icon: String,
    width: i32,
    timeout: u32,
}

fn parse() -> Result<Opts, String> {
    let mut o = Opts { title: "VeloGuard".into(), text: String::new(), ok: "Approve".into(), cancel: "Deny".into(),
                       icon: "dialog-warning".into(), width: 560, timeout: 120 };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let (k, inline) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut val = || inline.clone().or_else(|| it.next()).ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--question" | "--default-cancel" | "--no-wrap" => {}
            "--title" => o.title = val()?,
            "--text" => o.text = val()?,
            "--ok-label" => o.ok = val()?,
            "--cancel-label" => o.cancel = val()?,
            "--icon" | "--icon-name" => o.icon = val()?,
            "--width" => o.width = val()?.parse().map_err(|_| "--width takes a number")?,
            "--timeout" => o.timeout = val()?.parse().map_err(|_| "--timeout takes seconds")?,
            _ => return Err(format!("unknown option {a}")),
        }
    }
    o.timeout = o.timeout.clamp(1, 3600);
    o.width = o.width.clamp(300, 1200);
    Ok(o)
}

fn main() {
    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("veloguard-ask: {e}");
            std::process::exit(2);
        }
    };
    if gtk::init().is_err() {
        eprintln!("veloguard-ask: no display to ask on");
        std::process::exit(2);
    }
    let answer = Rc::new(Cell::new(1)); // a closed window is a Deny
    let armed = Rc::new(Cell::new(false));
    let main_loop = glib::MainLoop::new(None, false);

    let win = gtk::Window::builder().title(o.title.as_str()).default_width(o.width).resizable(false).build();
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 14);
    for m in [&outer] {
        m.set_margin_top(18);
        m.set_margin_bottom(14);
        m.set_margin_start(18);
        m.set_margin_end(18);
    }
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    let icon = gtk::Image::from_icon_name(&o.icon);
    icon.set_pixel_size(48);
    icon.set_valign(gtk::Align::Start);
    row.append(&icon);

    let label = gtk::Label::new(None);
    // Shown as markup only if it parses: bad markup must not blank the question.
    if pango::parse_markup(&o.text, '\0').is_ok() {
        label.set_markup(&o.text);
    } else {
        label.set_text(&o.text);
    }
    label.set_wrap(true);
    label.set_wrap_mode(pango::WrapMode::WordChar);
    label.set_xalign(0.0);
    label.set_yalign(0.0);
    label.set_max_width_chars(80);
    label.set_selectable(false);
    let scroll = gtk::ScrolledWindow::builder().child(&label).hscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true).max_content_height(560).hexpand(true)
        .overlay_scrolling(false).build();             // a visible scrollbar, not one that appears on hover
    row.append(&scroll);
    outer.append(&row);

    let more = gtk::Label::new(None);
    more.set_xalign(0.0);
    more.set_markup("<span foreground='#e01b24'><b>↓ There's more below — scroll to read the rest \
                     before you can approve.</b></span>");
    more.set_visible(false);
    outer.append(&more);

    let hint = gtk::Label::new(None);
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");
    let set_hint = {
        let hint = hint.clone();
        move |left: u32| hint.set_markup(&format!(
            "<small><b>Esc</b> = Deny  ·  <b>Ctrl+Enter</b> = Approve  ·  no answer in {left} s = Deny</small>"))
    };
    set_hint(o.timeout);
    outer.append(&hint);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    buttons.set_halign(gtk::Align::End);
    let deny = gtk::Button::with_label(&o.cancel);
    let approve = gtk::Button::with_label(&o.ok);
    approve.add_css_class("destructive-action");
    approve.set_sensitive(false);
    buttons.append(&deny);
    buttons.append(&approve);
    outer.append(&buttons);
    win.set_child(Some(&outer));
    win.set_default_widget(Some(&deny));

    let finish = {
        let (answer, win) = (answer.clone(), win.clone());
        Rc::new(move |code: i32| {
            answer.set(code);
            win.close();
        })
    };
    // Approve answers only once the whole question has been on screen.
    let adj = scroll.vadjustment();
    let reached_end = Rc::new(Cell::new(false));
    let ok = {
        let (armed, reached_end, adj) = (armed.clone(), reached_end.clone(), adj.clone());
        Rc::new(move || may_approve(armed.get(), reached_end.get(), adj.value(), adj.page_size(), adj.upper()))
    };
    let refresh = {
        let (ok, approve, more, reached_end, adj) =
            (ok.clone(), approve.clone(), more.clone(), reached_end.clone(), adj.clone());
        Rc::new(move || {
            approve.set_sensitive(ok());
            let seen = reached_end.get() || at_end(adj.value(), adj.page_size(), adj.upper());
            more.set_visible(!seen && adj.page_size() > 0.0);
        })
    };
    {
        // Latched only by scrolling to the end; layout changes (wrapping,
        // a resize) re-check without latching, so a first, too-small layout
        // can't count as "seen".
        let (reached_end, r) = (reached_end.clone(), refresh.clone());
        adj.connect_value_changed(move |a| {
            if a.upper() > a.page_size() && at_end(a.value(), a.page_size(), a.upper()) {
                reached_end.set(true);
            }
            r();
        });
        let r = refresh.clone();
        adj.connect_changed(move |_| r());
    }
    {
        let f = finish.clone();
        deny.connect_clicked(move |_| f(1));
    }
    {
        let (f, ok) = (finish.clone(), ok.clone());
        approve.connect_clicked(move |_| if ok() { f(0) });
    }
    let keys = gtk::EventControllerKey::new();
    keys.set_propagation_phase(gtk::PropagationPhase::Capture);
    {
        let (f, ok, adj) = (finish.clone(), ok.clone(), adj.clone());
        keys.connect_key_pressed(move |_, key, _, state| {
            if key == gdk::Key::Escape {
                f(1);
                return glib::Propagation::Stop;
            }
            let enter = matches!(key, gdk::Key::Return | gdk::Key::KP_Enter | gdk::Key::ISO_Enter);
            if enter && state.contains(gdk::ModifierType::CONTROL_MASK) {
                if ok() {
                    f(0);
                }
                return glib::Propagation::Stop; // early Ctrl+Enter does nothing — never a Deny by surprise either
            }
            // Read with the keyboard: focus stays on Deny, the keys scroll the text.
            let (v, page, top) = (adj.value(), adj.page_size(), adj.upper() - adj.page_size());
            let to = match key {
                gdk::Key::Page_Down | gdk::Key::KP_Page_Down => Some(v + page * 0.9),
                gdk::Key::Page_Up | gdk::Key::KP_Page_Up => Some(v - page * 0.9),
                gdk::Key::Down | gdk::Key::KP_Down => Some(v + 40.0),
                gdk::Key::Up | gdk::Key::KP_Up => Some(v - 40.0),
                gdk::Key::End | gdk::Key::KP_End => Some(top),
                gdk::Key::Home | gdk::Key::KP_Home => Some(0.0),
                _ => None,
            };
            if let Some(to) = to {
                adj.set_value(to.clamp(0.0, top.max(0.0)));
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
    }
    win.add_controller(keys);
    {
        let ml = main_loop.clone();
        win.connect_close_request(move |_| {
            ml.quit();
            glib::Propagation::Proceed
        });
    }
    {
        let (armed, r) = (armed.clone(), refresh.clone());
        glib::timeout_add_local_once(ARM_AFTER, move || {
            armed.set(true);
            r();
        });
    }
    {
        let left = Cell::new(o.timeout);
        let f = finish.clone();
        glib::timeout_add_seconds_local(1, move || {
            let l = left.get().saturating_sub(1);
            left.set(l);
            if l == 0 {
                f(5);
                return glib::ControlFlow::Break;
            }
            set_hint(l);
            glib::ControlFlow::Continue
        });
    }
    win.present();
    deny.grab_focus();
    main_loop.run();
    std::process::exit(answer.get());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_waits_for_the_whole_text() {
        // not laid out yet (all zeros): never counts as seen
        assert!(!may_approve(true, false, 0.0, 0.0, 0.0));
        // fits on screen: approve once armed, not before
        assert!(may_approve(true, false, 0.0, 300.0, 300.0));
        assert!(!may_approve(false, false, 0.0, 300.0, 300.0));
        // taller than the 560-px area: not until it was scrolled to the end
        assert!(!may_approve(true, false, 0.0, 560.0, 1260.0));
        assert!(!may_approve(true, false, 600.0, 560.0, 1260.0));
        assert!(may_approve(true, false, 700.0, 560.0, 1260.0));
        // scrolled to the end once, then back up: still approvable
        assert!(may_approve(true, true, 0.0, 560.0, 1260.0));
        // but never before the 1 s arming, scrolled or not
        assert!(!may_approve(false, true, 700.0, 560.0, 1260.0));
    }
}
