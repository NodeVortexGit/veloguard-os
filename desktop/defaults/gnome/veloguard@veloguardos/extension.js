// VeloGuardOS on GNOME — the VeloGuard top-bar buttons, the GNOME way:
//
//   top bar   the guard (its colour is the guard's state; the menu: VPN
//             providers, trust this network, AI agents, Bulgarian Mode,
//             guard status) and the AI plan usage (a menu of every plan)
//   quick settings  VPN (with its providers), Trusted network, Bulgarian Mode
//   restart dialog  "Update VeloGuardOS on restart" when a kernel is staged
//   D-Bus     io.veloguard.Shell at /io/veloguard/Shell, so VeloGuard's keys
//             (and veloguard-quickpanel / veloguard-session) can open these
//
// GNOME's own top bar already has the rest of the buttons: clock + calendar
// + notifications, Wi-Fi, Bluetooth, volume, brightness, power profile,
// battery, keyboard layout, screenshot, lock and power (the tray comes from
// the AppIndicator extension VeloGuardOS enables alongside this one).
//
// Every action goes through the same helpers the other desktops use
// (veloguard-guard-menu do …, veloguard-agent, veloguard-vpn), which keep
// their polkit rules. State comes from `veloguard-bar panel-state`.
import GObject from 'gi://GObject';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import St from 'gi://St';
import Clutter from 'gi://Clutter';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {QuickToggle, QuickMenuToggle, SystemIndicator} from 'resource:///org/gnome/shell/ui/quickSettings.js';
import * as EndSessionDialog from 'resource:///org/gnome/shell/ui/endSessionDialog.js';
import {CheckBox} from 'resource:///org/gnome/shell/ui/checkBox.js';

const PENDING = '/var/lib/veloguard/staged-kernel/pending.json';
const ARM = ['pkexec', '/usr/local/bin/veloguard-arm-offline-update'];
const PROVIDERS = [['Proton VPN', 'proton'], ['Surfshark', 'surfshark'], ['NordVPN', 'nord']];

const DBUS_IFACE = `
<node>
  <interface name="io.veloguard.Shell">
    <method name="ShowGuardMenu"/>
    <method name="ShowVpnMenu"/>
    <method name="ShowQuickSettings"/>
    <method name="ShowUsage"/>
    <method name="ShowNotifications"/>
    <method name="Screenshot"/>
  </interface>
</node>`;

// Run a command line through bash (so PATH resolves), detached.
function sh(cmd) {
    try {
        GLib.spawn_command_line_async(`/bin/bash -lc ${GLib.shell_quote(cmd)}`);
    } catch (e) {
        logError(e, 'veloguard');
    }
}

// Run argv and hand its stdout to cb (null on failure).
function capture(argv, cb) {
    try {
        const p = Gio.Subprocess.new(argv,
            Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
        p.communicate_utf8_async(null, null, (proc, res) => {
            try {
                const [, out] = proc.communicate_utf8_finish(res);
                cb(out ?? '');
            } catch (_e) {
                cb(null);
            }
        });
    } catch (_e) {
        cb(null);
    }
}

// One shared state, refreshed every few seconds; every widget listens.
const State = GObject.registerClass({
    Signals: {'changed': {}},
}, class State extends GObject.Object {
    _init() {
        super._init();
        this.vpn = false;
        this.trusted = false;
        this.onNetwork = false;
        this.network = '';
        this.guardText = '🛡';
        this.guardClass = 'ok';
        this.usage = '';
        this.usageHigh = false;
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            this.refresh();
            return GLib.SOURCE_CONTINUE;
        });
        this.refresh();
    }

    refresh() {
        capture(['veloguard-bar', 'panel-state'], out => {
            if (!out)
                return;
            try {
                Object.assign(this, JSON.parse(out));
                this.emit('changed');
            } catch (_e) {}
        });
    }

    soon() {
        GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 3, () => {
            this.refresh();
            return GLib.SOURCE_REMOVE;
        });
    }

    destroy() {
        if (this._timer)
            GLib.source_remove(this._timer);
        this._timer = 0;
    }
});

// ── the guard: top-bar button + menu ────────────────────────────────────
const GuardButton = GObject.registerClass(
class GuardButton extends PanelMenu.Button {
    _init(state) {
        super._init(0.0, 'VeloGuard');
        this._state = state;
        this._icon = new St.Icon({icon_name: 'security-high-symbolic', style_class: 'system-status-icon'});
        this._label = new St.Label({text: '', y_align: Clutter.ActorAlign.CENTER, style_class: 'veloguard-guard-label'});
        const box = new St.BoxLayout({style_class: 'panel-status-menu-box'});
        box.add_child(this._icon);
        box.add_child(this._label);
        this.add_child(box);

        this._status = new PopupMenu.PopupMenuItem('', {reactive: false});
        this.menu.addMenuItem(this._status);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._vpn = new PopupMenu.PopupSubMenuMenuItem('VPN', true);
        this._vpn.icon.icon_name = 'network-vpn-symbolic';
        for (const [label, name] of PROVIDERS)
            this._vpn.menu.addAction(`Connect: ${label}`, () => this._do(`vpn-connect ${name}`));
        this._vpn.menu.addAction('Disconnect VPN', () => this._do('vpn-off'));
        this._vpn.menu.addAction('Import a WireGuard config…', () => this._do('vpn-import'));
        this._vpn.menu.addAction('Tor fallback', () => this._do('tor'));
        this.menu.addMenuItem(this._vpn);

        this._trust = this.menu.addAction('Trust this network', () => this._do('trust-toggle'));
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addAction('AI agent…', () => sh('veloguard-agent'));
        this.menu.addAction('Switch AI agent…', () => sh('veloguard-agent pick'));
        this.menu.addAction('Ask an AI agent about an error…', () => sh('veloguard-agent ask'));
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addAction('Toggle Bulgarian Mode', () => this._do('bgmode'));
        this.menu.addAction('Guard status', () => this._do('status'));

        this.menu.connect('open-state-changed', (_m, open) => {
            if (open)
                this._state.refresh();
        });
        this._sig = state.connect('changed', () => this._sync());
        this._sync();
    }

    _do(action) {
        sh(`veloguard-guard-menu do ${action}`);
        this._state.soon();
    }

    _sync() {
        const s = this._state;
        const cls = s.guardClass;
        // the guard's colour: green VPN up, amber untrusted / update, red alert / root grant
        const colour = {'vpn-up': '#7ee0a8', 'untrusted': '#f2c66d', 'update': '#f2c66d',
            'alert': '#f26d7d', 'grant': '#f26d7d'}[cls] ?? null;
        this._icon.style = colour ? `color: ${colour};` : '';
        this._icon.icon_name = cls === 'untrusted' || cls === 'alert' || cls === 'grant'
            ? 'security-low-symbolic' : 'security-high-symbolic';
        this._label.text = cls === 'grant' ? ' root' : cls === 'update' ? ' ⬆' : '';
        const net = !s.onNetwork ? 'not connected'
            : `${s.network} (${s.trusted ? 'trusted' : 'untrusted'})`;
        this._status.label.text = `VPN: ${s.vpn ? 'on' : 'off'}  ·  Network: ${net}`;
        this._trust.label.text = !s.onNetwork ? 'Trust this network (not connected)'
            : s.trusted ? 'Untrust this network' : 'Trust this network';
    }

    openVpn() {
        this.menu.open();
        this._vpn.setSubmenuShown(true);
    }

    destroy() {
        if (this._sig)
            this._state.disconnect(this._sig);
        this._sig = 0;
        super.destroy();
    }
});

// ── AI plan usage: top-bar button + one menu row per plan window ─────────
const UsageButton = GObject.registerClass(
class UsageButton extends PanelMenu.Button {
    _init(state) {
        super._init(0.0, 'VeloGuard AI usage');
        this._state = state;
        this._label = new St.Label({text: 'AI', y_align: Clutter.ActorAlign.CENTER});
        this.add_child(this._label);
        this.menu.connect('open-state-changed', (_m, open) => {
            if (open)
                this._fill();
        });
        this._sig = state.connect('changed', () => this._sync());
        this._sync();
    }

    _sync() {
        this._label.text = this._state.usage ? `AI ${this._state.usage}` : 'AI';
        this._label.style = this._state.usageHigh ? 'color: #f2c66d;' : '';
    }

    _fill() {
        this.menu.removeAll();
        const loading = new PopupMenu.PopupMenuItem('Reading your plans…', {reactive: false});
        this.menu.addMenuItem(loading);
        capture(['veloguard-ai-usage', '--plans'], out => {
            this.menu.removeAll();
            let plans = [];
            try {
                plans = JSON.parse(out ?? '[]');
            } catch (_e) {}
            if (!plans.length)
                this.menu.addMenuItem(new PopupMenu.PopupMenuItem('No AI plan usage yet', {reactive: false}));
            for (const p of plans) {
                const head = new PopupMenu.PopupMenuItem(`${p.label}${p.current ? '  ·  in use' : ''}`, {reactive: false});
                head.label.style = 'font-weight: bold;';
                this.menu.addMenuItem(head);
                if (!p.windows?.length && p.note)
                    this.menu.addMenuItem(new PopupMenu.PopupMenuItem(p.note, {reactive: false}));
                for (const w of p.windows ?? []) {
                    const pct = w.percent === null ? null : Math.min(100, Math.round(w.percent));
                    const filled = pct === null ? 0 : Math.round(pct / 10);
                    const bar = '▰'.repeat(filled) + '▱'.repeat(10 - filled);
                    const line = `${w.name}   ${bar}  ${pct === null ? '?' : `${pct}%`}${w.resets_text ? `   ${w.resets_text}` : ''}`;
                    const row = new PopupMenu.PopupMenuItem(line, {reactive: false});
                    if (pct !== null && pct >= 90)
                        row.label.style = 'color: #f26d7d;';
                    this.menu.addMenuItem(row);
                }
            }
            this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
            this.menu.addAction('Open your AI agent', () => sh('veloguard-agent'));
        });
    }

    destroy() {
        if (this._sig)
            this._state.disconnect(this._sig);
        this._sig = 0;
        super.destroy();
    }
});

// ── quick settings: VPN, Trusted network, Bulgarian Mode ─────────────────
const VpnToggle = GObject.registerClass(
class VpnToggle extends QuickMenuToggle {
    _init(state) {
        super._init({title: 'VPN', iconName: 'network-vpn-symbolic', toggleMode: false});
        this._state = state;
        this.menu.setHeader('network-vpn-symbolic', 'VeloGuard VPN');
        for (const [label, name] of PROVIDERS)
            this.menu.addAction(`Connect: ${label}`, () => this._do(`vpn-connect ${name}`));
        this.menu.addAction('Disconnect VPN', () => this._do('vpn-off'));
        this.menu.addAction('Import a WireGuard config…', () => this._do('vpn-import'));
        this.menu.addAction('Tor fallback', () => this._do('tor'));
        this.connect('clicked', () => {
            if (this._state.vpn)
                sh('pkexec veloguard-vpn disconnect');
            else
                sh('pkexec veloguard-vpn connect');
            this._state.soon();
        });
        this._sig = state.connect('changed', () => this._sync());
        this._sync();
    }

    _do(action) {
        sh(`veloguard-guard-menu do ${action}`);
        this._state.soon();
    }

    _sync() {
        this.checked = this._state.vpn;
        this.subtitle = this._state.vpn ? 'On' : null;
    }

    destroy() {
        if (this._sig)
            this._state.disconnect(this._sig);
        this._sig = 0;
        super.destroy();
    }
});

const TrustToggle = GObject.registerClass(
class TrustToggle extends QuickToggle {
    _init(state) {
        super._init({title: 'Trusted', iconName: 'security-medium-symbolic', toggleMode: false});
        this._state = state;
        this.connect('clicked', () => {
            if (!this._state.onNetwork)
                return;
            sh('veloguard-guard-menu do trust-toggle');
            this._state.soon();
        });
        this._sig = state.connect('changed', () => this._sync());
        this._sync();
    }

    _sync() {
        const s = this._state;
        this.checked = s.onNetwork && s.trusted;
        this.subtitle = s.onNetwork ? s.network : 'Not connected';
        this.title = !s.onNetwork ? 'Network' : s.trusted ? 'Trusted' : 'Untrusted';
    }

    destroy() {
        if (this._sig)
            this._state.disconnect(this._sig);
        this._sig = 0;
        super.destroy();
    }
});

const BgToggle = GObject.registerClass(
class BgToggle extends QuickToggle {
    _init() {
        super._init({title: 'Bulgarian Mode', iconName: 'folder-music-symbolic', toggleMode: true});
        this._pidfile = `${GLib.get_user_runtime_dir()}/veloguard-bgmode/wall.pid`;
        this.connect('clicked', () => {
            sh('veloguard-guard-menu do bgmode');
            GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 2, () => {
                this._sync();
                return GLib.SOURCE_REMOVE;
            });
        });
        this._timer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            this._sync();
            return GLib.SOURCE_CONTINUE;
        });
        this._sync();
    }

    _sync() {
        this.checked = GLib.file_test(this._pidfile, GLib.FileTest.EXISTS);
    }

    destroy() {
        if (this._timer)
            GLib.source_remove(this._timer);
        this._timer = 0;
        super.destroy();
    }
});

const Indicator = GObject.registerClass(
class Indicator extends SystemIndicator {
    _init(state) {
        super._init();
        this.quickSettingsItems.push(new VpnToggle(state), new TrustToggle(state), new BgToggle());
    }

    destroy() {
        this.quickSettingsItems.forEach(i => i.destroy());
        super.destroy();
    }
});

// ── "Update VeloGuardOS on restart" in the restart dialog ────────────────
// Wrapped so a GNOME change can never block a restart: worst case the
// checkbox just doesn't appear.
function pendingVersion() {
    try {
        const [ok, bytes] = GLib.file_get_contents(PENDING);
        if (!ok)
            return null;
        return JSON.parse(new TextDecoder().decode(bytes)).version || 'pending';
    } catch (_e) {
        return null;
    }
}

let _origOpen = null, _origConfirm = null;

function ensureCheckbox(dlg) {
    const v = pendingVersion();
    const showable = dlg._type === 1 || dlg._type === 2;   // shutdown / restart
    if (!dlg._veloCheck) {
        if (!v || !showable)
            return;
        dlg._veloCheck = new CheckBox('Update VeloGuardOS on restart');
        const box = dlg._messageDialogContent ?? dlg.contentLayout ?? null;
        if (box && box.add_child)
            box.add_child(dlg._veloCheck);
    }
    if (dlg._veloCheck) {
        dlg._veloCheck.visible = !!v && showable;
        const label = dlg._veloCheck.getLabelActor && dlg._veloCheck.getLabelActor();
        if (v && label)
            label.text = `Update VeloGuardOS (kernel ${v}) on restart`;
    }
}

function patchEndSession() {
    const proto = EndSessionDialog.EndSessionDialog?.prototype;
    if (!proto)
        return;
    _origOpen = proto.open;
    proto.open = function (...args) {
        try {
            ensureCheckbox(this);
        } catch (e) {
            logError(e, 'veloguard');
        }
        return _origOpen.apply(this, args);
    };
    if (typeof proto._confirm === 'function') {
        _origConfirm = proto._confirm;
        proto._confirm = function (signal) {
            try {
                if (this._veloCheck?.visible && this._veloCheck.checked)
                    GLib.spawn_sync(null, ARM, null, GLib.SpawnFlags.SEARCH_PATH, null);
            } catch (e) {
                logError(e, 'veloguard');
            }
            return _origConfirm.call(this, signal);
        };
    }
}

function unpatchEndSession() {
    const proto = EndSessionDialog.EndSessionDialog?.prototype;
    if (!proto)
        return;
    if (_origOpen)
        proto.open = _origOpen;
    if (_origConfirm)
        proto._confirm = _origConfirm;
    _origOpen = _origConfirm = null;
}

export default class VeloGuardExtension extends Extension {
    enable() {
        this._state = new State();
        this._guard = new GuardButton(this._state);
        this._usage = new UsageButton(this._state);
        // left of the clock: the guard right after Activities, AI usage at the
        // start of the status area (like the bar on the other desktops)
        Main.panel.addToStatusArea('veloguard-guard', this._guard, 1, 'left');
        Main.panel.addToStatusArea('veloguard-usage', this._usage, 0, 'right');
        this._indicator = new Indicator(this._state);
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
        try {
            patchEndSession();
        } catch (e) {
            logError(e, 'veloguard endSession');
        }
        this._dbus = Gio.DBusExportedObject.wrapJSObject(DBUS_IFACE, this);
        this._dbus.export(Gio.DBus.session, '/io/veloguard/Shell');
    }

    disable() {
        this._dbus?.unexport();
        this._dbus = null;
        try {
            unpatchEndSession();
        } catch (e) {
            logError(e, 'veloguard');
        }
        this._indicator?.destroy();
        this._indicator = null;
        this._guard?.destroy();
        this._guard = null;
        this._usage?.destroy();
        this._usage = null;
        this._state?.destroy();
        this._state = null;
    }

    // D-Bus methods (VeloGuard's keys on GNOME call these)
    ShowGuardMenu() {
        this._guard?.menu.toggle();
    }

    ShowVpnMenu() {
        this._guard?.openVpn();
    }

    ShowQuickSettings() {
        Main.panel.statusArea.quickSettings.menu.toggle();
    }

    ShowUsage() {
        this._usage?.menu.toggle();
    }

    ShowNotifications() {
        Main.panel.statusArea.dateMenu.menu.toggle();
    }

    Screenshot() {
        Main.screenshotUI?.open();
    }
}
