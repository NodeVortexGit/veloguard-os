/* VeloGuardOS — "Desktop" installer page (loaded by notesqml@veloguarddesktop).
 *
 * Global Storage it writes (read by the exec steps / the navigation bar):
 *   veloguard_desktop     the choice → shellprocess@veloguardinstalldesktop
 *   veloguard_ssh_link    "user@host[:port]" for a headless SSH link, or ""
 *   veloguard_block_next  true while the SSH-link box is ticked but the address
 *                         isn't valid; calamares-navigation.qml then disables
 *                         Next (notesqml pages can't block Next themselves)
 * hw.js is written at live boot by veloguard-hwprobe (a default ships here), so
 * the page can pre-select Clean Config on laptops and show what was detected.
 * Colours: theme.js (the default VeloGuard theme). Previews: DesktopPreview.qml.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0
import "hw.js" as Hw
import "theme.js" as Theme

// A Pane (a Control) so its palette reaches every Label/RadioButton below —
// QML pages don't see the widget stylesheet.
Pane {
    id: page
    padding: 20
    property string chosen: Hw.laptop ? "cleanconfig" : "hyprland"
    property var info: desktops.get(indexOf(chosen))

    background: Rectangle { color: Theme.bg }
    palette.window: Theme.bg
    palette.windowText: Theme.fg
    palette.text: Theme.fg
    palette.base: Theme.deep
    palette.button: Theme.deep
    palette.buttonText: Theme.fg
    palette.highlight: Theme.accent
    palette.highlightedText: Theme.deep
    palette.mid: Theme.line
    palette.dark: Theme.line
    palette.placeholderText: Theme.muted

    function indexOf(key) {
        for (var i = 0; i < desktops.count; ++i) if (desktops.get(i).key === key) return i
        return 0
    }
    function pick(key) {
        chosen = key
        Global.insert("veloguard_desktop", key)
        updateSsh()
    }

    // ── headless SSH link: user@host, optional :port ──────────────────────
    function sshValid(t) {
        var m = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}@([A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*)(:([0-9]{1,5}))?$/.exec(t)
        if (!m) return false
        return m[6] === undefined || (parseInt(m[6]) >= 1 && parseInt(m[6]) <= 65535)
    }
    readonly property bool sshOk: sshValid(sshField.text.trim())       // for the UI only
    // Computed fresh, never from the bindings above: this runs from the
    // field's own change handlers, which can fire before a binding updates.
    function updateSsh() {
        var t = sshField.text.trim()
        var on = chosen === "headless" && sshBox.checked
        var ok = sshValid(t)
        Global.insert("veloguard_ssh_link", on && ok ? t : "")
        Global.insert("veloguard_block_next", on && !ok)
    }
    // Called by Calamares when this page is shown / left (QmlViewStep).
    function onActivate() { updateSsh() }
    function onLeave() { Global.insert("veloguard_block_next", false) }

    Component.onCompleted: pick(chosen)

    ListModel {
        id: desktops
        ListElement { key: "cleanconfig"; name: "Clean Config — Hyprland"; tag: "NodeVortex's rice · Dynamic Island"
            note: "NodeVortex's rice: the Dynamic Island shell, black + dark-blue glass, installed exactly as published — every keybind included. Built from source during install (needs internet, ~15 min). Recommended on laptops." }
        ListElement { key: "hyprland"; name: "VeloGuard Hyprland"; tag: "tiling · guard bar · works offline"
            note: "The default tiling desktop: Waybar with the guard shield, VPN and Wi-Fi trust built in, navy + cyan theme. Already on the disc — works offline." }
        ListElement { key: "gnome"; name: "GNOME"; tag: "polished · overview · gestures"
            note: "Full, polished desktop: Activities overview, its own settings and software centre, touchpad gestures." }
        ListElement { key: "xfce"; name: "Xfce"; tag: "classic panel + menu · light"
            note: "Light, traditional desktop: a panel with menu, task list and clock; desktop icons. Great on older hardware." }
        ListElement { key: "niri"; name: "niri"; tag: "scrollable tiling"
            note: "Scrollable-tiling Wayland compositor: windows sit in columns on an endless horizontal strip you scroll through." }
        ListElement { key: "i3"; name: "i3"; tag: "keyboard tiling · X11"
            note: "Classic keyboard-driven tiling window manager (X11): every window tiled, i3bar at the bottom." }
        ListElement { key: "cosmic"; name: "COSMIC"; tag: "System76 · panel + dock"
            note: "System76's Rust desktop: top panel, dock, tiling or floating windows — modern and fast." }
        ListElement { key: "headless"; name: "Headless — no desktop"; tag: "text login · servers & VMs"
            note: "Boots to a text login: no display manager, no desktop. The guard, VPN, Wi-Fi auto-protect, drivers and Ollama still install." }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label { text: "Choose your desktop"; font.pixelSize: 22; font.bold: true; color: Theme.fg }
        Label {
            Layout.fillWidth: true; wrapMode: Text.WordWrap; color: Theme.muted
            text: "Detected: " + (Hw.laptop ? "laptop" : Hw.chassis) + "  ·  graphics: " + Hw.gpus
                  + (Hw.wifi ? "  ·  Wi-Fi" : "") + (Hw.bluetooth ? "  ·  Bluetooth" : "")
                  + (Hw.touchpad ? "  ·  touchpad" : "") + (Hw.fingerprint ? "  ·  fingerprint reader" : "")
                  + " — drivers for all of it are installed automatically."
        }

        RowLayout {
            Layout.fillWidth: true; Layout.fillHeight: true
            spacing: 14

            // ── the choices ────────────────────────────────────────────────
            ScrollView {
                Layout.preferredWidth: 250; Layout.fillHeight: true
                clip: true
                ListView {
                    model: desktops
                    spacing: 6
                    delegate: Rectangle {
                        readonly property bool sel: page.chosen === model.key
                        width: ListView.view.width
                        height: 46
                        radius: 7
                        color: sel ? Theme.raised : (hover.hovered ? Qt.darker(Theme.raised, 1.25) : Theme.deep)
                        border.width: sel ? 2 : 1
                        border.color: sel ? Theme.accent : Theme.line
                        HoverHandler { id: hover }
                        RowLayout {
                            anchors.fill: parent; anchors.leftMargin: 6; anchors.rightMargin: 8; spacing: 4
                            RadioButton { checkable: false; checked: sel }   // display only
                            ColumnLayout {
                                Layout.fillWidth: true; spacing: 0
                                Label {
                                    Layout.fillWidth: true; elide: Text.ElideRight
                                    text: model.name + ((model.key === "cleanconfig" && Hw.laptop) ? "  ★" : "")
                                    font.bold: true; font.pixelSize: 13
                                    color: sel ? Theme.accent : Theme.fg
                                }
                                Label { Layout.fillWidth: true; elide: Text.ElideRight; text: model.tag; color: Theme.muted; font.pixelSize: 11 }
                            }
                        }
                        MouseArea { anchors.fill: parent; onClicked: page.pick(model.key) }
                    }
                }
            }

            // ── the preview + details for the selected one ─────────────────
            ColumnLayout {
                Layout.fillWidth: true; Layout.fillHeight: true
                spacing: 8

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: width * 10 / 16          // 16:10, like most laptop panels
                    radius: 8; color: Theme.deep
                    border.width: 1; border.color: Theme.line
                    DesktopPreview {
                        anchors.fill: parent; anchors.margins: 5
                        kind: page.chosen
                    }
                }
                Label {
                    text: page.info.name + ((page.chosen === "cleanconfig" && Hw.laptop) ? "   (recommended for this laptop)" : "")
                    font.bold: true; font.pixelSize: 15; color: Theme.accent
                }
                Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: page.info.note; color: Theme.fg }
                Label {
                    Layout.fillWidth: true; wrapMode: Text.WordWrap; color: Theme.muted; font.pixelSize: 11
                    visible: page.chosen !== "hyprland" && page.chosen !== "headless"
                    text: "Downloaded during installation. Offline? You get VeloGuard Hyprland now and this desktop on the first boot with internet."
                }

                // ── headless only: link this machine to a computer over SSH ──
                ColumnLayout {
                    visible: page.chosen === "headless"
                    Layout.fillWidth: true; spacing: 4
                    CheckBox {
                        id: sshBox
                        text: "Link this machine to a computer over SSH"
                        onToggled: page.updateSsh()
                        indicator: Rectangle {
                            x: sshBox.leftPadding; y: (sshBox.height - height) / 2
                            implicitWidth: 18; implicitHeight: 18; radius: 4
                            color: sshBox.checked ? Theme.accent : Theme.deep
                            border.width: 1; border.color: sshBox.checked || sshBox.hovered ? Theme.accent : Theme.muted
                            Text { anchors.centerIn: parent; text: "✓"; visible: sshBox.checked; color: Theme.deep; font.bold: true; font.pixelSize: 13 }
                        }
                    }
                    TextField {
                        id: sshField
                        visible: sshBox.checked
                        Layout.fillWidth: true
                        placeholderText: "you@192.168.1.20   (or you@host.local:2222)"
                        inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                        color: Theme.fg
                        background: Rectangle {
                            radius: 4; color: Theme.deep
                            border.width: 1
                            border.color: sshField.text.length === 0 ? Theme.line : (page.sshOk ? Theme.green : "#ff6e6e")
                        }
                        onTextChanged: page.updateSsh()
                        Component.onCompleted: page.updateSsh()
                    }
                    Label {
                        visible: sshBox.checked
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 11
                        color: page.sshOk ? Theme.muted : "#ff6e6e"
                        text: page.sshOk
                              ? "From its first boot this machine keeps searching for " + sshField.text.trim()
                                + " and, once it answers, holds an SSH link to it — reach this machine from there "
                                + "whatever address it gets. The first time, log in here and run "
                                + "“sudo veloguard-ssh-link authorize” so that computer trusts this one."
                              : "Type user@address (for example you@192.168.1.20) — or untick the box — to continue."
                    }
                }
                Item { Layout.fillHeight: true }
            }
        }
    }
}
