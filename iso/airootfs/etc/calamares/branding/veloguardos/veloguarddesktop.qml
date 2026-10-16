/* VeloGuardOS — "Desktop" installer page (loaded by notesqml@veloguarddesktop).
 *
 * Stores the choice in Global Storage as `veloguard_desktop`; the exec step
 * shellprocess@veloguardinstalldesktop hands it to calamares-desktop.sh.
 * hw.js is written at live boot by veloguard-hwprobe (a default ships in this
 * directory), so the page can pre-select "Clean Config" on laptops and show
 * what was detected. Colours: theme.js (the default VeloGuard theme).
 *
 * Global Storage from QML: Global.insert(key, value) / Global.value(key) —
 * GlobalStorage exposes contains/count/keys/value/insert/remove/clear.
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
    padding: 24
    property string chosen: Hw.laptop ? "cleanconfig" : "hyprland"

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

    function pick(key) {
        chosen = key
        Global.insert("veloguard_desktop", key)
    }
    Component.onCompleted: pick(chosen)

    ListModel {
        id: desktops
        ListElement { key: "cleanconfig"; name: "Clean Config — Hyprland"
            note: "NodeVortex's rice: Dynamic Island shell, black + dark-blue, installed exactly as published. Built from source during install (needs internet, ~15 min). Recommended on laptops." }
        ListElement { key: "hyprland"; name: "VeloGuard Hyprland"
            note: "The default tiling desktop with the guard bar, VPN and Wi-Fi trust built in. Already on the disc — works offline." }
        ListElement { key: "gnome"; name: "GNOME"
            note: "Full, polished desktop with its own settings, software centre and touchpad gestures." }
        ListElement { key: "xfce"; name: "Xfce"
            note: "Light, traditional panel-and-menu desktop. Great on older hardware." }
        ListElement { key: "niri"; name: "niri"
            note: "Scrollable-tiling Wayland compositor: windows on an endless horizontal strip." }
        ListElement { key: "i3"; name: "i3"
            note: "Classic keyboard-driven tiling window manager (X11)." }
        ListElement { key: "cosmic"; name: "COSMIC"
            note: "System76's Rust desktop: tiling and floating, modern and fast." }
        ListElement { key: "headless"; name: "Headless — no desktop"
            note: "Boots to a text login: no display manager, no desktop. The guard, VPN, Wi-Fi auto-protect, drivers and Ollama still install. For servers, VMs and minimal setups." }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        Label {
            text: "Choose your desktop"
            font.pixelSize: 24; font.bold: true
            color: Theme.fg
        }
        Label {
            Layout.fillWidth: true; wrapMode: Text.WordWrap
            color: Theme.muted
            text: "Detected: " + (Hw.laptop ? "laptop" : Hw.chassis) + "  ·  graphics: " + Hw.gpus
                  + (Hw.wifi ? "  ·  Wi-Fi" : "") + (Hw.bluetooth ? "  ·  Bluetooth" : "")
                  + (Hw.touchpad ? "  ·  touchpad" : "") + (Hw.fingerprint ? "  ·  fingerprint reader" : "")
                  + "\nDrivers for all of it are installed automatically. Everything except "
                  + "VeloGuard Hyprland and Headless is downloaded during installation."
        }

        ScrollView {
            Layout.fillWidth: true; Layout.fillHeight: true
            clip: true
            ListView {
                model: desktops
                spacing: 8
                delegate: Rectangle {
                    readonly property bool sel: page.chosen === model.key
                    width: ListView.view.width
                    height: col.implicitHeight + 20
                    radius: 8
                    color: sel ? Theme.raised : (hover.hovered ? Qt.darker(Theme.raised, 1.25) : Theme.deep)
                    border.width: sel ? 2 : 1
                    border.color: sel ? Theme.accent : Theme.line
                    HoverHandler { id: hover }
                    RowLayout {
                        anchors.fill: parent; anchors.margins: 10; spacing: 10
                        RadioButton {
                            // Display only: the checked state is bound to the
                            // page's choice, so a key press can't break the binding.
                            checkable: false
                            checked: sel
                        }
                        ColumnLayout {
                            id: col
                            Layout.fillWidth: true; spacing: 2
                            Label {
                                text: model.name + ((model.key === "cleanconfig" && Hw.laptop) ? "   (recommended)" : "")
                                font.bold: true; font.pixelSize: 15
                                color: sel ? Theme.accent : Theme.fg
                            }
                            Label {
                                text: model.note; wrapMode: Text.WordWrap; Layout.fillWidth: true
                                color: Theme.muted
                            }
                        }
                    }
                    MouseArea { anchors.fill: parent; onClicked: page.pick(model.key) }
                }
            }
        }
    }
}
