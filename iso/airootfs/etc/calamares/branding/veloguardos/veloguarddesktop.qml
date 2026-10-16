/* VeloGuardOS — "Desktop" installer page (loaded by notesqml@veloguarddesktop).
 *
 * Stores the choice in Global Storage as `veloguard_desktop`; the exec step
 * shellprocess@veloguardinstalldesktop hands it to calamares-desktop.sh.
 * hw.js is written at live boot by veloguard-hwprobe (a default ships in this
 * directory), so the page can pre-select "Clean Config" on laptops and show
 * what was detected.
 *
 * Global Storage from QML: Global.insert(key, value) / Global.value(key) —
 * GlobalStorage exposes contains/count/keys/value/insert/remove/clear.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0
import "hw.js" as Hw

Item {
    id: page
    readonly property color accent: "#17a2b8"
    property string chosen: Hw.laptop ? "cleanconfig" : "hyprland"

    function pick(key) {
        chosen = key
        Global.insert("veloguard_desktop", key)
    }
    Component.onCompleted: pick(chosen)

    ListModel {
        id: desktops
        ListElement { key: "cleanconfig"; name: "Clean Config — Hyprland"
            note: "IVELINYTBG1's rice: Dynamic Island shell, black + dark-blue. Built from source during install (needs internet, ~15 min). Recommended on laptops." }
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
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12

        Label {
            text: "Choose your desktop"
            font.pixelSize: 24; font.bold: true
        }
        Label {
            Layout.fillWidth: true; wrapMode: Text.WordWrap
            text: "Detected: " + (Hw.laptop ? "laptop" : Hw.chassis) + "  ·  graphics: " + Hw.gpus
                  + (Hw.wifi ? "  ·  Wi-Fi" : "") + (Hw.bluetooth ? "  ·  Bluetooth" : "")
                  + (Hw.touchpad ? "  ·  touchpad" : "") + (Hw.fingerprint ? "  ·  fingerprint reader" : "")
                  + "\nDrivers for all of it are installed automatically. Everything except "
                  + "VeloGuard Hyprland is downloaded during installation."
            opacity: 0.8
        }

        ScrollView {
            Layout.fillWidth: true; Layout.fillHeight: true
            clip: true
            ListView {
                model: desktops
                spacing: 8
                delegate: Rectangle {
                    width: ListView.view.width
                    height: col.implicitHeight + 20
                    radius: 8
                    color: page.chosen === model.key ? Qt.rgba(0.09, 0.64, 0.72, 0.18) : "transparent"
                    border.width: page.chosen === model.key ? 2 : 1
                    border.color: page.chosen === model.key ? page.accent : Qt.rgba(0.5, 0.5, 0.5, 0.4)
                    RowLayout {
                        anchors.fill: parent; anchors.margins: 10; spacing: 10
                        RadioButton {
                            // Display only: the checked state is bound to the
                            // page's choice, so a key press can't break the binding.
                            checkable: false
                            checked: page.chosen === model.key
                            onClicked: page.pick(model.key)
                        }
                        ColumnLayout {
                            id: col
                            Layout.fillWidth: true; spacing: 2
                            Label {
                                text: model.name + ((model.key === "cleanconfig" && Hw.laptop) ? "   (recommended)" : "")
                                font.bold: true; font.pixelSize: 15
                            }
                            Label { text: model.note; wrapMode: Text.WordWrap; Layout.fillWidth: true; opacity: 0.75 }
                        }
                    }
                    MouseArea { anchors.fill: parent; onClicked: page.pick(model.key) }
                }
            }
        }
    }
}
