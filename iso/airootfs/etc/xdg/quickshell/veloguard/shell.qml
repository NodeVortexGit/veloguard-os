// VeloGuardOS quick panel (Quickshell, `qs -c veloguard`) — the top bar's
// quick settings, separate from notifications (those stay in swaync):
// Wi-Fi, Bluetooth, VPN, airplane mode, night light, do-not-disturb, volume
// and brightness, what's playing, every AI subscription's plan usage, and
// screenshot / lock / agent / power. Frosted glass (Hyprland layer rule
// "veloguard-quickpanel"), Frost colours.
//
//   qs -c veloguard ipc call panel toggle     # Super alone, Super+U, the bar's 󰒓
//   qs -c veloguard ipc call panel usage      # the bar's AI-usage button
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Hyprland
import Quickshell.Services.Mpris

ShellRoot {
    id: root
    property bool open: false
    property bool usageOnly: false

    // Frost palette
    readonly property color glass: Qt.rgba(10 / 255, 10 / 255, 18 / 255, 0.64)
    readonly property color tile: Qt.rgba(18 / 255, 18 / 255, 28 / 255, 0.78)
    readonly property color edge: Qt.rgba(59 / 255, 91 / 255, 217 / 255, 0.55)
    readonly property color accent: "#3b5bd9"
    readonly property color accent2: "#6b9bff"
    readonly property color fg: "#d8dcea"
    readonly property color muted: "#6a7290"

    // live state, refreshed while the panel is open
    property bool wifiOn: false
    property string network: ""
    property bool btOn: false
    property bool vpnOn: false
    property bool airplane: false
    property bool night: false
    property bool dnd: false
    property real volume: 0
    property bool sinkMuted: false
    property real brightness: -1
    property var plans: []

    IpcHandler {
        target: "panel"
        function toggle(): void { root.usageOnly = false; root.open = !root.open; if (root.open) root.refresh() }
        function usage(): void { root.usageOnly = true; root.open = true; root.refresh() }
        function close(): void { root.open = false }
    }

    function sh(cmd) { Quickshell.execDetached(["sh", "-c", cmd]) }
    function refresh() { stateProc.running = true; plansProc.running = true }

    // one shell round-trip for every toggle + slider state
    Process {
        id: stateProc
        command: ["sh", "-c",
            "echo wifi=$(nmcli radio wifi 2>/dev/null);" +
            "echo net=$(veloguard-netid 2>/dev/null | cut -f3);" +
            "bluetoothctl show 2>/dev/null | grep -q 'Powered: yes' && echo bt=1 || echo bt=0;" +
            "veloguard-vpn active >/dev/null 2>&1 && echo vpn=1 || echo vpn=0;" +
            "rfkill list 2>/dev/null | grep -q 'Soft blocked: no' && echo air=0 || echo air=1;" +
            "pgrep -x hyprsunset >/dev/null && echo night=1 || echo night=0;" +
            "echo dnd=$(swaync-client -D 2>/dev/null);" +
            "echo vol=$(wpctl get-volume @DEFAULT_AUDIO_SINK@ 2>/dev/null);" +
            "echo bri=$(brightnessctl -m 2>/dev/null | cut -d, -f4 | tr -d '%')"]
        stdout: StdioCollector {
            onStreamFinished: {
                for (const line of this.text.split("\n")) {
                    const i = line.indexOf("="); if (i < 0) continue
                    const k = line.slice(0, i), v = line.slice(i + 1).trim()
                    if (k === "wifi") root.wifiOn = v === "enabled"
                    else if (k === "net") root.network = v
                    else if (k === "bt") root.btOn = v === "1"
                    else if (k === "vpn") root.vpnOn = v === "1"
                    else if (k === "air") root.airplane = v === "1"
                    else if (k === "night") root.night = v === "1"
                    else if (k === "dnd") root.dnd = v === "true"
                    else if (k === "vol") { const m = v.match(/([0-9.]+)/); root.volume = m ? parseFloat(m[1]) : 0; root.sinkMuted = v.indexOf("MUTED") >= 0 }
                    else if (k === "bri") root.brightness = v === "" ? -1 : parseInt(v) / 100
                }
            }
        }
    }
    Process {
        id: plansProc
        command: ["veloguard-ai-usage", "--plans"]
        stdout: StdioCollector {
            onStreamFinished: { try { root.plans = JSON.parse(this.text) } catch (e) { root.plans = [] } }
        }
    }
    Timer { interval: 2500; running: root.open; repeat: true; onTriggered: stateProc.running = true }

    PanelWindow {
        id: win
        visible: root.open
        anchors { top: true; right: true }
        exclusionMode: ExclusionMode.Normal
        exclusiveZone: 0
        implicitWidth: 430
        implicitHeight: body.implicitHeight + 28
        color: "transparent"
        WlrLayershell.namespace: "veloguard-quickpanel"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: WlrKeyboardFocus.OnDemand

        HyprlandFocusGrab {
            windows: [win]
            active: root.open
            onCleared: root.open = false
        }

        Rectangle {
            anchors.fill: parent
            color: root.glass
            border.color: root.edge
            border.width: 1
            focus: true
            Keys.onEscapePressed: root.open = false

            ColumnLayout {
                id: body
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                spacing: 12

                // ── header ──────────────────────────────────────────────
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        id: clock
                        text: Qt.formatDateTime(new Date(), "dddd, d MMMM  ·  HH:mm")
                        color: root.fg; font.pixelSize: 15; font.bold: true
                        Timer { interval: 15000; running: root.open; repeat: true; triggeredOnStart: true
                                onTriggered: clock.text = Qt.formatDateTime(new Date(), "dddd, d MMMM  ·  HH:mm") }
                    }
                    Item { Layout.fillWidth: true }
                    Text { text: root.usageOnly ? "AI usage" : "VeloGuard"; color: root.accent2; font.pixelSize: 13 }
                }

                // ── toggles ─────────────────────────────────────────────
                GridLayout {
                    visible: !root.usageOnly
                    Layout.fillWidth: true
                    columns: 3; columnSpacing: 6; rowSpacing: 6
                    Toggle { icon: "󰤨"; label: root.wifiOn ? (root.network || "Wi-Fi") : "Wi-Fi off"; on: root.wifiOn
                             onClicked: root.sh(root.wifiOn ? "nmcli radio wifi off" : "nmcli radio wifi on")
                             onSecondary: { root.open = false; root.sh("veloguard-wifi-menu") } }
                    Toggle { icon: "󰂯"; label: "Bluetooth"; on: root.btOn
                             onClicked: root.sh(root.btOn ? "bluetoothctl power off" : "rfkill unblock bluetooth; bluetoothctl power on")
                             onSecondary: { root.open = false; root.sh("veloguard-bt-menu") } }
                    Toggle { icon: "󰒃"; label: root.vpnOn ? "VPN on" : "VPN off"; on: root.vpnOn
                             onClicked: root.sh((root.vpnOn ? "pkexec veloguard-vpn disconnect" : "pkexec veloguard-vpn connect") + "; pkill -RTMIN+7 waybar")
                             onSecondary: { root.open = false; root.sh("veloguard-guard-menu vpn") } }
                    Toggle { icon: "󰀝"; label: "Airplane"; on: root.airplane
                             onClicked: root.sh(root.airplane ? "rfkill unblock all" : "rfkill block all") }
                    Toggle { icon: "󰖔"; label: "Night light"; on: root.night
                             onClicked: root.sh(root.night ? "pkill hyprsunset" : "setsid -f hyprsunset -t 4000 >/dev/null 2>&1") }
                    Toggle { icon: "󰂛"; label: "Do not disturb"; on: root.dnd
                             onClicked: root.sh("swaync-client -d") }
                }

                // ── sliders ─────────────────────────────────────────────
                SliderRow {
                    visible: !root.usageOnly
                    icon: root.sinkMuted ? "󰝟" : "󰕾"; value: root.volume
                    onIconClicked: root.sh("wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle")
                    onMoved: v => root.sh("wpctl set-volume -l 1 @DEFAULT_AUDIO_SINK@ " + v.toFixed(2))
                }
                SliderRow {
                    visible: !root.usageOnly && root.brightness >= 0
                    icon: "󰃠"; value: Math.max(0, root.brightness)
                    onMoved: v => root.sh("brightnessctl -q s " + Math.max(1, Math.round(v * 100)) + "%")
                }

                // ── media ───────────────────────────────────────────────
                Rectangle {
                    id: media
                    readonly property var player: Mpris.players.values.length ? Mpris.players.values[0] : null
                    visible: !root.usageOnly && player !== null
                    Layout.fillWidth: true
                    implicitHeight: 56
                    color: root.tile; border.color: root.edge; border.width: 1
                    RowLayout {
                        anchors { fill: parent; margins: 10 }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 0
                            Text { Layout.fillWidth: true; elide: Text.ElideRight; color: root.fg; font.bold: true
                                   text: media.player ? (media.player.trackTitle || "Playing") : "" }
                            Text { Layout.fillWidth: true; elide: Text.ElideRight; color: root.muted; font.pixelSize: 11
                                   text: media.player ? (media.player.trackArtist || "") : "" }
                        }
                        IconButton { icon: "󰒮"; onClicked: if (media.player) media.player.previous() }
                        IconButton { icon: media.player && media.player.isPlaying ? "󰏤" : "󰐊"
                                     onClicked: if (media.player) media.player.togglePlaying() }
                        IconButton { icon: "󰒭"; onClicked: if (media.player) media.player.next() }
                    }
                }

                // ── AI plan usage ───────────────────────────────────────
                Text { text: "AI plan usage"; color: root.muted; font.pixelSize: 11 }
                Repeater {
                    model: root.plans
                    // one card per subscription, laid out like its own usage page
                    delegate: Rectangle {
                        id: card
                        required property var modelData
                        Layout.fillWidth: true
                        implicitHeight: cardCol.implicitHeight + 24
                        color: root.tile
                        border.width: modelData.current ? 1 : 0
                        border.color: modelData.color
                        ColumnLayout {
                            id: cardCol
                            anchors { left: parent.left; right: parent.right; top: parent.top; margins: 12 }
                            spacing: 6
                            RowLayout {
                                spacing: 10
                                Image { source: "file://" + card.modelData.icon; sourceSize: Qt.size(28, 28)
                                        Layout.preferredWidth: 28; Layout.preferredHeight: 28; smooth: true; mipmap: true }
                                Text { text: card.modelData.label; color: root.fg; font.bold: true; font.pixelSize: 15
                                       Layout.fillWidth: true }
                                Text { visible: card.modelData.current; text: "in use"; color: card.modelData.color; font.pixelSize: 11 }
                            }
                            Text { visible: card.modelData.windows.length === 0; text: card.modelData.note; color: root.muted
                                   font.pixelSize: 11; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                            Repeater {
                                model: card.modelData.windows
                                delegate: ColumnLayout {
                                    required property var modelData
                                    Layout.fillWidth: true; Layout.topMargin: 4; spacing: 4
                                    RowLayout {
                                        Layout.fillWidth: true
                                        Text { text: modelData.name; color: root.fg; font.pixelSize: 13; Layout.fillWidth: true }
                                        Text { text: modelData.percent === null ? "?" : Math.round(modelData.percent) + "% used"
                                               color: root.fg; font.pixelSize: 13 }
                                    }
                                    Rectangle {      // the bar — rounded, the service's colour
                                        Layout.fillWidth: true; implicitHeight: 8; radius: 4; color: Qt.rgba(1, 1, 1, 0.10)
                                        Rectangle {
                                            readonly property real p: modelData.percent === null ? 0 : Math.min(100, modelData.percent)
                                            width: Math.max(p > 0 ? height : 0, parent.width * p / 100); height: parent.height; radius: 4
                                            color: p >= 90 ? "#f26d7d" : card.modelData.color
                                        }
                                    }
                                    Text { text: modelData.resets_text; color: root.muted; font.pixelSize: 11; visible: text !== "" }
                                }
                            }
                        }
                    }
                }

                // ── actions ─────────────────────────────────────────────
                RowLayout {
                    visible: !root.usageOnly
                    Layout.fillWidth: true; spacing: 6
                    Action { icon: "󰄀"; label: "Screenshot"; onClicked: { root.open = false; root.sh("sleep 0.3; grim -g \"$(slurp)\" - | wl-copy && notify-send -u low 'Screenshot copied'") } }
                    Action { icon: "󰌾"; label: "Lock"; onClicked: { root.open = false; root.sh("loginctl lock-session") } }
                    Action { icon: "󰚩"; label: "Agent"; onClicked: { root.open = false; root.sh("veloguard-agent") } }
                    Action { icon: "󰐥"; label: "Power"; onClicked: { root.open = false; root.sh("veloguard-powermenu") } }
                }
            }
        }
    }

    // ── small building blocks ───────────────────────────────────────────
    component Toggle: Rectangle {
        id: t
        property string icon
        property string label
        property bool on
        signal clicked()
        signal secondary()
        Layout.fillWidth: true
        implicitHeight: 54
        color: on ? Qt.rgba(59 / 255, 91 / 255, 217 / 255, 0.78) : root.tile
        border.color: on ? root.accent2 : root.edge; border.width: 1
        ColumnLayout {
            anchors.centerIn: parent; spacing: 2
            Text { Layout.alignment: Qt.AlignHCenter; text: t.icon; color: t.on ? "#ffffff" : root.fg; font.pixelSize: 17 }
            Text { Layout.alignment: Qt.AlignHCenter; text: t.label; color: t.on ? "#ffffff" : root.fg; font.pixelSize: 11
                   elide: Text.ElideRight; Layout.maximumWidth: t.width - 12 }
        }
        MouseArea {
            anchors.fill: parent; acceptedButtons: Qt.LeftButton | Qt.RightButton; hoverEnabled: true
            onClicked: m => { if (m.button === Qt.RightButton) t.secondary(); else { t.clicked(); delay.restart() } }
            onEntered: t.border.color = root.accent2
            onExited: t.border.color = t.on ? root.accent2 : root.edge
        }
        Timer { id: delay; interval: 600; onTriggered: stateProc.running = true }
    }

    component SliderRow: RowLayout {
        id: s
        property string icon
        property real value
        signal moved(real v)
        signal iconClicked()
        Layout.fillWidth: true; spacing: 10
        Text { text: s.icon; color: root.fg; font.pixelSize: 17
               MouseArea { anchors.fill: parent; onClicked: s.iconClicked() } }
        Slider {
            id: sl
            Layout.fillWidth: true
            from: 0; to: 1; value: s.value
            onMoved: s.moved(value)
            background: Rectangle {
                x: sl.leftPadding; y: sl.topPadding + sl.availableHeight / 2 - height / 2
                width: sl.availableWidth; height: 6; color: Qt.rgba(1, 1, 1, 0.10)
                Rectangle { width: sl.visualPosition * parent.width; height: parent.height; color: root.accent }
            }
            handle: Rectangle {
                x: sl.leftPadding + sl.visualPosition * (sl.availableWidth - width)
                y: sl.topPadding + sl.availableHeight / 2 - height / 2
                width: 14; height: 14; color: "#ffffff"; border.color: root.accent
            }
        }
        Text { text: Math.round(s.value * 100) + "%"; color: root.muted; font.pixelSize: 11; Layout.preferredWidth: 34 }
    }

    component IconButton: Rectangle {
        id: ib
        property string icon
        signal clicked()
        implicitWidth: 32; implicitHeight: 32
        color: ma.containsMouse ? Qt.rgba(59 / 255, 91 / 255, 217 / 255, 0.45) : "transparent"
        Text { anchors.centerIn: parent; text: ib.icon; color: root.fg; font.pixelSize: 17 }
        MouseArea { id: ma; anchors.fill: parent; hoverEnabled: true; onClicked: ib.clicked() }
    }

    component Action: Rectangle {
        id: a
        property string icon
        property string label
        signal clicked()
        Layout.fillWidth: true
        implicitHeight: 44
        color: am.containsMouse ? Qt.rgba(59 / 255, 91 / 255, 217 / 255, 0.45) : root.tile
        border.color: root.edge; border.width: 1
        RowLayout {
            anchors.centerIn: parent; spacing: 6
            Text { text: a.icon; color: root.fg; font.pixelSize: 15 }
            Text { text: a.label; color: root.fg; font.pixelSize: 11 }
        }
        MouseArea { id: am; anchors.fill: parent; hoverEnabled: true; onClicked: a.clicked() }
    }
}
