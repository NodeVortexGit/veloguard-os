/* VeloGuardOS — schematic previews of each desktop's default layout, for the
 * installer's Desktop page. Drawn (not screenshots), so they stay crisp at any
 * size and ship no third-party images; each mirrors what that desktop looks
 * like out of the box: where the bars/docks sit, how windows are arranged.
 */
import QtQuick
import "theme.js" as Theme

Item {
    id: root
    property string kind: "hyprland"
    readonly property real u: width / 320          // 1 unit at the 320 px design width
    implicitWidth: 320; implicitHeight: 200
    clip: true

    // A window: optional title bar, a few "text" lines, coloured frame.
    component Win: Rectangle {
        id: w
        property color frame: Theme.accent
        property color bar: "transparent"
        property real barH: 0
        property color body: "#101b30"
        property color ink: Theme.fg
        property int lines: 4
        color: body
        radius: 4 * root.u
        border.width: Math.max(1, root.u)
        border.color: frame
        clip: true
        Rectangle {
            visible: w.barH > 0
            width: parent.width; height: w.barH
            color: w.bar; radius: w.radius
            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: parent.radius; color: parent.color }
        }
        Column {
            x: 6 * root.u; y: w.barH + 6 * root.u
            spacing: 4 * root.u
            Repeater {
                model: w.lines
                Rectangle {
                    width: (w.width - 12 * root.u) * [0.82, 0.55, 0.7, 0.4, 0.62, 0.5][index % 6]
                    height: 2.5 * root.u; radius: height / 2
                    color: w.ink; opacity: 0.28
                }
            }
        }
    }
    component Dot: Rectangle { width: 5 * root.u; height: width; radius: width / 2 }
    component Txt: Text { color: Theme.fg; font.pixelSize: Math.max(6, 7 * root.u); font.family: "monospace" }

    Loader {
        anchors.fill: parent
        sourceComponent: ({ cleanconfig: cleanconfig, hyprland: hyprland, gnome: gnome, xfce: xfce,
                            niri: niri, i3: i3, cosmic: cosmic, headless: headless })[root.kind] || hyprland
    }

    // ── Clean Config: black + dark blue glass, the floating "Dynamic Island" ──
    Component {
        id: cleanconfig
        Rectangle {
            gradient: Gradient { GradientStop { position: 0; color: "#05070d" } GradientStop { position: 1; color: "#0b1a3d" } }
            Win { x: 2 * root.u; y: 22 * root.u; width: parent.width * 0.58; height: parent.height - 24 * root.u
                  body: "#cc0e1630"; frame: "#3b5bd9"; radius: 12 * root.u; lines: 6 }
            Win { x: parent.width * 0.58 + 2 * root.u; y: 22 * root.u; width: parent.width * 0.42 - 4 * root.u
                  height: (parent.height - 26 * root.u) / 2; body: "#c20e1630"; frame: "#2e49ae"; radius: 12 * root.u }
            Win { x: parent.width * 0.58 + 2 * root.u; y: 24 * root.u + (parent.height - 26 * root.u) / 2
                  width: parent.width * 0.42 - 4 * root.u; height: (parent.height - 26 * root.u) / 2
                  body: "#c20e1630"; frame: "#2e49ae"; radius: 12 * root.u; lines: 3 }
            Rectangle {                                    // the island
                anchors.horizontalCenter: parent.horizontalCenter; y: 4 * root.u
                width: 92 * root.u; height: 14 * root.u; radius: height / 2; color: "#000000"
                border.width: 1; border.color: "#3b5bd9"
                Txt { anchors.centerIn: parent; text: "12:40  ♪  ▮▮▮"; color: "#9fb4ff" }
            }
        }
    }

    // ── VeloGuard Hyprland: navy, Waybar on top, tiled windows with gaps ───────
    Component {
        id: hyprland
        Rectangle {
            gradient: Gradient { GradientStop { position: 0; color: "#13203a" } GradientStop { position: 1; color: "#0a1426" } }
            Rectangle {                                    // waybar
                width: parent.width; height: 12 * root.u; color: "#0d1729"
                Row { x: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; spacing: 3 * root.u
                      Txt { text: "🛡" } Dot { color: Theme.accent } Dot { color: Theme.line } Dot { color: Theme.line } }
                Txt { anchors.centerIn: parent; text: "Friday 12:40" }
                Txt { anchors.right: parent.right; anchors.rightMargin: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; text: "VPN ⏻" }
            }
            Win { x: 6 * root.u; y: 18 * root.u; width: parent.width * 0.56; height: parent.height - 24 * root.u; lines: 6 }
            Win { x: parent.width * 0.56 + 12 * root.u; y: 18 * root.u; width: parent.width * 0.44 - 18 * root.u
                  height: (parent.height - 30 * root.u) / 2; frame: Theme.green }
            Win { x: parent.width * 0.56 + 12 * root.u; y: 24 * root.u + (parent.height - 30 * root.u) / 2
                  width: parent.width * 0.44 - 18 * root.u; height: (parent.height - 30 * root.u) / 2; frame: Theme.line; lines: 3 }
        }
    }

    // ── GNOME: black top bar, one centred rounded window, overview-first ──────
    Component {
        id: gnome
        Rectangle {
            gradient: Gradient { GradientStop { position: 0; color: "#2b3a67" } GradientStop { position: 1; color: "#6b4f8f" } }
            Rectangle {
                width: parent.width; height: 12 * root.u; color: "#000000"
                Rectangle { x: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; width: 22 * root.u; height: 6 * root.u
                            radius: height / 2; color: "#ffffff"; opacity: 0.85 }
                Txt { anchors.centerIn: parent; text: "Fri 12:40"; color: "#ffffff" }
                Txt { anchors.right: parent.right; anchors.rightMargin: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; text: "⏻"; color: "#ffffff" }
            }
            Win { anchors.horizontalCenter: parent.horizontalCenter; y: 26 * root.u; width: parent.width * 0.62; height: parent.height * 0.62
                  body: "#242424"; bar: "#303030"; barH: 14 * root.u; frame: "#404040"; radius: 8 * root.u; lines: 5 }
            Rectangle {                                    // the dash (shown in the overview)
                anchors.horizontalCenter: parent.horizontalCenter; anchors.bottom: parent.bottom; anchors.bottomMargin: 6 * root.u
                width: 88 * root.u; height: 16 * root.u; radius: 6 * root.u; color: "#ffffff"; opacity: 0.18
                Row { anchors.centerIn: parent; spacing: 4 * root.u
                      Repeater { model: 5; Rectangle { width: 10 * root.u; height: width; radius: 3 * root.u; color: ["#3584e4","#e66100","#2ec27e","#f6d32d","#9141ac"][index] } } }
            }
        }
    }

    // ── Xfce: bottom panel with menu + tasks + clock, desktop icons ───────────
    Component {
        id: xfce
        Rectangle {
            gradient: Gradient { GradientStop { position: 0; color: "#1d3b5e" } GradientStop { position: 1; color: "#2d6b8f" } }
            Column { x: 8 * root.u; y: 8 * root.u; spacing: 8 * root.u
                     Repeater { model: 3; Rectangle { width: 14 * root.u; height: 12 * root.u; radius: 2 * root.u; color: "#e8e8e8"; opacity: 0.75 } } }
            Win { x: parent.width * 0.22; y: 14 * root.u; width: parent.width * 0.6; height: parent.height * 0.62
                  body: "#f2f2f2"; ink: "#333333"; bar: "#dcdcdc"; barH: 12 * root.u; frame: "#a0a0a0"; radius: 3 * root.u; lines: 5 }
            Rectangle {
                anchors.bottom: parent.bottom; width: parent.width; height: 14 * root.u; color: "#2b2b2b"
                Rectangle { x: 3 * root.u; anchors.verticalCenter: parent.verticalCenter; width: 10 * root.u; height: 10 * root.u; radius: 2 * root.u; color: "#4a90d9" }
                Row { x: 17 * root.u; anchors.verticalCenter: parent.verticalCenter; spacing: 3 * root.u
                      Repeater { model: 2; Rectangle { width: 44 * root.u; height: 9 * root.u; radius: 2 * root.u; color: index === 0 ? "#555555" : "#3a3a3a" } } }
                Txt { anchors.right: parent.right; anchors.rightMargin: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; text: "12:40"; color: "#eeeeee" }
            }
        }
    }

    // ── niri: columns on an endless horizontal strip, scrolling past the edge ──
    Component {
        id: niri
        Rectangle {
            color: "#1e1e2e"
            Rectangle { width: parent.width; height: 10 * root.u; color: "#11111b"
                        Txt { anchors.centerIn: parent; text: "12:40"; color: "#cdd6f4" } }
            Win { x: -parent.width * 0.18; y: 16 * root.u; width: parent.width * 0.36; height: parent.height - 22 * root.u; frame: "#585b70"; body: "#181825"; ink: "#cdd6f4" }
            Win { x: parent.width * 0.21; y: 16 * root.u; width: parent.width * 0.5; height: parent.height - 22 * root.u; frame: "#cba6f7"; body: "#181825"; ink: "#cdd6f4"; lines: 6 }
            Win { x: parent.width * 0.74; y: 16 * root.u; width: parent.width * 0.42; height: (parent.height - 26 * root.u) / 2; frame: "#585b70"; body: "#181825"; ink: "#cdd6f4" }
            Win { x: parent.width * 0.74; y: 20 * root.u + (parent.height - 26 * root.u) / 2; width: parent.width * 0.42; height: (parent.height - 26 * root.u) / 2; frame: "#585b70"; body: "#181825"; ink: "#cdd6f4"; lines: 2 }
            Txt { anchors.left: parent.left; anchors.leftMargin: 2 * root.u; anchors.verticalCenter: parent.verticalCenter; text: "‹"; font.pixelSize: 16 * root.u; color: "#cba6f7" }
            Txt { anchors.right: parent.right; anchors.rightMargin: 2 * root.u; anchors.verticalCenter: parent.verticalCenter; text: "›"; font.pixelSize: 16 * root.u; color: "#cba6f7" }
        }
    }

    // ── i3: tiled windows with text title bars, i3bar at the bottom ───────────
    Component {
        id: i3
        Rectangle {
            color: "#000000"
            Win { x: 0; y: 0; width: parent.width / 2; height: parent.height - 12 * root.u; radius: 0
                  bar: "#285577"; barH: 9 * root.u; frame: "#4c7899"; body: "#111111"; lines: 7 }
            Win { x: parent.width / 2; y: 0; width: parent.width / 2; height: (parent.height - 12 * root.u) / 2; radius: 0
                  bar: "#222222"; barH: 9 * root.u; frame: "#333333"; body: "#111111" }
            Win { x: parent.width / 2; y: (parent.height - 12 * root.u) / 2; width: parent.width / 2; height: (parent.height - 12 * root.u) / 2; radius: 0
                  bar: "#222222"; barH: 9 * root.u; frame: "#333333"; body: "#111111"; lines: 3 }
            Rectangle {
                anchors.bottom: parent.bottom; width: parent.width; height: 12 * root.u; color: "#000000"
                Row { x: 2 * root.u; anchors.verticalCenter: parent.verticalCenter; spacing: 2 * root.u
                      Repeater { model: ["1", "2", "3"]; Rectangle { width: 10 * root.u; height: 9 * root.u; color: index === 0 ? "#285577" : "#333333"
                                 Txt { anchors.centerIn: parent; text: modelData } } } }
                Txt { anchors.right: parent.right; anchors.rightMargin: 4 * root.u; anchors.verticalCenter: parent.verticalCenter
                      text: "W: up | 82% | 12:40"; color: "#cccccc" }
            }
        }
    }

    // ── COSMIC: top panel, rounded windows, dock at the bottom ────────────────
    Component {
        id: cosmic
        Rectangle {
            gradient: Gradient { GradientStop { position: 0; color: "#1b2a33" } GradientStop { position: 1; color: "#3a5361" } }
            Rectangle { width: parent.width; height: 11 * root.u; color: "#1b1b1b"
                        Row { x: 5 * root.u; anchors.verticalCenter: parent.verticalCenter; spacing: 4 * root.u
                              Txt { text: "Workspaces"; color: "#cfcfcf" } Txt { text: "Applications"; color: "#cfcfcf" } }
                        Txt { anchors.centerIn: parent; text: "Oct 16 12:40"; color: "#ffffff" } }
            Win { x: 10 * root.u; y: 18 * root.u; width: parent.width * 0.5; height: parent.height * 0.6
                  body: "#2a2a2a"; bar: "#333333"; barH: 11 * root.u; frame: "#63d0df"; radius: 9 * root.u; lines: 5 }
            Win { x: parent.width * 0.5 + 16 * root.u; y: 18 * root.u; width: parent.width * 0.5 - 26 * root.u; height: parent.height * 0.6
                  body: "#2a2a2a"; bar: "#333333"; barH: 11 * root.u; frame: "#444444"; radius: 9 * root.u; lines: 3 }
            Rectangle { anchors.horizontalCenter: parent.horizontalCenter; anchors.bottom: parent.bottom; anchors.bottomMargin: 5 * root.u
                        width: 96 * root.u; height: 17 * root.u; radius: 8 * root.u; color: "#1b1b1b"
                        Row { anchors.centerIn: parent; spacing: 4 * root.u
                              Repeater { model: 6; Rectangle { width: 11 * root.u; height: width; radius: width / 2
                                         color: ["#63d0df","#94ebeb","#fda1a1","#f0e68c","#a1c8fd","#cfcfcf"][index] } } } }
        }
    }

    // ── Headless: no desktop at all — a text login (and the optional SSH link) ─
    Component {
        id: headless
        Rectangle {
            color: "#000000"
            Column {
                x: 8 * root.u; y: 8 * root.u; spacing: 3 * root.u
                Txt { text: "VeloGuardOS (tty1)"; color: "#cccccc" }
                Txt { text: " "; }
                Txt { text: "SSH link → you@192.168.1.20: connected"; color: Theme.green }
                Txt { text: " "; }
                Txt { text: "veloguard login: _"; color: "#ffffff" }
            }
            Txt { anchors.right: parent.right; anchors.bottom: parent.bottom; anchors.margins: 6 * root.u
                  text: "no display manager · no desktop"; color: "#666666" }
        }
    }
}
