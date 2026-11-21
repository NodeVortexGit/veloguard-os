/* VeloGuardOS — "AI agents" installer page (loaded by notesqml@veloguardagents).
 *
 * Which AI coding agents to install. Each one becomes a brain the guard can
 * think with (veloguard-agent set <agent>) and gets VeloGuard's plugin: the
 * guard's tools, its rules, and a check before every shell command and edit.
 * Claude Code, Codex and Kimi Code are ticked by default.
 *
 * Global Storage it writes (read by shellprocess@veloguardagents):
 *   veloguard_agents   space-separated agent ids, or "none"
 * Colours: theme.js.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0
import "theme.js" as Theme

Pane {
    id: page
    padding: 20

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

    ListModel {
        id: agents
        ListElement { key: "claude-code"; name: "Claude Code"; vendor: "Anthropic"; on: true
            note: "Anthropic's coding agent. Sign in with your Claude account the first time you open it." }
        ListElement { key: "codex"; name: "Codex"; vendor: "OpenAI"; on: true
            note: "OpenAI's coding agent (from the Arch repos). Sign in with ChatGPT or an API key." }
        ListElement { key: "kimi"; name: "Kimi Code"; vendor: "Moonshot AI"; on: true
            note: "Moonshot's coding agent. Sign in with your Kimi account." }
        ListElement { key: "hermes"; name: "Hermes Agent"; vendor: "Nous Research"; on: false
            note: "Nous Research's agent; works with many model providers (OpenRouter, Nous, Anthropic…)." }
        ListElement { key: "openclaw"; name: "OpenClaw"; vendor: "OpenClaw"; on: false
            note: "A personal agent that can also talk to you through chat apps." }
    }

    function save() {
        var picked = []
        for (var i = 0; i < agents.count; ++i) if (agents.get(i).on) picked.push(agents.get(i).key)
        Global.insert("veloguard_agents", picked.length ? picked.join(" ") : "none")
        count = picked.length
    }
    property int count: 0
    Component.onCompleted: save()
    function onActivate() { save() }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label { text: "AI agents"; font.pixelSize: 22; font.bold: true; color: Theme.fg }
        Label {
            Layout.fillWidth: true; wrapMode: Text.WordWrap; color: Theme.muted
            text: "Pick the coding agents to install. Each one can be the brain VeloGuard thinks with, and opens "
                  + "with Super+A. Every agent gets VeloGuard's plugin: the guard's tools, its rules, and a check "
                  + "before each command — an agent can never switch the guard off, and its root commands wait for "
                  + "your Approve. You sign in to each one the first time you open it. More can be added later: "
                  + "veloguard-agent install <name>."
        }

        ScrollView {
            Layout.fillWidth: true; Layout.fillHeight: true
            clip: true
            ListView {
                model: agents
                spacing: 6
                delegate: Rectangle {
                    width: ListView.view.width
                    height: 58
                    radius: 7
                    color: model.on ? Theme.raised : (hover.hovered ? Qt.darker(Theme.raised, 1.25) : Theme.deep)
                    border.width: model.on ? 2 : 1
                    border.color: model.on ? Theme.accent : Theme.line
                    HoverHandler { id: hover }
                    RowLayout {
                        anchors.fill: parent; anchors.leftMargin: 6; anchors.rightMargin: 10; spacing: 6
                        // display only; drawn here because the style's own box
                        // was navy on navy — an unticked agent showed no box at all
                        CheckBox {
                            checkable: false; checked: model.on
                            indicator: Rectangle {
                                implicitWidth: 18; implicitHeight: 18; radius: 3
                                x: parent.leftPadding; y: parent.height / 2 - height / 2
                                color: model.on ? Theme.accent : "transparent"
                                border.width: 1; border.color: model.on ? Theme.accent : Theme.muted
                                Label {
                                    anchors.centerIn: parent; visible: model.on
                                    text: "✓"; color: Theme.deep; font.bold: true; font.pixelSize: 13
                                }
                            }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 1
                            Label {
                                Layout.fillWidth: true; elide: Text.ElideRight
                                text: model.name + "   ·   " + model.vendor
                                font.bold: true; font.pixelSize: 13
                                color: model.on ? Theme.accent : Theme.fg
                            }
                            Label { Layout.fillWidth: true; elide: Text.ElideRight; text: model.note; color: Theme.muted; font.pixelSize: 11 }
                        }
                    }
                    MouseArea {
                        anchors.fill: parent
                        onClicked: { agents.setProperty(index, "on", !model.on); page.save() }
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 11
            color: page.count ? Theme.muted : "#ffcc33"
            text: page.count
                  ? page.count + (page.count === 1 ? " agent" : " agents") + " will be installed (needs internet; whatever "
                    + "can't finish is installed on the first online boot)."
                  : "No agents — VeloGuard will use Ollama (local) or the Claude API as its brain."
        }
    }
}
