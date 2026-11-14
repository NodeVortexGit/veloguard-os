/* VeloGuardOS — the installer's welcome page (the welcomeq module loads
 * welcomeq.qml from the branding directory, qmlSearch: both).
 *
 * Replaces the widget welcome page, whose title can only be one of Calamares'
 * fixed sentences ("Welcome to the Calamares installer for …"). Everything it
 * did is still here, driven by the module's own Config object (`config`):
 * the requirement checks (storage, RAM, root, internet) and the language.
 * Colours: theme.js.
 */
import io.calamares.core 1.0
import io.calamares.ui 1.0

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "theme.js" as Theme

Pane {
    id: welcome
    padding: 24

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

    ColumnLayout {
        anchors.fill: parent
        spacing: 14

        Label {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("Welcome to %1").arg(Branding.string(Branding.ProductName))
            font.pixelSize: 30; font.bold: true
            color: Theme.fg
        }
        Label {
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: qsTr("AI-first, and guarded. This will install %1 on this computer — a few questions, then it does the rest.")
                  .arg(Branding.string(Branding.ProductName))
            color: Theme.muted
        }

        Image {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumHeight: 120
            source: "veloguard-logo.png"
            fillMode: Image.PreserveAspectFit
            smooth: true; mipmap: true
        }

        // Requirements: only the ones not met (storage, RAM, root, internet…).
        // Red = blocks the installation, amber = works but with limits.
        Rectangle {
            Layout.fillWidth: true
            visible: config.requirementsModel && !config.requirementsModel.satisfiedRequirements
            implicitHeight: reqCol.implicitHeight + 20
            radius: 8; color: Theme.deep
            border.width: 1
            border.color: config.requirementsModel && config.requirementsModel.satisfiedMandatory ? "#ffcc33" : "#ff6e6e"
            ColumnLayout {
                id: reqCol
                anchors.fill: parent; anchors.margins: 10; spacing: 4
                Repeater {
                    model: config.requirementsModel
                    delegate: Label {
                        required property bool satisfied
                        required property bool mandatory
                        required property string negatedText
                        visible: !satisfied
                        Layout.fillWidth: true; wrapMode: Text.WordWrap
                        text: (mandatory ? "✕  " : "!  ") + negatedText
                        color: mandatory ? "#ff6e6e" : "#ffcc33"
                    }
                }
                Label {
                    Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 11; color: Theme.muted
                    text: config.requirementsModel && config.requirementsModel.satisfiedMandatory
                          ? qsTr("You can still install; some features may be limited until this is fixed.")
                          : qsTr("The installation can't continue until this is fixed.")
                }
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 12
            Label { text: qsTr("Language"); color: Theme.muted }
            ComboBox {
                id: language
                Layout.preferredWidth: 280
                model: config.languagesModel
                textRole: "label"
                currentIndex: config.localeIndex
                onActivated: config.localeIndex = currentIndex
            }
            Button {
                visible: config.supportUrl !== ""
                text: qsTr("Support")
                onClicked: Qt.openUrlExternally(config.supportUrl)
            }
        }
    }
}
