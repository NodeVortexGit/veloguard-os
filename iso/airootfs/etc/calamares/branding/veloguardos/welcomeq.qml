/* VeloGuardOS — the installer's welcome page (the welcomeq module loads
 * welcomeq.qml from the branding directory, qmlSearch: both).
 *
 * Replaces the widget welcome page, whose title can only be one of Calamares'
 * fixed sentences ("Welcome to the Calamares installer for …"). Everything it
 * did is still here, driven by the module's own Config object (`config`):
 * the requirement checks (storage, RAM, root, internet) and the language.
 *
 * Language: three choices — English (the default), Български, 日本語. One
 * pick switches the installer itself (config.localeIndex, Calamares' own
 * translations) AND sets the installed system's language, all of it: the
 * locale page used to keep English text but take numbers, dates and units from
 * the timezone (Bulgarian formats under English). Global Storage:
 *   veloguard_language   en_US.UTF-8 | bg_BG.UTF-8 | ja_JP.UTF-8
 *                        → shellprocess@veloguardlanguage (calamares-language.sh)
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

    // The installer's languages, as Calamares lists them (to find ours by name)
    Instantiator {
        id: uiLangs
        model: config.languagesModel
        delegate: QtObject {
            property string en: model.englishLabel !== undefined ? model.englishLabel : ""
            // not "native": a reserved word in QML — the whole page failed to
            // load ("Welcome Loading failed"), and with it the installer
            property string nativeName: model.label !== undefined ? model.label : ""
        }
    }
    readonly property var langs: [
        { code: "en_US", label: "English", english: "English", nativeName: "english" },
        { code: "bg_BG", label: "Български", english: "Bulgarian", nativeName: "български" },
        { code: "ja_JP", label: "日本語", english: "Japanese", nativeName: "日本語" }
    ]
    property string lang: "en_US"
    function uiIndexFor(l) {
        for (var i = 0; i < uiLangs.count; ++i) {
            var o = uiLangs.objectAt(i)
            if (!o) continue
            if (o.en.indexOf(l.english) === 0 || o.nativeName.toLowerCase().indexOf(l.nativeName) === 0) return i
        }
        return -1
    }
    function pickLang(l) {
        lang = l.code
        Global.insert("veloguard_language", l.code + ".UTF-8")
        var i = uiIndexFor(l)
        if (i >= 0 && config.localeIndex !== i) config.localeIndex = i
    }
    // English unless the person picks otherwise — never a guess from the timezone.
    Component.onCompleted: pickLang(langs[0])

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
            spacing: 10
            Label { text: qsTr("Language"); color: Theme.muted }
            Repeater {
                model: welcome.langs
                delegate: Rectangle {
                    required property var modelData
                    readonly property bool sel: welcome.lang === modelData.code
                    implicitWidth: 130; implicitHeight: 40; radius: 7
                    color: sel ? Theme.raised : (langHover.hovered ? Qt.darker(Theme.raised, 1.25) : Theme.deep)
                    border.width: sel ? 2 : 1
                    border.color: sel ? Theme.accent : Theme.line
                    HoverHandler { id: langHover }
                    Label {
                        anchors.centerIn: parent
                        text: modelData.label
                        font.pixelSize: 15; font.bold: sel
                        color: sel ? Theme.accent : Theme.fg
                    }
                    MouseArea { anchors.fill: parent; onClicked: welcome.pickLang(modelData) }
                }
            }
            Button {
                visible: config.supportUrl !== ""
                text: qsTr("Support")
                onClicked: Qt.openUrlExternally(config.supportUrl)
            }
        }
    }
}
