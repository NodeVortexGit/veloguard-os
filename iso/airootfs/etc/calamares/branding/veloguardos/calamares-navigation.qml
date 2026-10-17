/* VeloGuardOS — the installer's navigation bar (branding.desc: navigation: qml).
 *
 * Calamares' own sample navigation (ViewManager back/next/quit), themed, plus
 * one rule: Next is disabled while a page sets Global Storage
 * `veloguard_block_next` — the Desktop page does, while its headless SSH-link
 * box is ticked without a valid user@address. QML pages (notesqml) have no
 * other way to stop the installer from moving on.
 */
import io.calamares.ui 1.0
import io.calamares.core 1.0

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "theme.js" as Theme

Rectangle {
    id: navigationBar
    color: Theme.deep
    height: 52
    property bool blocked: false

    Connections {
        target: Global
        function onChanged() { navigationBar.blocked = Global.value("veloguard_block_next") === true }
    }

    // A themed button: the primary (Next) one is filled cyan, like the theme's
    // active border; the others are outlined.
    component NavButton: Button {
        id: b
        property bool primary: false
        implicitHeight: 34
        leftPadding: 18; rightPadding: 18
        font.bold: primary
        contentItem: Label {
            text: b.text
            font: b.font
            color: !b.enabled ? "#4a5568" : (b.primary ? Theme.deep : Theme.fg)
            horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 6
            color: !b.enabled ? Theme.raised
                   : b.primary ? (b.down ? "#2bb3e0" : (b.hovered ? "#66d9ff" : Theme.accent))
                   : (b.down ? Theme.accent : (b.hovered ? Theme.raised : Theme.deep))
            border.width: 1
            border.color: !b.enabled ? Theme.raised : (b.primary || b.hovered ? Theme.accent : Theme.line)
        }
    }

    RowLayout {
        id: buttonBar
        anchors.fill: parent
        anchors.rightMargin: 12
        spacing: 8

        Item { Layout.fillWidth: true }

        NavButton {
            text: ViewManager.backLabel
            enabled: ViewManager.backEnabled
            visible: ViewManager.backAndNextVisible
            onClicked: ViewManager.back()
        }
        NavButton {
            primary: true
            text: ViewManager.nextLabel
            enabled: ViewManager.nextEnabled && !navigationBar.blocked
            visible: ViewManager.backAndNextVisible
            onClicked: ViewManager.next()
            Layout.rightMargin: 16
        }
        NavButton {
            text: ViewManager.quitLabel
            ToolTip.visible: hovered
            ToolTip.timeout: 5000
            ToolTip.delay: 1000
            ToolTip.text: ViewManager.quitTooltip
            enabled: ViewManager.quitEnabled
            visible: ViewManager.quitVisible
            onClicked: ViewManager.quit()
        }
    }
}
