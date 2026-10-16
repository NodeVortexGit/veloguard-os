/* VeloGuardOS — installation slideshow (slideshowAPI 1: started when the
 * install begins). Colours: theme.js, the default VeloGuard theme. */
import QtQuick 2.0
import calamares.slideshow 1.0
import "theme.js" as Theme

Presentation {
    id: presentation
    Timer { interval: 6000; running: true; repeat: true; onTriggered: presentation.goToNextSlide() }

    Slide {
        Rectangle { anchors.fill: parent; color: Theme.bg }
        Text {
            anchors.centerIn: parent; width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            color: Theme.fg; font.pixelSize: 24
            text: "VeloGuardOS — AI-first, and guarded.\nThe AI can run the machine; the guard keeps you in control."
        }
    }
    Slide {
        Rectangle { anchors.fill: parent; color: Theme.bg }
        Text {
            anchors.centerIn: parent; width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            color: Theme.accent; font.pixelSize: 24
            text: "Auto-VPN on untrusted Wi-Fi · honeypot + AI diagnosis · app sandbox · signed updates."
        }
    }
    Slide {
        Rectangle { anchors.fill: parent; color: Theme.bg }
        Text {
            anchors.centerIn: parent; width: parent.width * 0.8
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
            color: Theme.green; font.pixelSize: 24
            text: "Drivers for this machine are installing now — graphics, Wi-Fi, Bluetooth, laptop power and sensors."
        }
    }
}
