pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    width: 430
    height: 860
    visible: true
    title: "PQVPN"
    color: "#080b17"
    property string cipher: "xchacha"
    property int page: 0
    property bool reduceMotion: false
    readonly property color cyan: "#65e6ff"
    readonly property color violet: "#724cff"
    readonly property color panel: "#11162a"
    readonly property color muted: "#a5aec8"

    function resetCurrentPageScroll() {
        const views = [routeView, commonsView, shieldView]
        views[root.page].contentItem.contentY = 0
    }
    onPageChanged: Qt.callLater(resetCurrentPageScroll)

    component Card: Rectangle {
        radius: 20
        color: root.panel
        border.color: "#2a355a"
        border.width: 1
    }

    component Pill: Button {
        id: control
        property bool selected: false
        implicitHeight: 48
        font.weight: Font.DemiBold
        contentItem: Text {
            text: control.text
            color: control.selected ? "white" : root.muted
            font: control.font
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 14
            color: control.selected ? root.violet : "#151b31"
            border.color: control.activeFocus ? root.cyan : control.selected ? "#9a82ff" : "#344064"
            border.width: control.activeFocus ? 2 : 1
            scale: control.down ? 0.97 : 1
            Behavior on scale { enabled: !root.reduceMotion; NumberAnimation { duration: 90 } }
        }
    }

    background: Rectangle {
        color: root.color
        Rectangle {
            width: parent.width * 1.3; height: width; radius: width / 2
            x: -width * 0.55; y: -height * 0.55
            color: "#382080"; opacity: 0.28
        }
        Rectangle {
            width: parent.width; height: width; radius: width / 2
            x: parent.width * 0.55; y: parent.height * 0.4
            color: "#057891"; opacity: 0.16
        }
    }

    header: ToolBar {
        z: 100
        height: 74
        background: Rectangle { color: "#0a0e1d"; opacity: 0.96 }
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 20; anchors.rightMargin: 20
            Rectangle {
                Layout.preferredWidth: 42; Layout.preferredHeight: 42; radius: 13
                color: root.violet; border.color: root.cyan
                Text { anchors.centerIn: parent; text: "◈"; color: "white"; font.pixelSize: 24; font.bold: true }
            }
            ColumnLayout {
                spacing: 0
                Text { text: "PQVPN"; color: "white"; font.pixelSize: 20; font.bold: true; font.letterSpacing: 2 }
                Text { text: "PRIVACY CONSOLE"; color: root.cyan; font.pixelSize: 10; font.bold: true; font.letterSpacing: 1.5 }
            }
            Item { Layout.fillWidth: true }
            Rectangle {
                implicitWidth: 86; implicitHeight: 30; radius: 15
                color: "#2b203f"; border.color: "#8e72ff"
                Text { anchors.centerIn: parent; text: "OFFLINE"; color: "#d7c9ff"; font.pixelSize: 11; font.bold: true }
            }
        }
    }

    footer: TabBar {
        id: navigation
        z: 100
        height: 64
        currentIndex: root.page
        onCurrentIndexChanged: root.page = currentIndex
        background: Rectangle { color: "#0a0e1d"; border.color: "#202946" }
        Repeater {
            model: ["Route", "StrangeNet", "Shield"]
            TabButton {
                id: tabButton
                required property string modelData
                height: navigation.height
                text: modelData
                contentItem: Text {
                    text: parent.text
                    color: parent.checked ? root.cyan : root.muted
                    font.pixelSize: 12; font.bold: parent.checked
                    horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle { color: "transparent"; Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 3; color: parent.parent.checked ? root.cyan : "transparent" } }
            }
        }
    }

    SwipeView {
        anchors.fill: parent
        focus: true
        currentIndex: root.page
        onCurrentIndexChanged: root.page = currentIndex
        clip: true

        ScrollView {
            id: routeView
            contentWidth: availableWidth
            ColumnLayout {
                x: 20
                width: parent.width - 40
                spacing: 16
                Item { Layout.preferredHeight: 2 }
                Text { text: "Connection settings"; color: "white"; font.pixelSize: 28; font.bold: true; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                Text { text: "Select an encryption profile before connecting."; color: root.muted; font.pixelSize: 14; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                CheckBox {
                    id: reduceMotionControl
                    text: "Reduce motion"
                    checked: root.reduceMotion
                    onToggled: root.reduceMotion = checked
                    Accessible.name: "Reduce interface motion"
                    contentItem: Text {
                        leftPadding: reduceMotionControl.indicator.width + 12
                        text: reduceMotionControl.text
                        color: "white"
                        font.pixelSize: 14
                        verticalAlignment: Text.AlignVCenter
                    }
                    indicator: Rectangle {
                        implicitWidth: 24; implicitHeight: 24; radius: 7
                        y: (reduceMotionControl.height - height) / 2
                        color: reduceMotionControl.checked ? root.violet : "#151b31"
                        border.color: reduceMotionControl.activeFocus ? root.cyan : "#526184"
                        border.width: reduceMotionControl.activeFocus ? 2 : 1
                        Text { anchors.centerIn: parent; text: "✓"; visible: reduceMotionControl.checked; color: "white"; font.bold: true }
                    }
                }

                Card {
                    Layout.fillWidth: true; implicitHeight: cryptoColumn.implicitHeight + 40
                    ColumnLayout {
                        id: cryptoColumn; anchors.fill: parent; anchors.margins: 20; spacing: 12
                        Text { text: "CIPHER PROFILE"; color: root.cyan; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1.5 }
                        RowLayout {
                            Layout.fillWidth: true; spacing: 10
                            Pill { text: "Blue · AES-GCM"; selected: root.cipher === "aes"; Layout.fillWidth: true; onClicked: root.cipher = "aes" }
                            Pill { text: "Red · XChaCha20"; selected: root.cipher === "xchacha"; Layout.fillWidth: true; onClicked: root.cipher = "xchacha" }
                        }
                        Text {
                            Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.muted; font.pixelSize: 13
                            text: root.cipher === "aes" ? "Uses hardware AES acceleration when available." : "Software profile with an extended nonce size."
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true; implicitHeight: routeColumn.implicitHeight + 42
                    gradient: Gradient { GradientStop { position: 0; color: "#4d2bbb" } GradientStop { position: 1; color: "#087e96" } }
                    ColumnLayout {
                        id: routeColumn; anchors.fill: parent; anchors.margins: 22; spacing: 9
                        Text { text: "ROUTE STATE"; color: "#c7f8ff"; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1.5 }
                        Text { text: "Not connected"; color: "white"; font.pixelSize: 23; font.bold: true; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                        Text { text: "Local tunnel checks have not completed."; color: "#e2e6ff"; font.pixelSize: 13; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                        Pill { text: "Connection disabled"; enabled: false; Layout.fillWidth: true }
                    }
                }
                Item { Layout.preferredHeight: 20 }
            }
        }

        ScrollView {
            id: commonsView
            contentWidth: availableWidth
            ColumnLayout {
                x: 20; width: parent.width - 40; spacing: 16
                Item { Layout.preferredHeight: 2 }
                Text { text: "StrangeNet Commons"; color: "white"; font.pixelSize: 28; font.bold: true }
                Text { text: "Participants are identified by Peer ID. Network addresses are not displayed."; color: root.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                Card {
                    Layout.fillWidth: true; implicitHeight: 270
                    Rectangle { anchors.fill: parent; anchors.margins: 14; radius: 14; color: "#18203a" }
                    GridLayout {
                        anchors.fill: parent; anchors.margins: 28; columns: 2; rowSpacing: 14; columnSpacing: 14
                        Repeater {
                            model: ["Gateway", "Transit Lab", "Poetry", "Commons"]
                            Rectangle {
                                Layout.fillWidth: true; Layout.fillHeight: true; radius: 12
                                color: index === 3 ? root.violet : "#263455"; border.color: index === 3 ? root.cyan : "#465a89"
                                Text { anchors.centerIn: parent; text: modelData; color: "white"; font.bold: true }
                            }
                        }
                    }
                }
                Text { text: "Messaging remains disabled until the transport can authenticate peers end to end."; color: root.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                Card {
                    Layout.fillWidth: true; implicitHeight: researchSemantics.implicitHeight + 36
                    ColumnLayout {
                        id: researchSemantics; anchors.fill: parent; anchors.margins: 18; spacing: 7
                        Text { text: "RESEARCH REVIEW"; color: root.cyan; font.pixelSize: 11; font.bold: true }
                        Text { text: "Formal logic check · automated · no scientific verdict"; color: "white" }
                        Text { text: "Peer review · support / challenge / abstain"; color: root.muted }
                        Text { text: "User decision · private and local"; color: root.muted }
                        Text { text: "BOINC evidence · validation pending"; color: root.muted }
                        Text { text: "Ledger entry · requires project proof and quorum"; color: root.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                    }
                }
            }
        }

        ScrollView {
            id: shieldView
            contentWidth: availableWidth
            ColumnLayout {
                x: 20; width: parent.width - 40; spacing: 16
                Item { Layout.preferredHeight: 2 }
                Text { text: "Shield"; color: "white"; font.pixelSize: 28; font.bold: true }
                Text { text: "Aggregate status. No query history is shown."; color: root.muted }
                Card {
                    Layout.fillWidth: true; implicitHeight: 104
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 18; spacing: 6
                        Text { text: "CUSTOM · LOCAL ONLY"; color: root.cyan; font.pixelSize: 11; font.bold: true }
                        Text { text: "Off on the exit + your blocklist files and domain rules"; color: "white"; font.pixelSize: 15; font.bold: true }
                        Text { text: "Files and rules stay on this device and are never sent to Pi-hole."; color: root.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                    }
                }
                Repeater {
                    model: [
                        { title: "Malware", detail: "Blocklist policy staged" },
                        { title: "Child safety", detail: "No query history exposed" },
                        { title: "Privacy", detail: "OISD + curated regex profiles" }
                    ]
                    Card {
                        Layout.fillWidth: true; implicitHeight: 86
                        RowLayout {
                            anchors.fill: parent; anchors.margins: 18
                            Rectangle { width: 42; height: 42; radius: 14; color: "#163b42"; Text { anchors.centerIn: parent; text: "◆"; color: root.cyan; font.pixelSize: 20 } }
                            ColumnLayout {
                                Text { text: modelData.title; color: "white"; font.pixelSize: 17; font.bold: true }
                                Text { text: modelData.detail; color: root.muted; font.pixelSize: 12 }
                            }
                            Item { Layout.fillWidth: true }
                            Text { text: "NOT ACTIVE"; color: "#d7c9ff"; font.pixelSize: 10; font.bold: true }
                        }
                    }
                }
            }
        }
    }
}
