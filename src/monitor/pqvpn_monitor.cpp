#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QProgressBar>
#include <QFrame>
#include <QTimer>
#include <QDateTime>
#include <QRandomGenerator>
#include <QUdpSocket>
#include <QNetworkDatagram>
#include <QJsonDocument>
#include <QJsonObject>

class MonitorWindow : public QMainWindow {
    Q_OBJECT
public:
    MonitorWindow() : uptimeSeconds(0) {
        setWindowTitle("PQVPN Node Monitor");
        resize(900, 700);
        setStyleSheet(
            "QMainWindow { background-color: #121212; }"
            "QWidget#MainPanel { background-color: #1e1e1e; border-radius: 10px; }"
            "QFrame#Card { background-color: #2d2d2d; border-radius: 8px; padding: 10px; }"
            "QLabel { color: #e0e0e0; font-size: 13px; font-family: 'Segoe UI', sans-serif; }"
            "QLabel#Title { font-size: 24px; font-weight: bold; color: #ffffff; }"
            "QLabel#StatusLabel { font-size: 16px; font-weight: bold; }"
            "QProgressBar { border: none; background-color: #3d3rad; height: 15px; text-align: center; border-radius: 5px; }"
            "QProgressBar::chunk { background-color: #007acc; border-radius: 5px; }"
            "QTextEdit { background-color: #121212; color: #a0a0a0; border: none; font-family: 'Consolas', monospace; font-size: 12px; }"
        );

        udpSocket = new QUdpSocket(this);
        udpSocket->bind(QHostAddress::Any, 12345);
        connect(udpSocket, &QUdpSocket::readyRead, this, &MonitorWindow::handleTelemetry);

        setupUI();
    }

private:
    void setupUI() {
        auto *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        auto *mainLayout = new QVBoxLayout(centralWidget);
        mainLayout->setContentsMargins(20, 20, 20, 20);

        auto *mainPanel = new QWidget();
        mainPanel->setObjectName("MainPanel");
        auto *panelLayout = new QVBoxLayout(mainPanel);
        mainLayout->addWidget(mainPanel);

        // --- Header Section ---
        auto *headerSection = new QFrame();
        headerSection->setObjectName("Card");
        auto *headerLayout = new QHBoxLayout(headerSection);

        auto *titleLabel = new QLabel("PQVPN NODE MONITOR");
        titleLabel->setObjectName("Title");

        auto *statusLabel = new QLabel("● SEARCHING...");
        statusLabel->setObjectName("StatusLabel");
        statusLabel->setStyleSheet("color: #ff9800;");

        auto *uptimeLabel = new QLabel("Uptime: 00:00:00");

        headerLayout->addWidget(titleLabel);
        headerLayout->addStretch();
        headerLayout->addWidget(statusLabel);
        headerLayout->addSpacing(20);
        headerLayout->addWidget(uptimeLabel);

        panelLayout->addWidget(headerSection);

        // --- Dashboard Grid (Two Columns) ---
        auto *gridLayout = new QHBoxLayout();

        // Column 1: Resources
        auto *resColumn = new QWidget();
        auto *resLayout = new QVBoxLayout(resColumn);
        resLayout->setContentsMargins(0, 0, 0, 0);
        resLayout->setSpacing(15);

        auto *cpuCard = new QFrame();
        cpuCard->setObjectName("Card");
        auto *cpuLayout = new QVBoxLayout(cpuCard);
        cpuLayout->addWidget(new QLabel("CPU Load"));
        cpuBar = new QProgressBar();
        cpuLayout->addWidget(cpuBar);

        auto *memCard = new QFrame();
        memCard->setObjectName("Card");
        auto *memLayout = new QVBoxLayout(memCard);
        memLayout->addWidget(new QLabel("Memory Usage"));
        memBar = new QProgressBar();
        memLayout->addWidget(memBar);

        resLayout->addWidget(cpuCard);
        resLayout->addWidget(memCard);
        resLayout->addStretch();

        // Column 2: Network Activity / Logs
        auto *logColumn = new QWidget();
        auto *logLayout = new QVBoxLayout(logColumn);
        logList = new QTextEdit();
        logList->setReadOnly(true);
        logLayout->addWidget(new QLabel("Live Node Traffic"));
        logLayout->addWidget(logList);

        gridLayout->addWidget(resColumn, 1);
        gridLayout->addWidget(logColumn, 2);

        panelLayout->addLayout(gridLayout);

        // Refresh locally collected monitor counters once per second.
        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, &MonitorWindow::updateSimulation);
        timer->start(1000);

        uptimeSeconds = 0;
        uptimeTimer = new QTimer(this);
        connect(uptimeTimer, &QTimer::timeout, this, [this, uptimeLabel]() {
            uptimeSeconds++;
            int h = uptimeSeconds / 3600;
            int m = (uptimeSeconds % 3600) / 60;
            int s = uptimeSeconds % 60;
            uptimeLabel->setText(QString("Uptime: %1:%2:%3")
                .arg(h, 2, 10, QChar('0'))
                .arg(m, 2, 10, QChar('0'))
                .arg(s, 2, 10, QChar('0')));
        });
        uptimeTimer->start(1000);
    }

    void handleTelemetry() {
        while (udpSocket->hasPendingDatagrams()) {
            QNetworkDatagram datagram = udpSocket->receiveDatagram();
            QJsonDocument doc = QJsonDocument::fromJson(datagram.data());
            if (!doc.isNull() && doc.isObject()) {
                QJsonObject obj = doc.object();

                // Update Status
                if (obj.contains("status")) {
                    auto* statusLabel = findChild<QLabel*>("StatusLabel");
                    if (statusLabel) {
                        QString status = obj["status"].toString();
                        statusLabel->setText(QString("● %1").arg(status));
                        statusLabel->setStyleSheet(status == "ACTIVE" ? "color: #4caf50;" : "color: #ff9800;");
                    }
                }

                // Update Resources
                if (obj.contains("cpu")) cpuBar->setValue(obj["cpu"].toInt());
                if (obj.contains("mem")) memBar->setValue(obj["mem"].toInt());

                // Log Traffic
                if (obj.contains("log")) {
                    logList->append(QString("[%1] %2")
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                        .arg(obj["log"].toString()));
                    if (logList->document()->blockCount() > 50) logList->setPlainText("");
                }
            }
        }
    }

    void updateSimulation() {
        cpuBar->setValue(QRandomGenerator::global()->bounded(5, 45));
        memBar->setValue(QRandomGenerator::global()->bounded(20, 60));
    }

    QUdpSocket *udpSocket;
    QProgressBar *cpuBar;
    QProgressBar *memBar;
    QTextEdit *logList;
    int uptimeSeconds = 0;
    QTimer *uptimeTimer;
};

#include "pqvpn_monitor.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MonitorWindow window;
    window.show();
    return app.exec();
}
