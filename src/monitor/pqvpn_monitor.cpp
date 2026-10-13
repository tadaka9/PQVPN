#include <QAbstractAnimation>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QEasingCurve>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QSaveFile>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStackedLayout>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QSysInfo>
#include <QSystemTrayIcon>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>

#include <cmath>

namespace {
enum Page { Overview, Connection, Transports, StrangeNet, Activity, Privacy, About };

const char* theme = R"CSS(
* { font-family: "Inter", "SF Pro Display", "Segoe UI", sans-serif; }
QMainWindow, QDialog { background: #080b17; color: #f8f9ff; }
QMenuBar { background: #080b17; color: #aeb7d4; border-bottom: 1px solid rgba(255,255,255,.09); padding: 4px; }
QMenuBar::item { padding: 7px 12px; border-radius: 7px; }
QMenuBar::item:selected { background: #724cff; color: white; }
QMenu { background: #11162a; color: white; border: 1px solid #293252; padding: 7px; }
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 6px; }
QMenu::item:selected { background: #724cff; }
#sidebar { background: rgba(7,10,24,.96); border-right: 1px solid rgba(255,255,255,.08); }
#wordmark { font-size: 21px; font-weight: 850; letter-spacing: 3px; color: white; }
#brandSub { color: #65e6ff; font-size: 10px; font-weight: 750; letter-spacing: 2px; }
#pageTitle { font-size: 34px; font-weight: 820; color: white; }
#pageSubtitle { color: #a5aec8; font-size: 14px; }
#heroTitle { font-size: 38px; font-weight: 850; color: white; }
#sectionTitle { font-size: 17px; font-weight: 760; color: white; }
#metric { font-size: 23px; font-weight: 820; color: white; }
#eyebrow { color: #7cecff; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
QPushButton[nav="true"] { background: transparent; color: #8994b7; border: 0; border-radius: 10px; padding: 13px 14px; text-align: left; font-weight: 680; }
QPushButton[nav="true"]:hover { background: rgba(101,230,255,.10); color: white; }
QPushButton[nav="true"]:checked { background: rgba(114,76,255,.28); color: white; border: 1px solid rgba(146,117,255,.50); }
QFrame[card="true"] { background: rgba(15,21,43,.92); border: 1px solid rgba(142,162,221,.18); border-radius: 16px; }
QFrame[accent="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5432c9,stop:.52 #824cff,stop:1 #0fa9cb); border: 1px solid rgba(255,255,255,.22); border-radius: 20px; }
QLabel[muted="true"] { color: #9ba6c7; }
QLabel[chip="true"] { background: rgba(101,230,255,.10); color: #a5f3ff; border: 1px solid rgba(101,230,255,.28); border-radius: 11px; padding: 4px 10px; font-size: 11px; font-weight: 700; }
QLineEdit, QComboBox, QPlainTextEdit, QListWidget { background: rgba(6,10,25,.82); color: #f4f6ff; border: 1px solid #303a60; border-radius: 10px; padding: 10px; selection-background-color: #724cff; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus { border-color: #65e6ff; }
QComboBox::drop-down { border: 0; width: 28px; }
QComboBox QAbstractItemView { background: #11162a; color: white; border: 1px solid #354064; selection-background-color: #724cff; }
QPushButton { background: #724cff; color: white; border: 1px solid #8e72ff; border-radius: 10px; padding: 11px 17px; font-weight: 760; }
QPushButton:hover { background: #825eff; }
QPushButton:pressed { background: #5e3bd8; }
QPushButton:disabled { background: #252a41; color: #68718f; border-color: #30364e; }
QPushButton[quiet="true"] { background: rgba(255,255,255,.04); color: #b9c2df; border-color: #343d61; }
QPushButton[danger="true"] { background: #d94172; border-color: #ff6494; }
QCheckBox { color: #ced5ea; spacing: 9px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #586488; border-radius: 5px; background: #0b1022; }
QCheckBox::indicator:checked { background: #65e6ff; border-color: #65e6ff; }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #465174; border-radius: 4px; min-height: 28px; }
QStatusBar { background: #080b17; color: #8f9aba; border-top: 1px solid rgba(255,255,255,.08); }
QToolTip { background: #65e6ff; color: #07101d; border: 0; padding: 6px; }
)CSS";

QLabel* text(const QString& value, const char* id = nullptr) {
    auto* result = new QLabel(value);
    if (id) result->setObjectName(id);
    result->setWordWrap(true);
    return result;
}
QFrame* card(QLayout* layout, bool accent = false) {
    auto* result = new QFrame;
    result->setProperty(accent ? "accent" : "card", true);
    result->setLayout(layout);
    return result;
}
QString stateName(QProcess::ProcessState state) {
    if (state == QProcess::Running) return "Protected";
    if (state == QProcess::Starting) return "Starting";
    return "Disconnected";
}
}

class Aurora final : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal phase READ phase WRITE setPhase)
public:
    explicit Aurora(QWidget* parent = nullptr) : QWidget(parent) { setAttribute(Qt::WA_TransparentForMouseEvents); }
    qreal phase() const { return phase_; }
    void setPhase(qreal value) { phase_ = value; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), QColor("#080b17"));
        const qreal extent = std::max(width(), height()) * .48;
        const QPointF points[] = {{width() * (.12 + .04 * std::sin(phase_)), height() * .17},
            {width() * (.80 + .05 * std::cos(phase_ * .8)), height() * .25},
            {width() * (.55 + .05 * std::sin(phase_ * .6)), height() * .84}};
        const QColor colors[] = {QColor(80,43,220,78), QColor(0,201,231,54), QColor(217,65,171,42)};
        for (int i = 0; i < 3; ++i) {
            QRadialGradient gradient(points[i], extent);
            gradient.setColorAt(0, colors[i]); gradient.setColorAt(1, QColor(0,0,0,0));
            painter.setPen(Qt::NoPen); painter.setBrush(gradient);
            painter.drawEllipse(points[i], extent, extent);
        }
    }
private:
    qreal phase_ = 0;
};

class StatusOrb final : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal pulse READ pulse WRITE setPulse)
public:
    StatusOrb() { setFixedSize(112,112); }
    qreal pulse() const { return pulse_; }
    void setPulse(qreal value) { pulse_ = value; update(); }
    void setConnected(bool value) { connected_ = value; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this); painter.setRenderHint(QPainter::Antialiasing);
        const QPointF center(width()/2.0, height()/2.0);
        const QColor color = connected_ ? QColor("#65e6ff") : QColor("#ff7aac");
        painter.setPen(QPen(QColor(color.red(),color.green(),color.blue(),int(80*(1-pulse_))),2));
        painter.setBrush(Qt::NoBrush); painter.drawEllipse(center,34+pulse_*17,34+pulse_*17);
        QRadialGradient glow(center,34); glow.setColorAt(0,color.lighter(140)); glow.setColorAt(.52,color); glow.setColorAt(1,QColor(color.red(),color.green(),color.blue(),12));
        painter.setPen(Qt::NoPen); painter.setBrush(glow); painter.drawEllipse(center,29,29);
        painter.setBrush(Qt::white); painter.drawEllipse(center,7,7);
    }
private:
    qreal pulse_ = 0;
    bool connected_ = false;
};

class Window final : public QMainWindow {
    Q_OBJECT
public:
    Window() {
        setWindowTitle("PQVPN");
        setWindowIcon(QIcon(":/brand/logo.svg"));
        setMinimumSize(940,650); resize(1240,800); setAcceptDrops(true);
        process_.setProcessChannelMode(QProcess::MergedChannels);
        buildMenus(); buildUi(); buildTray(); connectProcess(); applyPreferences(); loadConfig(configPath_->text());
        statusBar()->showMessage("Ready — no connection starts without your action");
        QTimer::singleShot(0,this,[this]{ if(!configValid_ && !QApplication::arguments().contains("--smoke-test")) validateConfig(false); });
    }
    void prepareSmokePage(const QString& request) {
        QSignalBlocker guard(reduceMotion_); reduceMotion_->setChecked(true); setMotion(false);
        const QHash<QString,int> pages{{"connection",Connection},{"transports",Transports},{"strangenet",StrangeNet},{"activity",Activity},{"privacy",Privacy},{"about",About}};
        switchPage(pages.value(request,Overview)); QApplication::processEvents();
    }
protected:
    void closeEvent(QCloseEvent* event) override {
        if (!quitting_ && minimizeToTray_->isChecked() && tray_->isVisible()) {
            hide(); event->ignore();
            if (!trayNoticeShown_) { tray_->showMessage("PQVPN is still available", "The console was minimized to the tray. Connection state did not change.", QSystemTrayIcon::Information, 4000); trayNoticeShown_=true; }
            return;
        }
        if (process_.state()!=QProcess::NotRunning) {
            pendingQuit_=true; requestStop(); event->ignore(); return;
        }
        savePreferences(); event->accept(); QTimer::singleShot(0,qApp,&QCoreApplication::quit);
    }
    void dragEnterEvent(QDragEnterEvent* event) override {
        if (event->mimeData()->hasUrls() && event->mimeData()->urls().size()==1 && event->mimeData()->urls().constFirst().toLocalFile().endsWith(".json",Qt::CaseInsensitive)) event->acceptProposedAction();
    }
    void dropEvent(QDropEvent* event) override {
        const QString path=event->mimeData()->urls().constFirst().toLocalFile();
        if (loadConfig(path)) { configPath_->setText(path); log("Configuration selected · "+QDir::toNativeSeparators(path)); event->acceptProposedAction(); }
    }
private:
    QProcess process_;
    QStackedWidget* pages_=nullptr; QWidget* sidebar_=nullptr; QWidget* brandWords_=nullptr;
    Aurora* aurora_=nullptr; StatusOrb* orb_=nullptr; QPropertyAnimation *auroraAnimation_=nullptr,*pulseAnimation_=nullptr;
    QHash<int,QPushButton*> pageButtons_; QList<QPushButton*> navButtons_;
    QLineEdit *configPath_=nullptr,*executablePath_=nullptr; QComboBox *logLevel_=nullptr,*adaptiveMode_=nullptr; QCheckBox* noTunnel_=nullptr;
    QPushButton *connectButton_=nullptr,*validateButton_=nullptr; QLabel *stateLabel_=nullptr,*statusText_=nullptr,*endpointMetric_=nullptr,*verificationMetric_=nullptr,*shapingMetric_=nullptr,*mainnetMetric_=nullptr,*tunnelMetric_=nullptr,*egressMetric_=nullptr,*transportMetric_=nullptr,*transportDetails_=nullptr,*configHealth_=nullptr;
    QCheckBox* adaptiveEnabled_=nullptr; QLabel* adaptiveMetric_=nullptr; QPushButton* saveTransportButton_=nullptr;
    QLineEdit *strangeRoom_=nullptr,*strangeMessage_=nullptr;
    QComboBox* strangeAudience_=nullptr; QListWidget* peerDirectory_=nullptr;
    QTextBrowser* strangeTranscript_=nullptr; QPushButton *strangeJoin_=nullptr,*strangeSend_=nullptr,*strangeSticker_=nullptr,*strangeReaction_=nullptr; QLabel *strangeBytes_=nullptr,*peerCount_=nullptr;
    QPlainTextEdit* activity_=nullptr; QAction *reduceMotion_=nullptr,*compactSidebar_=nullptr,*minimizeToTray_=nullptr,*strangeNotifications_=nullptr;
    QSystemTrayIcon* tray_=nullptr; QMenu* trayMenu_=nullptr; QAction *trayStatus_=nullptr,*trayToggle_=nullptr;
    QByteArray processBuffer_;
    QByteArray validatedConfigHash_,validatedExecutableHash_;
    QString lastStrangeSender_,activeStrangePeer_="auto";QHash<QString,QString> authenticatedPeers_;qulonglong lastStrangeSequence_=0;int unreadStrange_=0;qint64 lastStrangeNotificationMs_=0;
    bool configValid_=false,stopping_=false,quitting_=false,pendingQuit_=false,trayNoticeShown_=false,strangeActive_=false,mainnetReady_=false,tunnelReady_=false,pendingStrangeJoin_=false;

    void refreshConnectionPresentation() {
        const bool active=process_.state()!=QProcess::NotRunning;
        const bool relay=noTunnel_&&noTunnel_->isChecked();
        QString title="Disconnected", detail="Disconnected. No node process is running from this console.";
        bool protectedPath=false;
        if(active&&!mainnetReady_){title="Connecting";detail="Negotiating an authenticated mainnet session…";}
        else if(active&&mainnetReady_&&relay){title="Mainnet connected · relay mode";detail="Authenticated peer ready. Local system traffic is not routed through PQVPN.";}
        else if(active&&mainnetReady_&&!tunnelReady_){title="Peer ready · securing routes";detail="The peer is authenticated; waiting for the operating-system tunnel and fail-closed routes.";}
        else if(active&&mainnetReady_&&tunnelReady_){title="Protected";detail="Authenticated peer, tunnel adapter and leak-safe routes are ready.";protectedPath=true;}
        stateLabel_->setText(title);statusText_->setText(detail);orb_->setConnected(protectedPath);
        trayStatus_->setText(title);tray_->setToolTip("PQVPN · "+title);
    }
    QByteArray fileFingerprint(const QString& path) const {
        QFile file(path);if(!file.open(QIODevice::ReadOnly))return {};
        QCryptographicHash hash(QCryptographicHash::Sha256);
        while(!file.atEnd())hash.addData(file.read(1024*1024));
        return hash.result();
    }
    void captureBoundedOutput(QProcess* child) {
        child->setProperty("pqvpnOutput",QByteArray{});
        connect(child,&QProcess::readyReadStandardOutput,child,[child]{
            QByteArray output=child->property("pqvpnOutput").toByteArray();output.append(child->readAllStandardOutput());
            if(output.size()>1024*1024)output=QByteArray("[earlier output discarded]\n")+output.right(1024*1024);
            child->setProperty("pqvpnOutput",output);
        });
    }

    void buildMenus() {
        auto* file=menuBar()->addMenu("File"); file->addAction("Choose configuration…",QKeySequence::Open,this,&Window::chooseConfig); file->addAction("Validate configuration",QKeySequence("Ctrl+Shift+V"),this,&Window::validateConfig); file->addSeparator(); file->addAction("Exit PQVPN",QKeySequence::Quit,this,&Window::quitApplication);
        auto* view=menuBar()->addMenu("View"); reduceMotion_=view->addAction("Reduce motion"); reduceMotion_->setCheckable(true); compactSidebar_=view->addAction("Compact sidebar"); compactSidebar_->setCheckable(true); minimizeToTray_=view->addAction("Close window to tray"); minimizeToTray_->setCheckable(true); minimizeToTray_->setChecked(true);strangeNotifications_=view->addAction("Private StrangeNet notifications");strangeNotifications_->setCheckable(true);strangeNotifications_->setChecked(true);
        connect(reduceMotion_,&QAction::toggled,this,[this](bool checked){QSettings("PQVPN","Privacy Console").setValue("reduceMotion",checked);setMotion(!checked);});
        connect(compactSidebar_,&QAction::toggled,this,&Window::setSidebarCompact);
        connect(minimizeToTray_,&QAction::toggled,this,[](bool checked){QSettings("PQVPN","Privacy Console").setValue("minimizeToTray",checked);});
        connect(strangeNotifications_,&QAction::toggled,this,[](bool checked){QSettings("PQVPN","Privacy Console").setValue("strangeNotifications",checked);});
        auto* tools=menuBar()->addMenu("Tools"); tools->addAction("Command palette…",QKeySequence("Ctrl+K"),this,&Window::showCommandPalette); tools->addAction("Copy diagnostics",QKeySequence("Ctrl+Shift+C"),this,&Window::copyDiagnostics);
    }
    void buildUi() {
        auto* root=new QWidget; auto* stack=new QStackedLayout(root); stack->setStackingMode(QStackedLayout::StackAll); aurora_=new Aurora;
        auto* shell=new QWidget; auto* row=new QHBoxLayout(shell); row->setContentsMargins(0,0,0,0); row->setSpacing(0); buildSidebar(row);
        pages_=new QStackedWidget; pages_->setStyleSheet("background:transparent"); pages_->addWidget(buildOverview()); pages_->addWidget(buildConnection()); pages_->addWidget(buildTransports()); pages_->addWidget(buildStrangeNet()); pages_->addWidget(buildActivity()); pages_->addWidget(buildPrivacy()); pages_->addWidget(buildAbout()); auto* pageScroll=new QScrollArea;pageScroll->setFrameShape(QFrame::NoFrame);pageScroll->setWidgetResizable(true);pageScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);pageScroll->setWidget(pages_);row->addWidget(pageScroll,1);
        stack->addWidget(aurora_); stack->addWidget(shell); stack->setCurrentWidget(shell); setCentralWidget(root); switchPage(Overview); setMotion(true);
    }
    void buildSidebar(QHBoxLayout* shell) {
        sidebar_=new QWidget; sidebar_->setObjectName("sidebar"); sidebar_->setMinimumWidth(238); sidebar_->setMaximumWidth(238);
        auto* layout=new QVBoxLayout(sidebar_); layout->setContentsMargins(18,24,18,20); layout->setSpacing(8);
        auto* brand=new QHBoxLayout; auto* icon=new QLabel; icon->setPixmap(QIcon(":/brand/logo.svg").pixmap(46,46)); brandWords_=new QWidget; auto* words=new QVBoxLayout(brandWords_); words->setContentsMargins(0,0,0,0); words->setSpacing(0); words->addWidget(text("PQVPN","wordmark")); words->addWidget(text("PRIVACY CONSOLE","brandSub")); brand->addWidget(icon); brand->addWidget(brandWords_,1); layout->addLayout(brand); layout->addSpacing(24);
        auto* group=new QButtonGroup(this); group->setExclusive(true); const QList<QPair<QString,int>> items{{"Overview",Overview},{"Connect",Connection},{"Transports",Transports},{"StrangeNet",StrangeNet},{"Activity",Activity},{"Privacy",Privacy},{"About",About}};
        for (const auto& [name,page]:items) { auto* button=new QPushButton(QString("%1   %2").arg(page+1,2,10,QChar('0')).arg(name)); button->setProperty("fullText",button->text()); button->setProperty("nav",true); button->setCheckable(true); group->addButton(button,page); pageButtons_[page]=button; navButtons_.append(button); layout->addWidget(button); connect(button,&QPushButton::clicked,this,[this,page]{switchPage(page);}); }
        layout->addStretch(); auto* ethics=text("YOU CHOOSE WHEN TO CONNECT\nNO TRACKING · NO DARK PATTERNS"); ethics->setObjectName("eyebrow"); layout->addWidget(ethics); shell->addWidget(sidebar_);
    }
    QWidget* pageShell(const QString& title,const QString& subtitle,QVBoxLayout** body) { auto* page=new QWidget; auto* outer=new QVBoxLayout(page); outer->setContentsMargins(34,28,34,28); outer->setSpacing(18); outer->addWidget(text(title,"pageTitle")); outer->addWidget(text(subtitle,"pageSubtitle")); *body=outer; return page; }
    QLabel* metric(const QString& title,const QString& value,QHBoxLayout* row) { auto* layout=new QVBoxLayout; layout->setContentsMargins(20,18,20,18); layout->addWidget(text(title,"eyebrow")); auto* result=text(value,"metric"); layout->addWidget(result); row->addWidget(card(layout),1); return result; }
    QWidget* buildOverview() {
        QVBoxLayout* body; auto* page=pageShell("Your private route, at a glance","Real state only. Nothing connects or changes routes until you ask.",&body);
        auto* hero=new QHBoxLayout; hero->setContentsMargins(28,25,28,25); auto* copy=new QVBoxLayout; copy->addWidget(text("POST-QUANTUM PRIVACY","eyebrow")); stateLabel_=text("Disconnected","heroTitle"); copy->addWidget(stateLabel_); statusText_=text("Choose a configuration, validate it, then connect when you are ready."); statusText_->setProperty("muted",true); copy->addWidget(statusText_); auto* open=new QPushButton("Review connection"); connect(open,&QPushButton::clicked,this,[this]{switchPage(Connection);}); copy->addWidget(open,0,Qt::AlignLeft); hero->addLayout(copy,1); orb_=new StatusOrb; hero->addWidget(orb_,0,Qt::AlignCenter); body->addWidget(card(hero,true));
        auto* metrics=new QHBoxLayout; mainnetMetric_=metric("MAINNET BOOTSTRAP","Not loaded",metrics); endpointMetric_=metric("LOCAL LISTENER","Not loaded",metrics); verificationMetric_=metric("PEER POLICY","Unknown",metrics); body->addLayout(metrics);
        auto* capabilities=new QHBoxLayout; tunnelMetric_=metric("TUNNEL BOUNDARY","Unknown",capabilities); egressMetric_=metric("EXIT MODE","Off",capabilities); shapingMetric_=metric("TRAFFIC SHAPING","Off",capabilities); body->addLayout(capabilities);
        auto* explain=new QVBoxLayout; explain->setContentsMargins(22,20,22,20); explain->addWidget(text("Your path to a working session","sectionTitle")); explain->addWidget(text("01  Validate the same configuration the node will run.\n02  Start the native tunnel boundary and contact a declared bootstrap peer.\n03  Wait for the hybrid peer session; only then does the console show Mainnet connected.\n04  Use the tunnel and StrangeNet on that one authenticated session.")); auto* note=text("Every state comes from the node. Traffic shaping changes encrypted packet size and timing; it does not promise invisibility."); note->setProperty("muted",true); explain->addWidget(note); body->addWidget(card(explain)); body->addStretch(); return page;
    }
    QWidget* buildConnection() {
        QVBoxLayout* body; auto* page=pageShell("Connect","A short, reversible flow with validation before execution.",&body); auto* form=new QVBoxLayout; form->setContentsMargins(23,21,23,21); form->setSpacing(12);
        auto* journey=new QHBoxLayout;journey->setSpacing(10);journey->addWidget(capability("01 · CONFIGURE","Choose node + policy","Local",true),1);journey->addWidget(capability("02 · VERIFY","Real node validation","Required",true),1);journey->addWidget(capability("03 · CONNECT","Hybrid mainnet session","Observed",true),1);journey->addWidget(capability("04 · USE","Tunnel + StrangeNet","One session",true),1);body->addLayout(journey);
        form->addWidget(text("CONFIGURATION","eyebrow")); auto* cr=new QHBoxLayout; configPath_=new QLineEdit(QDir::current().absoluteFilePath("config.json")); auto* cb=new QPushButton("Choose…"); cb->setProperty("quiet",true); cr->addWidget(configPath_,1); cr->addWidget(cb); form->addLayout(cr);
        form->addWidget(text("NODE EXECUTABLE","eyebrow")); auto* er=new QHBoxLayout; executablePath_=new QLineEdit(defaultExecutable()); auto* eb=new QPushButton("Choose…"); eb->setProperty("quiet",true); er->addWidget(executablePath_,1); er->addWidget(eb); form->addLayout(er);
        auto* options=new QHBoxLayout; options->addWidget(text("LOG DETAIL","eyebrow")); logLevel_=new QComboBox; logLevel_->addItems({"info","debug","warning","error"}); options->addWidget(logLevel_);
        noTunnel_=new QCheckBox("Relay / exit only (no local tunnel)"); noTunnel_->setToolTip("Run the authenticated node without the operating-system tunnel boundary. Mainnet and StrangeNet still work, but local system traffic is not tunneled."); noTunnel_->setChecked(false); options->addWidget(noTunnel_);
        options->addStretch(); form->addLayout(options); configHealth_=text("Configuration has not been validated."); configHealth_->setProperty("muted",true); form->addWidget(configHealth_); body->addWidget(card(form));
        auto* utilities=new QHBoxLayout;auto* inspect=new QPushButton("Inspect system");inspect->setProperty("quiet",true);auto* normalized=new QPushButton("Review normalized config");normalized->setProperty("quiet",true);utilities->addWidget(inspect);utilities->addWidget(normalized);utilities->addStretch();form->addLayout(utilities);
        auto* actions=new QHBoxLayout; validateButton_=new QPushButton("Validate first"); validateButton_->setProperty("quiet",true); connectButton_=new QPushButton("Connect securely"); connectButton_->setEnabled(false); actions->addWidget(validateButton_); actions->addStretch(); actions->addWidget(connectButton_); body->addLayout(actions); auto* consent=text("Starting may create a tunnel adapter or change routes according to your configuration and OS permissions. Closing the window can keep PQVPN in the tray without changing the connection."); consent->setProperty("muted",true); body->addWidget(consent); body->addStretch();
        connect(cb,&QPushButton::clicked,this,&Window::chooseConfig); connect(eb,&QPushButton::clicked,this,&Window::chooseExecutable); connect(validateButton_,&QPushButton::clicked,this,&Window::validateConfig); connect(connectButton_,&QPushButton::clicked,this,&Window::toggleConnection);connect(inspect,&QPushButton::clicked,this,[this]{runNodeTool({"--platform-info"},"System inspection");});connect(normalized,&QPushButton::clicked,this,[this]{runNodeTool({"--print-config","--config",configPath_->text()},"Normalized configuration");});
        connect(configPath_,&QLineEdit::textChanged,this,[this](const QString& path){invalidate("Configuration changed. Validate before connecting.");loadConfig(path);}); connect(executablePath_,&QLineEdit::textChanged,this,[this]{invalidate("Executable changed. Validate before connecting.");}); connect(noTunnel_,&QCheckBox::toggled,this,[this]{invalidate("Connection mode changed. Validate before connecting.");loadConfig(configPath_->text());}); return page;
    }
    QFrame* capability(const QString& name,const QString& kind,const QString& status,bool available) { auto* layout=new QVBoxLayout; layout->setContentsMargins(17,17,17,17); layout->addWidget(text(name,"sectionTitle")); auto* type=text(kind); type->setProperty("muted",true); layout->addWidget(type); auto* chip=text(available?status:"Not integrated · "+status); chip->setProperty("chip",true); layout->addWidget(chip,0,Qt::AlignLeft); layout->addStretch(); return card(layout); }
    QWidget* buildTransports() {
        QVBoxLayout* body; auto* page=pageShell("Transports","Capabilities read from configuration — no implied support.",&body); auto* current=new QVBoxLayout; current->setContentsMargins(23,21,23,21); current->addWidget(text("SELECTED OUTER PATH","eyebrow")); transportMetric_=text("Direct PQVPN UDP","heroTitle"); current->addWidget(transportMetric_); transportDetails_=text("Load a configuration to inspect its transport constraints."); transportDetails_->setProperty("muted",true); current->addWidget(transportDetails_); body->addWidget(card(current,true));
        auto* adaptive=new QVBoxLayout; adaptive->setContentsMargins(20,18,20,18); adaptive->addWidget(text("PQTP ADAPTIVE PATH","eyebrow")); adaptiveMetric_=text("Disabled","sectionTitle"); adaptive->addWidget(adaptiveMetric_); auto* adaptiveRow=new QHBoxLayout; adaptiveEnabled_=new QCheckBox("Enable automatic UDP/TCP failover"); adaptiveMode_=new QComboBox; adaptiveMode_->addItem("Automatic · prefer UDP", "auto"); adaptiveMode_->addItem("UDP only", "udp"); adaptiveMode_->addItem("TCP only", "tcp"); saveTransportButton_=new QPushButton("Save transport policy"); saveTransportButton_->setProperty("quiet",true); adaptiveRow->addWidget(adaptiveEnabled_); adaptiveRow->addWidget(adaptiveMode_); adaptiveRow->addStretch(); adaptiveRow->addWidget(saveTransportButton_); adaptive->addLayout(adaptiveRow); auto* adaptiveCopy=text("Automatic mode preserves the authenticated PQVPN frame, uses UDP for low latency, falls back to TCP after measured loss, jitter or blocking, and probes UDP before returning."); adaptiveCopy->setProperty("muted",true); adaptive->addWidget(adaptiveCopy); body->addWidget(card(adaptive)); connect(saveTransportButton_,&QPushButton::clicked,this,&Window::saveTransportSettings);
        auto* grid=new QHBoxLayout; grid->addWidget(capability("udp2raw","External UDP forwarder","Attach mode",true),1); grid->addWidget(capability("obfs4","External SOCKS transport","TCP relay required",false),1); grid->addWidget(capability("Xray / V2Ray","External SOCKS transport","TCP relay required",false),1); grid->addWidget(capability("Shadowsocks","External SOCKS transport","TCP relay required",false),1); body->addLayout(grid); auto* truth=text("Available means the PQVPN adapter exists. It does not prove an external engine is installed, running or interoperable; the authenticated handshake remains the runtime check."); truth->setProperty("muted",true); body->addWidget(truth); body->addStretch(); return page;
    }
    QWidget* buildStrangeNet() {
        QVBoxLayout* body; auto* page=pageShell("StrangeNet","Universal rooms over authenticated PQVPN mainnet sessions.",&body);
        auto* intro=new QVBoxLayout; intro->setContentsMargins(24,21,24,21); intro->addWidget(text("ZERO-TRUST STRANGENET","eyebrow")); intro->addWidget(text("One room. Explicit recipients. No public history.","heroTitle")); auto* note=text("Text, emoji, stickers, reactions and receipts are encrypted separately for every authenticated peer; messages are limited to 2 KiB."); note->setProperty("muted",true); intro->addWidget(note); body->addWidget(card(intro,true));
        auto* form=new QVBoxLayout; form->setContentsMargins(20,18,20,18); auto* fields=new QHBoxLayout; strangeRoom_=new QLineEdit("mainnet"); strangeRoom_->setPlaceholderText("Room · mainnet"); strangeRoom_->setMaxLength(64); strangeAudience_=new QComboBox;strangeAudience_->addItem("All authenticated peers","auto"); fields->addWidget(strangeRoom_,1);fields->addWidget(strangeAudience_,2); form->addLayout(fields); auto* actions=new QHBoxLayout; strangeJoin_=new QPushButton("Join universal room"); actions->addWidget(strangeJoin_); actions->addStretch(); form->addLayout(actions); body->addWidget(card(form));
        auto* peers=new QVBoxLayout;peers->setContentsMargins(20,18,20,18);auto* peerHeader=new QHBoxLayout;peerHeader->addWidget(text("ZERO-TRUST PEER DIRECTORY","eyebrow"));peerCount_=text("0 authenticated","sectionTitle");peerHeader->addStretch();peerHeader->addWidget(peerCount_);peers->addLayout(peerHeader);auto* peerNote=text("Only peers that completed the hybrid authenticated session appear here. Select all for per-session encrypted fanout, or pin this room to one verified identity. A disconnected target never falls back to another peer.");peerNote->setProperty("muted",true);peers->addWidget(peerNote);peerDirectory_=new QListWidget;peerDirectory_->setMaximumHeight(150);peers->addWidget(peerDirectory_);body->addWidget(card(peers));
        strangeTranscript_=new QTextBrowser; strangeTranscript_->setOpenExternalLinks(false);strangeTranscript_->setOpenLinks(false);strangeTranscript_->document()->setMaximumBlockCount(1000); strangeTranscript_->setPlaceholderText("Encrypted messages, stickers, reactions and delivery receipts appear here."); body->addWidget(strangeTranscript_,1); auto* composer=new QHBoxLayout; strangeMessage_=new QLineEdit; strangeMessage_->setPlaceholderText("Write an E2E message · 2048 UTF-8 bytes maximum"); strangeMessage_->setMaxLength(2048);auto* emoji=new QPushButton("Emoji");emoji->setProperty("quiet",true);auto* emojiMenu=new QMenu(emoji);for(const QString& value:QStringList{"😀","😂","😍","🤔","😮","😢","👍","👏","🎉","🔥","❤️","🚀","🔐","🛡️"}){auto* action=emojiMenu->addAction(value);connect(action,&QAction::triggered,this,[this,value]{strangeMessage_->insert(value);strangeMessage_->setFocus();});}emoji->setMenu(emojiMenu);strangeSticker_=new QPushButton("Create sticker…");strangeSticker_->setProperty("quiet",true);strangeReaction_=new QPushButton("React");strangeReaction_->setProperty("quiet",true);strangeReaction_->setEnabled(false);auto* reactionMenu=new QMenu(strangeReaction_);for(const QString& value:QStringList{"👍","❤️","😂","😮","🎉","🔥"}){auto* action=reactionMenu->addAction(value);connect(action,&QAction::triggered,this,[this,value]{sendStrangeReaction(value);});}strangeReaction_->setMenu(reactionMenu); strangeSend_=new QPushButton("Send"); strangeSend_->setEnabled(false); composer->addWidget(strangeMessage_,1);composer->addWidget(emoji);composer->addWidget(strangeSticker_);composer->addWidget(strangeReaction_); composer->addWidget(strangeSend_); body->addLayout(composer);strangeBytes_=text("0 / 2048 bytes");strangeBytes_->setProperty("muted",true);body->addWidget(strangeBytes_,0,Qt::AlignRight);
        connect(strangeJoin_,&QPushButton::clicked,this,&Window::toggleStrangeNet); connect(strangeSend_,&QPushButton::clicked,this,&Window::sendStrangeMessage);connect(strangeSticker_,&QPushButton::clicked,this,&Window::createStrangeSticker); connect(strangeMessage_,&QLineEdit::returnPressed,this,&Window::sendStrangeMessage);connect(strangeMessage_,&QLineEdit::textChanged,this,[this](const QString& value){const auto bytes=value.toUtf8().size();strangeBytes_->setText(QString("%1 / 2048 bytes").arg(bytes));strangeSend_->setEnabled(strangeActive_&&strangeRecipientReady()&&bytes>0&&bytes<=2048);});connect(peerDirectory_,&QListWidget::itemActivated,this,[this](QListWidgetItem* item){if(strangeActive_)return;const QString peer=item->data(Qt::UserRole).toString();const int index=strangeAudience_->findData(peer);if(index>=0)strangeAudience_->setCurrentIndex(index);});
        return page;
    }
    QWidget* buildActivity() {
        QVBoxLayout* body; auto* page=pageShell("Activity","This session only. Output comes from the actual node process.",&body); activity_=new QPlainTextEdit; activity_->setReadOnly(true); activity_->document()->setMaximumBlockCount(2000); activity_->setPlaceholderText("Validation, node output and process events will appear here."); body->addWidget(activity_,1); auto* row=new QHBoxLayout; auto* copy=new QPushButton("Copy activity"); copy->setProperty("quiet",true); auto* clear=new QPushButton("Clear"); clear->setProperty("quiet",true); row->addStretch(); row->addWidget(copy); row->addWidget(clear); body->addLayout(row); connect(copy,&QPushButton::clicked,this,[this]{QApplication::clipboard()->setText(activity_->toPlainText());}); connect(clear,&QPushButton::clicked,activity_,&QPlainTextEdit::clear); return page;
    }
    QWidget* buildPrivacy() {
        QVBoxLayout* body; auto* page=pageShell("Privacy & control","Clear promises, observable limits and choices that stay yours.",&body); const QList<QPair<QString,QString>> principles={{"Local by default","No analytics or telemetry client."},{"Zero-trust peers","Discovery grants no access. A peer appears only after hybrid authentication and configured admission policy pass."},{"Honest status","Every status and event comes from the node process."},{"Reversible actions","You explicitly connect, disconnect, hide or exit."},{"Motion is optional","Reduce motion stops ambient, pulse and page animations."},{"No fear or urgency","No countdowns, streaks, scores or pressure tactics."},{"Accurate claims","Shaping and transports reduce patterns; the UI never promises invisibility."}};
        for (const auto& [title,copy]:principles) { auto* row=new QHBoxLayout; row->setContentsMargins(20,17,20,17); auto* icon=text("✓","metric"); icon->setFixedWidth(34); auto* words=new QVBoxLayout; words->addWidget(text(title,"sectionTitle")); auto* detail=text(copy); detail->setProperty("muted",true); words->addWidget(detail); row->addWidget(icon); row->addLayout(words,1); body->addWidget(card(row)); } body->addStretch(); return page;
    }
    QWidget* buildAbout() {
        QVBoxLayout* body; auto* page=pageShell("About PQVPN","A native C++23 console for the post-quantum node.",&body); auto* info=new QVBoxLayout; info->setContentsMargins(27,25,27,25); auto* logo=new QLabel; logo->setPixmap(QIcon(":/brand/logo.svg").pixmap(96,96)); info->addWidget(logo,0,Qt::AlignLeft); info->addWidget(text("PQVPN","heroTitle")); info->addWidget(text("Privacy Console · Qt 6 · C++23","sectionTitle")); auto* detail=text("The node owns cryptography, sessions, routing, shaping and transport policy. Qt owns presentation and launches the same pqvpn_node executable used by the CLI."); detail->setProperty("muted",true); info->addWidget(detail); auto* diagnostic=new QPushButton("Copy diagnostics"); diagnostic->setProperty("quiet",true); connect(diagnostic,&QPushButton::clicked,this,&Window::copyDiagnostics); info->addWidget(diagnostic,0,Qt::AlignLeft); body->addWidget(card(info,true)); body->addStretch(); return page;
    }
    void buildTray() {
        tray_=new QSystemTrayIcon(QIcon(":/brand/tray.svg"),this); trayMenu_=new QMenu; trayStatus_=trayMenu_->addAction("Disconnected"); trayStatus_->setEnabled(false); trayMenu_->addSeparator(); auto* show=trayMenu_->addAction("Show Privacy Console"); connect(show,&QAction::triggered,this,&Window::restoreFromTray); trayToggle_=trayMenu_->addAction("Connect securely"); connect(trayToggle_,&QAction::triggered,this,[this]{restoreFromTray(); if(process_.state()==QProcess::NotRunning&&!configValid_)switchPage(Connection); else toggleConnection();}); trayMenu_->addSeparator(); auto* exit=trayMenu_->addAction("Exit PQVPN"); connect(exit,&QAction::triggered,this,&Window::quitApplication); tray_->setContextMenu(trayMenu_); connect(tray_,&QSystemTrayIcon::activated,this,[this](QSystemTrayIcon::ActivationReason reason){if(reason==QSystemTrayIcon::Trigger||reason==QSystemTrayIcon::DoubleClick)restoreFromTray();}); if(QSystemTrayIcon::isSystemTrayAvailable())tray_->show(); else minimizeToTray_->setChecked(false);
    }
    QString defaultExecutable() const { const QString name=
#ifdef _WIN32
        "pqvpn_node.exe";
#else
        "pqvpn_node";
#endif
        const QString sibling=QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(name); return QFileInfo::exists(sibling)?sibling:QDir::current().absoluteFilePath("build/"+name); }
    bool strangeRecipientReady() const {return mainnetReady_&&(activeStrangePeer_=="auto"||authenticatedPeers_.contains(activeStrangePeer_));}
    void refreshPeerDirectory(){
        if(!strangeAudience_||!peerDirectory_)return;const QString selected=strangeAudience_->currentData().toString();QSignalBlocker guard(strangeAudience_);strangeAudience_->clear();strangeAudience_->addItem(QString("All authenticated peers · %1").arg(authenticatedPeers_.size()),"auto");peerDirectory_->clear();QStringList identities=authenticatedPeers_.keys();identities.sort(Qt::CaseInsensitive);for(const QString& identity:identities){const QString endpoint=authenticatedPeers_.value(identity);const QString label=QString("%1…  ·  %2  ·  authenticated + policy accepted").arg(identity.left(16),endpoint);strangeAudience_->addItem(label,identity);auto* item=new QListWidgetItem(label,peerDirectory_);item->setData(Qt::UserRole,identity);item->setToolTip(identity);}const int restored=strangeAudience_->findData(selected);strangeAudience_->setCurrentIndex(restored>=0?restored:0);peerCount_->setText(QString("%1 authenticated").arg(authenticatedPeers_.size()));
    }
    void connectProcess() {
        connect(&process_,&QProcess::readyReadStandardOutput,this,[this]{
            processBuffer_.append(process_.readAllStandardOutput());
            if(processBuffer_.size()>1024*1024){processBuffer_.clear();log("Node output discarded · unterminated record exceeded 1 MiB");return;}
            qsizetype newline=0;
            while((newline=processBuffer_.indexOf('\n'))>=0){
                const QString clean=QString::fromUtf8(processBuffer_.left(newline)).trimmed().left(16384);
                processBuffer_.remove(0,newline+1);
                if(clean.isEmpty())continue;
                log(clean);
                if(!clean.startsWith("PQVPN_EVENT "))continue;
                QJsonParseError error;const auto event=QJsonDocument::fromJson(clean.mid(12).toUtf8(),&error).object();
                if(error.error!=QJsonParseError::NoError)continue;
                const QString name=event.value("event").toString();
                if(name=="peer.connected"){
                    const QString peer=event.value("peer").toString().toLower();if(QRegularExpression("^[0-9a-f]{64}$").match(peer).hasMatch())authenticatedPeers_.insert(peer,event.value("endpoint").toString());refreshPeerDirectory();mainnetReady_=!authenticatedPeers_.isEmpty();refreshConnectionPresentation();strangeSend_->setEnabled(strangeActive_&&strangeRecipientReady()&&!strangeMessage_->text().isEmpty());
                }else if(name=="peer.disconnected"){
                    const QString peer=event.value("peer").toString().toLower();authenticatedPeers_.remove(peer);refreshPeerDirectory();mainnetReady_=!authenticatedPeers_.isEmpty();refreshConnectionPresentation();const bool ready=strangeRecipientReady();strangeSend_->setEnabled(strangeActive_&&ready&&!strangeMessage_->text().isEmpty());if(strangeActive_&&activeStrangePeer_==peer){strangeReaction_->setEnabled(false);appendStrangeText("Selected peer disconnected. Zero-trust targeting remains pinned; leave the room to choose another peer.");}
                }else if(name=="tunnel.ready"){
                    tunnelReady_=event.value("fail_closed").toBool(false)&&event.value("ipv4").toString()=="full";
                    refreshConnectionPresentation();
                }else if(name=="strangenet.joined"){
                    strangeActive_=true;pendingStrangeJoin_=false;activeStrangePeer_=event.value("peer").toString("auto").toLower();strangeJoin_->setText("Leave room");
                    strangeRoom_->setEnabled(false);strangeAudience_->setEnabled(false);strangeSend_->setEnabled(strangeRecipientReady()&&!strangeMessage_->text().isEmpty()&&strangeMessage_->text().toUtf8().size()<=2048);
                    appendStrangeText(activeStrangePeer_=="auto"?QString("Joined '%1' · all authenticated peers").arg(event.value("room").toString()):QString("Joined '%1' · pinned to %2…").arg(event.value("room").toString(),activeStrangePeer_.left(16)));
                }else if(name=="strangenet.left"){
                    strangeActive_=false;strangeJoin_->setText("Join universal room");strangeSend_->setEnabled(false);strangeReaction_->setEnabled(false);
                    strangeRoom_->setEnabled(true);strangeAudience_->setEnabled(true);activeStrangePeer_="auto";appendStrangeText("Left room.");
                }else if(name=="strangenet.message"){
                    lastStrangeSender_=event.value("sender").toString();lastStrangeSequence_=event.value("sequence").toVariant().toULongLong();strangeReaction_->setEnabled(strangeRecipientReady());appendStrangeText(QString("%1  %2\n%3").arg(lastStrangeSender_.left(12),QDateTime::fromMSecsSinceEpoch(event.value("timestamp_ms").toVariant().toLongLong()).toLocalTime().toString("HH:mm:ss"),event.value("text").toString()));notifyStrangeActivity();
                }else if(name=="strangenet.sticker"){
                    lastStrangeSender_=event.value("sender").toString();lastStrangeSequence_=event.value("sequence").toVariant().toULongLong();strangeReaction_->setEnabled(strangeRecipientReady());appendStrangeSticker(event.value("text").toString(),lastStrangeSender_.left(12));notifyStrangeActivity();
                }else if(name=="strangenet.reaction"){
                    appendStrangeReaction(event.value("text").toString(),event.value("sender").toString().left(12),event.value("reply_to").toVariant().toULongLong());notifyStrangeActivity();
                }else if(name=="strangenet.delivered"){
                    appendStrangeText(QString("Delivered · message %1 · peer %2").arg(event.value("sequence").toVariant().toULongLong()).arg(event.value("peer").toString().left(12)));
                }else if(name=="strangenet.sent"){
                    const QString kind=event.value("kind").toString();if(kind=="sticker")appendStrangeSticker(event.value("text").toString(),"You");else if(kind=="reaction")appendStrangeReaction(event.value("text").toString(),"You",0);else{appendStrangeText("You\n"+event.value("text").toString());strangeMessage_->clear();}appendStrangeText(QString("Encrypted separately for %1 authenticated peer(s).").arg(event.value("recipients").toInt()));const auto bytes=strangeMessage_->text().toUtf8().size();strangeSend_->setEnabled(strangeActive_&&strangeRecipientReady()&&bytes>0&&bytes<=2048);
                }else if(name=="strangenet.deferred"||name=="control.error"){
                    appendStrangeText("Notice · "+event.value("message").toString());const auto bytes=strangeMessage_->text().toUtf8().size();strangeSend_->setEnabled(strangeActive_&&strangeRecipientReady()&&bytes>0&&bytes<=2048);strangeMessage_->setFocus();
                }
            }
        });
        connect(&process_,&QProcess::stateChanged,this,[this](QProcess::ProcessState state){const bool active=state!=QProcess::NotRunning,running=state==QProcess::Running;if(!active){mainnetReady_=false;tunnelReady_=false;authenticatedPeers_.clear();refreshPeerDirectory();}refreshConnectionPresentation();connectButton_->setText(active?"Disconnect":"Connect securely"); connectButton_->setProperty("danger",active); connectButton_->style()->unpolish(connectButton_);connectButton_->style()->polish(connectButton_); validateButton_->setEnabled(!active); configPath_->setEnabled(!active);executablePath_->setEnabled(!active);logLevel_->setEnabled(!active);adaptiveEnabled_->setEnabled(!active);adaptiveMode_->setEnabled(!active);saveTransportButton_->setEnabled(!active); trayToggle_->setText(active?"Disconnect":"Connect securely");if(strangeJoin_){strangeJoin_->setEnabled(running||(!active&&configValid_));strangeSend_->setEnabled(strangeActive_&&strangeRecipientReady()&&!strangeMessage_->text().isEmpty()&&strangeMessage_->text().toUtf8().size()<=2048);strangeReaction_->setEnabled(strangeActive_&&strangeRecipientReady()&&lastStrangeSequence_!=0);strangeRoom_->setEnabled(!strangeActive_);strangeAudience_->setEnabled(!strangeActive_);}if(!active){strangeActive_=false;pendingStrangeJoin_=false;activeStrangePeer_="auto";strangeJoin_->setText("Join universal room");}});
        connect(&process_,&QProcess::started,this,[this]{log("Node process started");if(pendingStrangeJoin_)sendStrangeJoin();}); connect(&process_,&QProcess::errorOccurred,this,[this](QProcess::ProcessError){log("Process error · "+process_.errorString());statusText_->setText("The node could not continue: "+process_.errorString());});
        connect(&process_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus status){if(!processBuffer_.isEmpty()){log(QString::fromUtf8(processBuffer_).trimmed());processBuffer_.clear();}log(QString("Node stopped · exit %1 · %2").arg(code).arg(status==QProcess::NormalExit?"normal":"crashed"));statusText_->setText(stopping_&&status==QProcess::NormalExit?"Disconnected cleanly.":QString("Node stopped with exit code %1. Review Activity.").arg(code));stopping_=false;connectButton_->setEnabled(configValid_);if(pendingQuit_){pendingQuit_=false;quitting_=true;savePreferences();qApp->quit();}});
    }
    bool loadConfig(const QString& path) {
        QFile file(path); if(!file.open(QIODevice::ReadOnly)){setUnknownConfig();return false;} QJsonParseError error; const auto doc=QJsonDocument::fromJson(file.readAll(),&error); if(error.error!=QJsonParseError::NoError||!doc.isObject()){configHealth_->setText("JSON could not be read: "+error.errorString());return false;}
        const auto root=doc.object(),network=root.value("network").toObject(),security=root.value("security").toObject(),shaping=root.value("traffic_shaping").toObject(),external=root.value("external_transport").toObject(),adaptive=root.value("adaptive_transport").toObject(),tunnel=root.value("tunnel").toObject(),egress=root.value("egress").toObject();
        const auto bootstrap=root.value("bootstrap").toArray();
        if(bootstrap.isEmpty())mainnetMetric_->setText("Listener only");else{const auto first=bootstrap.first();if(first.isString())mainnetMetric_->setText(first.toString());else{const auto peer=first.toObject();mainnetMetric_->setText(QString("%1:%2").arg(peer.value("host").toString()).arg(peer.value("port").toInt()));}}
        endpointMetric_->setText(QString("%1:%2").arg(network.value("bind_address").toString("127.0.0.1")).arg(network.value("port").toInt(9090)));
        verificationMetric_->setText(QString("%1 · %2").arg(security.value("strict_sig_verify").toBool(true)?"Hybrid strict":"Relaxed",security.value("tofu").toBool(true)?"TOFU":"Pinned"));
        shapingMetric_->setText(shaping.value("enabled").toBool(false)?"Enabled":"Off");egressMetric_->setText(egress.value("enabled").toBool(false)?"Enabled":"Relay only");
#ifdef _WIN32
        tunnelMetric_->setText(noTunnel_&&noTunnel_->isChecked()?"UDP-only":"PQVPN NDIS");
#elif defined(__APPLE__)
        tunnelMetric_->setText("Network Extension");
#else
        tunnelMetric_->setText("Linux TUN");
#endif
        if(!tunnel.isEmpty()&&tunnel.value("plugin").toString("pqvpn")!="pqvpn")tunnelMetric_->setText(tunnel.value("plugin").toString().toUpper());
        const bool adaptiveOn=adaptive.value("enabled").toBool(false);const QString adaptiveMode=adaptive.value("mode").toString("auto");adaptiveEnabled_->setChecked(adaptiveOn);adaptiveMode_->setCurrentIndex(qMax(0,adaptiveMode_->findData(adaptiveMode)));adaptiveMetric_->setText(adaptiveOn?QString("Enabled · %1").arg(adaptiveMode.toUpper()):"Disabled · direct UDP");if(external.isEmpty()){transportMetric_->setText(adaptiveOn?"PQTP adaptive path":"Direct PQVPN UDP");transportDetails_->setText(adaptiveOn?"Policy is configured; runtime events report every lane change.":"No external transport selected.");}else{transportMetric_->setText(external.value("engine").toString("Unknown"));transportDetails_->setText(QString("Attach mode · %1:%2 · external process required").arg(external.value("host").toString()).arg(external.value("port").toInt()));}return !root.isEmpty();
    }
    void setUnknownConfig(){mainnetMetric_->setText("Not loaded");endpointMetric_->setText("Not loaded");verificationMetric_->setText("Unknown");tunnelMetric_->setText("Unknown");egressMetric_->setText("Unknown");shapingMetric_->setText("Unknown");transportMetric_->setText("Configuration unavailable");transportDetails_->setText("Choose a readable JSON configuration.");if(adaptiveMetric_)adaptiveMetric_->setText("Configuration unavailable");}
    void saveTransportSettings(){QFile source(configPath_->text());if(!source.open(QIODevice::ReadOnly)){log("Transport policy was not saved · configuration unavailable");return;}QJsonParseError error;auto document=QJsonDocument::fromJson(source.readAll(),&error);source.close();if(error.error!=QJsonParseError::NoError||!document.isObject()){log("Transport policy was not saved · invalid JSON");return;}auto root=document.object();auto adaptive=root.value("adaptive_transport").toObject();adaptive["enabled"]=adaptiveEnabled_->isChecked();adaptive["mode"]=adaptiveMode_->currentData().toString();if(!adaptive.contains("loss_switch_percent"))adaptive["loss_switch_percent"]=12.0;if(!adaptive.contains("jitter_switch_ms"))adaptive["jitter_switch_ms"]=45.0;if(!adaptive.contains("failure_switch_count"))adaptive["failure_switch_count"]=3;if(!adaptive.contains("recovery_probe_count"))adaptive["recovery_probe_count"]=4;if(!adaptive.contains("minimum_dwell_ms"))adaptive["minimum_dwell_ms"]=5000;root["adaptive_transport"]=adaptive;document.setObject(root);QSaveFile output(configPath_->text());if(!output.open(QIODevice::WriteOnly)||output.write(document.toJson(QJsonDocument::Indented))<0||!output.commit()){log("Transport policy could not be written safely");return;}invalidate("Transport policy saved. Validate before connecting.");loadConfig(configPath_->text());log("Transport policy saved · "+adaptiveMode_->currentData().toString());}
    void invalidate(const QString& reason){configValid_=false;validatedConfigHash_.clear();validatedExecutableHash_.clear();connectButton_->setEnabled(false);configHealth_->setText(reason);}
    void chooseConfig(){const QString path=QFileDialog::getOpenFileName(this,"Choose PQVPN configuration",QFileInfo(configPath_->text()).absolutePath(),"JSON configuration (*.json)");if(!path.isEmpty())configPath_->setText(path);}
    void chooseExecutable(){const QString path=QFileDialog::getOpenFileName(this,"Choose pqvpn_node",QFileInfo(executablePath_->text()).absolutePath());if(!path.isEmpty())executablePath_->setText(path);}
    void runNodeTool(const QStringList& arguments,const QString& title){
        const QFileInfo binary(executablePath_->text());
        if(!binary.exists()||!binary.isExecutable()){configHealth_->setText("Choose an executable pqvpn_node binary.");switchPage(Connection);return;}
        auto* tool=new QProcess(this);tool->setProcessChannelMode(QProcess::MergedChannels);captureBoundedOutput(tool);log(title+" started");
        connect(tool,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,tool,title](int code,QProcess::ExitStatus status){
            QByteArray raw=tool->property("pqvpnOutput").toByteArray()+tool->readAllStandardOutput();if(raw.size()>1024*1024)raw=QByteArray("[earlier output discarded]\n")+raw.right(1024*1024);QString output=QString::fromUtf8(raw).trimmed();if(output.isEmpty())output="No output was produced.";log(title+QString(" finished · exit %1").arg(code));
            QDialog dialog(this);dialog.setWindowTitle(title);dialog.resize(760,520);auto* layout=new QVBoxLayout(&dialog);auto* heading=text(status==QProcess::NormalExit&&code==0?title+" completed":title+QString(" failed · exit %1").arg(code),"sectionTitle");layout->addWidget(heading);auto* report=new QPlainTextEdit(output);report->setReadOnly(true);layout->addWidget(report,1);auto* close=new QPushButton("Close");connect(close,&QPushButton::clicked,&dialog,&QDialog::accept);layout->addWidget(close,0,Qt::AlignRight);dialog.exec();tool->deleteLater();
        });
        connect(tool,&QProcess::errorOccurred,this,[this,tool,title](QProcess::ProcessError){log(title+" failed to start · "+tool->errorString());});
        tool->start(executablePath_->text(),arguments);
    }
    void finishValidation(bool passed,const QString& message){
        configValid_=passed;configHealth_->setText(message);connectButton_->setEnabled(passed);
        if(passed){validatedConfigHash_=fileFingerprint(configPath_->text());validatedExecutableHash_=fileFingerprint(executablePath_->text());
            if(validatedConfigHash_.isEmpty()||validatedExecutableHash_.isEmpty()){invalidate("Validated files are no longer readable. Validate again.");passed=false;}}
        else{validatedConfigHash_.clear();validatedExecutableHash_.clear();}
        validateButton_->setEnabled(true);log(passed?"Configuration and platform preflight passed":"Connection preflight failed");
    }
    void validatePlatform(){
        if(noTunnel_&&noTunnel_->isChecked()){
            finishValidation(true,"Validated for relay mode. Local traffic will not be tunneled.");return;
        }
#ifdef _WIN32
        auto* platform=new QProcess(this);platform->setProcessChannelMode(QProcess::MergedChannels);captureBoundedOutput(platform);
        connect(platform,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,platform](int code,QProcess::ExitStatus status){
            const QString output=QString::fromUtf8(platform->property("pqvpnOutput").toByteArray()+platform->readAllStandardOutput()).trimmed();
            const bool ready=status==QProcess::NormalExit&&code==0&&output.contains("driver=ready");
            QString message="PQVPN driver is ready. Configuration and platform checks passed.";
            if(!ready&&output.contains("driver=access-denied"))message="Driver access denied. Run the installed application with the required privileges.";
            else if(!ready&&output.contains("driver=not-installed"))message="PQVPN driver is not installed. A local tunnel cannot start safely.";
            else if(!ready)message="PQVPN driver preflight failed. Review Activity before connecting.";
            finishValidation(ready,message);platform->deleteLater();
        });
        connect(platform,&QProcess::errorOccurred,this,[this,platform](QProcess::ProcessError){finishValidation(false,"Platform inspection could not start: "+platform->errorString());platform->deleteLater();});
        platform->start(executablePath_->text(),{"--platform-info"});
#else
        finishValidation(true,"Configuration and platform checks passed. Route readiness will be verified at runtime.");
#endif
    }
    void validateConfig(bool switchToConnection=true) {
        if(process_.state()!=QProcess::NotRunning) return;
        const QFileInfo binary(executablePath_->text());
        if(!binary.exists()||!binary.isExecutable()) {
            configHealth_->setText("Choose an executable pqvpn_node binary.");
            log("Validation blocked · node executable unavailable");
            return;
        }
        validateButton_->setEnabled(false); configHealth_->setText("Validating with pqvpn_node…"); log("Configuration validation started");
        auto* check=new QProcess(this); check->setProcessChannelMode(QProcess::MergedChannels);captureBoundedOutput(check);
        connect(check,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,check](int code,QProcess::ExitStatus status){
            check->readAllStandardOutput();
            const bool valid=status==QProcess::NormalExit&&code==0&&loadConfig(configPath_->text());check->deleteLater();
            if(valid){log("Configuration validation passed; checking platform readiness");validatePlatform();}
            else finishValidation(false,QString("Validation failed with exit code %1. Review Activity.").arg(code));
        });
        check->start(executablePath_->text(),{"--smoke-test","--config",configPath_->text()}); if(switchToConnection) switchPage(Connection);
    }
    void toggleConnection(){if(process_.state()==QProcess::NotRunning){if(!configValid_)return;if(fileFingerprint(configPath_->text())!=validatedConfigHash_||fileFingerprint(executablePath_->text())!=validatedExecutableHash_){invalidate("Configuration or executable changed after validation. Validate again.");log("Connection blocked · validated files changed");return;}stopping_=false;bool noTunnel=false;
        noTunnel=noTunnel_&&noTunnel_->isChecked();
        log(QString("Connect requested · config %1 · log %2%3").arg(configPath_->text(),logLevel_->currentText(),noTunnel?" · no-tunnel":""));QStringList args={"--config",configPath_->text(),"--log-level",logLevel_->currentText(),"--control-stdin"};if(noTunnel)args<<"--no-tunnel";process_.start(executablePath_->text(),args);}else requestStop();}
    void appendStrangeText(const QString& value){strangeTranscript_->append(QString("<div style='margin:6px 0;color:#eef1ff'>%1</div>").arg(value.toHtmlEscaped().replace("\n","<br>")));}
    void appendStrangeSticker(const QString& payload,const QString& sender){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),caption=object.value("caption").toString(),color=object.value("color").toString();const QStringList palette{"#5432c9","#0f8fa8","#b83280","#b86b18","#226c4a","#3d4d73"};if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16||caption.size()>48||!palette.contains(color)){appendStrangeText("Invalid sticker was discarded.");return;}strangeTranscript_->append(QString("<table width='260' cellpadding='12' bgcolor='%1'><tr><td><span style='font-size:34pt'>%2</span><br><b>%3</b><br><small>%4</small></td></tr></table>").arg(color,emoji.toHtmlEscaped(),caption.toHtmlEscaped(),sender.toHtmlEscaped()));}
    void appendStrangeReaction(const QString& payload,const QString& sender,qulonglong fallbackSequence){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),target=object.value("target").toString().left(12);const auto sequence=object.value("sequence").toVariant().toULongLong();if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16){appendStrangeText("Invalid reaction was discarded.");return;}appendStrangeText(QString("%1 reacted %2 to %3 · message %4").arg(sender,emoji,target.isEmpty()?QString("a message"):target).arg(sequence?sequence:fallbackSequence));}
    void notifyStrangeActivity(){if(pages_->currentIndex()==StrangeNet&&isActiveWindow())return;unreadStrange_=qMin(unreadStrange_+1,999);const QString label=QString("04   StrangeNet · %1").arg(unreadStrange_);pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);const auto now=QDateTime::currentMSecsSinceEpoch();if(strangeNotifications_->isChecked()&&tray_->isVisible()&&now-lastStrangeNotificationMs_>=3000){lastStrangeNotificationMs_=now;tray_->showMessage("New encrypted StrangeNet activity","Open PQVPN to view it.",QSystemTrayIcon::Information,3500);}}
    bool validStrangeRoom() { const QString room=strangeRoom_->text().trimmed();const bool valid=QRegularExpression("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").match(room).hasMatch();if(!valid)appendStrangeText("Use a safe 1–64 character room name.");return valid; }
    void sendControl(const QJsonObject& command){process_.write(QJsonDocument(command).toJson(QJsonDocument::Compact)+'\n');}
    void sendStrangeJoin(){const QString peer=strangeAudience_->currentData().toString();sendControl({{"command","strangenet.join"},{"room",strangeRoom_->text().trimmed()},{"peer",peer.isEmpty()?"auto":peer}});}
    void toggleStrangeNet(){if(strangeActive_){sendControl({{"command","strangenet.leave"}});return;}if(!validStrangeRoom())return;if(process_.state()==QProcess::NotRunning){if(!configValid_){appendStrangeText("Validate the mainnet configuration before joining.");switchPage(Connection);return;}pendingStrangeJoin_=true;appendStrangeText("Starting the mainnet connection for room '"+strangeRoom_->text().trimmed()+"'…");toggleConnection();return;}sendStrangeJoin();}
    void sendStrangeMessage(){const QByteArray message=strangeMessage_->text().toUtf8();if(!strangeActive_||!strangeRecipientReady()||process_.state()!=QProcess::Running||message.isEmpty()||message.size()>2048)return;sendControl({{"command","strangenet.send"},{"text",strangeMessage_->text()}});strangeSend_->setEnabled(false);}
    void sendStrangeReaction(const QString& emoji){if(!strangeActive_||!strangeRecipientReady()||lastStrangeSequence_==0)return;const QJsonObject reaction{{"emoji",emoji},{"target",lastStrangeSender_},{"sequence",static_cast<qint64>(lastStrangeSequence_)}};sendControl({{"command","strangenet.react"},{"reply_to",static_cast<qint64>(lastStrangeSequence_)},{"text",QString::fromUtf8(QJsonDocument(reaction).toJson(QJsonDocument::Compact))}});}
    void createStrangeSticker(){if(!strangeActive_||!strangeRecipientReady()){appendStrangeText("Join a room with an authenticated recipient before creating a sticker.");return;}QDialog dialog(this);dialog.setWindowTitle("Create encrypted sticker");auto* layout=new QVBoxLayout(&dialog);auto* emoji=new QComboBox;emoji->addItems({"🚀","🔐","🛡️","🎉","🔥","💜","🌌","⚡","👋","👍"});auto* caption=new QLineEdit;caption->setMaxLength(48);caption->setPlaceholderText("Short caption");auto* color=new QComboBox;const QList<QPair<QString,QString>> colors{{"Violet","#5432c9"},{"Cyan","#0f8fa8"},{"Magenta","#b83280"},{"Amber","#b86b18"},{"Green","#226c4a"},{"Slate","#3d4d73"}};for(const auto& entry:colors)color->addItem(entry.first,entry.second);auto* preview=text("","heroTitle");auto refresh=[=]{preview->setText(emoji->currentText()+"  "+caption->text());preview->setStyleSheet("padding:18px;border-radius:14px;background:"+color->currentData().toString()+";color:white");};connect(emoji,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});connect(caption,&QLineEdit::textChanged,&dialog,[=]{refresh();});connect(color,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});layout->addWidget(text("EMOJI","eyebrow"));layout->addWidget(emoji);layout->addWidget(text("CAPTION","eyebrow"));layout->addWidget(caption);layout->addWidget(text("COLOR","eyebrow"));layout->addWidget(color);layout->addWidget(preview);auto* send=new QPushButton("Send sticker E2E");layout->addWidget(send);connect(send,&QPushButton::clicked,&dialog,&QDialog::accept);refresh();if(dialog.exec()!=QDialog::Accepted)return;const QJsonObject sticker{{"emoji",emoji->currentText()},{"caption",caption->text()},{"color",color->currentData().toString()}};sendControl({{"command","strangenet.sticker"},{"text",QString::fromUtf8(QJsonDocument(sticker).toJson(QJsonDocument::Compact))}});}
    void requestStop(){if(process_.state()==QProcess::NotRunning)return;stopping_=true;statusText_->setText("Disconnecting cleanly…");log("Disconnect requested");process_.terminate();QTimer::singleShot(5000,this,[this]{if(process_.state()!=QProcess::NotRunning){log("Clean shutdown timed out; process termination escalated");process_.kill();}});}
    void quitApplication(){quitting_=true;if(process_.state()!=QProcess::NotRunning){pendingQuit_=true;requestStop();}else{savePreferences();qApp->quit();}}
    void restoreFromTray(){showNormal();raise();activateWindow();}
    void switchPage(int index){if(!pages_||index<0||index>=pages_->count())return;pageButtons_.value(index)->setChecked(true);if(index==StrangeNet&&unreadStrange_){unreadStrange_=0;const QString label="04   StrangeNet";pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);}if(pages_->currentIndex()==index)return;pages_->setCurrentIndex(index);if(reduceMotion_&&reduceMotion_->isChecked())return;auto* effect=new QGraphicsOpacityEffect(pages_->currentWidget());pages_->currentWidget()->setGraphicsEffect(effect);auto* animation=new QPropertyAnimation(effect,"opacity",effect);animation->setDuration(260);animation->setStartValue(0.0);animation->setEndValue(1.0);animation->setEasingCurve(QEasingCurve::OutCubic);connect(animation,&QPropertyAnimation::finished,effect,[effect]{effect->setEnabled(false);});animation->start(QAbstractAnimation::DeleteWhenStopped);}
    void setMotion(bool enabled){if(!auroraAnimation_){auroraAnimation_=new QPropertyAnimation(aurora_,"phase",this);auroraAnimation_->setStartValue(0.0);auroraAnimation_->setEndValue(6.283185307);auroraAnimation_->setDuration(15000);auroraAnimation_->setLoopCount(-1);pulseAnimation_=new QPropertyAnimation(orb_,"pulse",this);pulseAnimation_->setStartValue(0.0);pulseAnimation_->setEndValue(1.0);pulseAnimation_->setDuration(1700);pulseAnimation_->setEasingCurve(QEasingCurve::InOutSine);pulseAnimation_->setLoopCount(-1);}if(enabled){auroraAnimation_->start();pulseAnimation_->start();}else{auroraAnimation_->stop();pulseAnimation_->stop();aurora_->setPhase(0);orb_->setPulse(0);}}
    void setSidebarCompact(bool compact){QSettings("PQVPN","Privacy Console").setValue("compactSidebar",compact);const int width=compact?82:238;brandWords_->setVisible(!compact);for(int i=0;i<navButtons_.size();++i)navButtons_[i]->setText(compact?QString("%1").arg(i+1,2,10,QChar('0')):navButtons_[i]->property("fullText").toString());if(reduceMotion_->isChecked()){sidebar_->setMinimumWidth(width);sidebar_->setMaximumWidth(width);return;}for(const QByteArray& property:{QByteArray("minimumWidth"),QByteArray("maximumWidth")}){auto* animation=new QPropertyAnimation(sidebar_,property,sidebar_);animation->setDuration(300);animation->setEndValue(width);animation->setEasingCurve(QEasingCurve::OutCubic);animation->start(QAbstractAnimation::DeleteWhenStopped);}}
    void applyPreferences(){QSettings settings("PQVPN","Privacy Console");restoreGeometry(settings.value("geometry").toByteArray());const QString stored=settings.value("config").toString();if(!stored.isEmpty())configPath_->setText(stored);reduceMotion_->setChecked(settings.value("reduceMotion",false).toBool());compactSidebar_->setChecked(settings.value("compactSidebar",false).toBool());minimizeToTray_->setChecked(settings.value("minimizeToTray",true).toBool());strangeNotifications_->setChecked(settings.value("strangeNotifications",true).toBool());}
    void savePreferences(){QSettings settings("PQVPN","Privacy Console");settings.setValue("geometry",saveGeometry());settings.setValue("config",configPath_->text());settings.setValue("minimizeToTray",minimizeToTray_->isChecked());settings.setValue("strangeNotifications",strangeNotifications_->isChecked());}
    void log(const QString& message){const QString stamp=QDateTime::currentDateTime().toString("HH:mm:ss");for(const QString& line:message.split('\n',Qt::SkipEmptyParts))activity_->appendPlainText(stamp+"  "+line.left(16384));}
    void copyDiagnostics(){QString state=stateName(process_.state());if(process_.state()==QProcess::Running&&!mainnetReady_)state="Negotiating";else if(mainnetReady_&&noTunnel_&&noTunnel_->isChecked())state="Mainnet connected · relay mode";else if(mainnetReady_&&tunnelReady_)state="Protected";else if(mainnetReady_)state="Peer ready · securing routes";const QString value=QString("PQVPN Privacy Console\nQt %1\nOS %2\nNode %3\nConfig %4\nState %5\nTransport %6\nShaping %7").arg(qVersion(),QSysInfo::prettyProductName(),executablePath_->text(),configPath_->text(),state,transportMetric_->text(),shapingMetric_->text());QApplication::clipboard()->setText(value);statusBar()->showMessage("Diagnostics copied — activity log excluded",3000);log("Diagnostics copied");}
    void showCommandPalette(){QDialog dialog(this);dialog.setWindowTitle("Command palette");dialog.resize(540,410);auto* layout=new QVBoxLayout(&dialog);auto* search=new QLineEdit;search->setPlaceholderText("Type a command…");auto* list=new QListWidget;const QList<QPair<QString,QString>> commands={{"Go to overview","overview"},{"Review connection","connection"},{"Inspect transports","transports"},{"Open activity","activity"},{"Privacy principles","privacy"},{"Validate configuration","validate"},{"Copy diagnostics","diagnostics"},{"About PQVPN","about"}};for(const auto& command:commands){auto* item=new QListWidgetItem(command.first,list);item->setData(Qt::UserRole,command.second);}layout->addWidget(search);layout->addWidget(list);connect(search,&QLineEdit::textChanged,&dialog,[list](const QString& query){for(int row=0;row<list->count();++row)list->item(row)->setHidden(!list->item(row)->text().contains(query,Qt::CaseInsensitive));});connect(list,&QListWidget::itemActivated,&dialog,[this,&dialog](QListWidgetItem* item){const QString command=item->data(Qt::UserRole).toString();const QHash<QString,int> pages={{"overview",Overview},{"connection",Connection},{"transports",Transports},{"activity",Activity},{"privacy",Privacy},{"about",About}};if(pages.contains(command))switchPage(pages.value(command));else if(command=="validate")validateConfig();else if(command=="diagnostics")copyDiagnostics();dialog.accept();});list->setCurrentRow(0);search->setFocus();dialog.exec();}
};

int main(int argc,char** argv){QApplication app(argc,argv);app.setApplicationName("PQVPN Privacy Console");app.setOrganizationName("PQVPN");app.setQuitOnLastWindowClosed(false);app.setWindowIcon(QIcon(":/brand/logo.svg"));app.setStyleSheet(theme);Window window;window.show();if(app.arguments().contains("--smoke-test")){app.processEvents();window.prepareSmokePage(qEnvironmentVariable("PQVPN_SMOKE_PAGE"));const QPixmap frame=window.grab();if(frame.isNull())return 1;const QString output=qEnvironmentVariable("PQVPN_SMOKE_IMAGE");if(!output.isEmpty()&&!frame.save(output))return 1;return 0;}return app.exec();}

#include "pqvpn_monitor.moc"
