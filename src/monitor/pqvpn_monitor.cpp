Warning: truncated output (original token count: 54718)
Total output lines: 1344

#include "engine_manager.hpp"
#include <QAbstractAnimation>
#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QAudioSource>
#include <QBuffer>
#include <QActionGroup>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDialog>
#include <QDir>
#include <QDoubleSpinBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QEasingCurve>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QIODevice>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QOpenGLWidget>
#include <QMenu>
#include <QMenuBar>
#include <QMediaDevices>
#include <QMessageBox>
#include <QMimeData>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QSettings>
#include <QSaveFile>
#include <QSet>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QStackedLayout>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStandardPaths>
#include <QSpinBox>
#include <QStyle>
#include <QStyleHints>
#include <QSysInfo>
#include <QSystemTrayIcon>
#include <QTextBrowser>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextOption>
#include <QTimer>
#include <QVBoxLayout>

#include <cmath>
#include <functional>
#include "console/connection_state.hpp"
#include "console/default_profile.hpp"
#include "monitor/release_updater.hpp"
#include "monitor/strangenet_proof_chain.hpp"
#include "modules/wallet_dashboard.hpp"
#include "modules/audible_fingerprint.hpp"

namespace {
enum Page { Overview, Connection, Transports, StrangeNet, Wallet, Shield, Activity, Privacy, About };

const char* darkTheme = R"CSS(
QMainWindow, QDialog { background: #020203; color: #f8f9ff; }
QLabel { color: #dbe1f2; }
QMenuBar { background: #020203; color: #aeb7d4; border-bottom: 1px solid rgba(255,255,255,.09); padding: 4px; }
QMenuBar::item { padding: 7px 12px; border-radius: 7px; }
QMenuBar::item:selected { background: #724cff; color: white; }
QMenu { background: #09090b; color: white; border: 1px solid #2c2d34; padding: 7px; }
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 6px; }
QMenu::item:selected { background: #724cff; }
#sidebar { background: #000; border-right: 1px solid rgba(255,255,255,.10); }
#wordmark { font-size: 21px; font-weight: 850; letter-spacing: 3px; color: white; }
#brandSub { color: #65e6ff; font-size: 10px; font-weight: 750; letter-spacing: 2px; }
QLabel[sidebarSection="true"] { color: #66718f; font-size: 9px; font-weight: 800; letter-spacing: 2px; padding: 12px 14px 4px 14px; }
#pageTitle { font-size: 30px; font-weight: 820; color: white; }
#pageSubtitle { color: #a5aec8; font-size: 14px; }
#heroTitle { font-size: 34px; font-weight: 850; color: white; }
#sectionTitle { font-size: 17px; font-weight: 760; color: white; }
#metric { font-size: 21px; font-weight: 820; color: white; }
#eyebrow { color: #7cecff; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
QPushButton[nav="true"] { background: transparent; color: #8994b7; border: 0; border-radius: 10px; padding: 13px 14px; text-align: left; font-weight: 680; }
QPushButton[nav="true"]:hover { background: rgba(101,230,255,.10); color: white; }
QPushButton[nav="true"]:checked { background: rgba(114,76,255,.28); color: white; border: 1px solid rgba(146,117,255,.50); }
QFrame[card="true"] { background: rgba(9,9,11,.97); border: 1px solid rgba(255,255,255,.13); border-radius: 16px; }
QFrame[accent="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5432c9,stop:.52 #824cff,stop:1 #0fa9cb); border: 1px solid rgba(255,255,255,.22); border-radius: 20px; }
QLabel[muted="true"] { color: #9ba6c7; }
QFrame[accent="true"] QLabel { color: white; }
QFrame[accent="true"] QCheckBox { color: white; }
QFrame[accent="true"] QLabel[muted="true"] { color: rgba(255,255,255,.78); }
QLabel[chip="true"] { background: rgba(101,230,255,.10); color: #a5f3ff; border: 1px solid rgba(101,230,255,.28); border-radius: 11px; padding: 4px 10px; font-size: 11px; font-weight: 700; }
QLineEdit, QComboBox, QDoubleSpinBox, QPlainTextEdit, QTextBrowser, QListWidget { background: #050506; color: #f4f6ff; border: 1px solid #34353d; border-radius: 10px; padding: 10px; selection-background-color: #724cff; }
#strangeTranscript { background: #030304; border: 1px solid rgba(101,230,255,.24); border-radius: 16px; padding: 14px; }
#strangeComposer { background: #050506; border: 1px solid #4b4d58; border-radius: 14px; padding: 13px; font-size: 14px; }
#strangeComposer:focus { border-color: #65e6ff; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextBrowser:focus { border-color: #65e6ff; }
QComboBox::drop-down { border: 0; width: 28px; }
QComboBox QAbstractItemView { background: #09090b; color: white; border: 1px solid #35363e; selection-background-color: #724cff; }
QPushButton { background: #724cff; color: white; border: 1px solid #8e72ff; border-radius: 10px; padding: 11px 17px; font-weight: 760; }
QPushButton:hover { background: #825eff; }
QPushButton:pressed { background: #5e3bd8; }
QPushButton:focus { border: 2px solid #b8f6ff; padding: 10px 16px; }
QPushButton[nav="true"]:focus { border: 1px solid #65e6ff; padding: 12px 13px; }
QPushButton:disabled { background: #252a41; color: #68718f; border-color: #30364e; }
QPushButton[quiet="true"] { background: rgba(255,255,255,.04); color: #b9c2df; border-color: #343d61; }
QPushButton[quiet="true"]:checked { background: rgba(114,76,255,.28); color: white; border-color: #8e72ff; }
QPushButton[danger="true"] { background: #d94172; border-color: #ff6494; }
QPushButton[milestone="active"] { background: rgba(114,76,255,.28); color: white; border-color: #8e72ff; }
QPushButton[milestone="done"] { background: rgba(42,190,135,.16); color: #9ff3d0; border-color: rgba(77,224,166,.48); }
QCheckBox { color: #ced5ea; spacing: 9px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #586488; border-radius: 5px; background: #0b1022; }
QCheckBox::indicator:checked { background: #65e6ff; border-color: #65e6ff; image: url(:/brand/check.svg); }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #465174; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #63719c; }
QStatusBar { background: #020203; color: #8f9aba; border-top: 1px solid rgba(255,255,255,.08); }
QToolTip { background: #65e6ff; color: #07101d; border: 0; padding: 6px; }
)CSS";

const char* soulsThemeOverrides = R"CSS(
QMainWindow, QDialog { background: #090806; color: #efe6cf; }
QLabel { color: #d8cdb6; }
QMenuBar, QStatusBar { background: #090806; color: #b7a98c; border-color: #3c3121; }
QMenu { background: #14110c; color: #efe6cf; border-color: #594626; }
QMenuBar::item:selected, QMenu::item:selected { background: #7a241c; color: #fff2d2; }
#sidebar { background: rgba(10,8,5,.98); border-right-color: #3c3121; }
#wordmark, #pageTitle, #heroTitle, #sectionTitle, #metric { color: #f3e5c1; }
#brandSub, #eyebrow { color: #d4aa55; }
QPushButton[nav="true"] { color: #aa9b7e; }
QPushButton[nav="true"]:hover { background: rgba(212,170,85,.10); color: #fff2d2; }
QPushButton[nav="true"]:checked { background: rgba(122,36,28,.34); color: #fff2d2; border-color: #9f6d31; }
QFrame[card="true"] { background: rgba(22,18,12,.95); border-color: rgba(191,145,66,.25); }
QFrame[accent="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #2a160f,stop:.52 #7a241c,stop:1 #9f6d31); border-color: #c09548; }
QLabel[muted="true"] { color: #aa9d83; }
QLabel[chip="true"] { background: rgba(212,170,85,.10); color: #e8c97d; border-color: rgba(212,170,85,.35); }
QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser, QListWidget { background: #0e0c09; color: #eee3cb; border-color: #594626; selection-background-color: #7a241c; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextBrowser:focus { border-color: #d4aa55; }
QComboBox QAbstractItemView { background: #14110c; color: #efe6cf; border-color: #594626; selection-background-color: #7a241c; }
QPushButton { background: #7a241c; color: #fff2d2; border-color: #b56339; }
QPushButton:hover { background: #913126; }
QPushButton:pressed { background: #551711; }
QPushButton:disabled { background: #211d17; color: #6f6657; border-color: #383027; }
QPushButton[quiet="true"] { background: rgba(212,170,85,.05); color: #cbbd9e; border-color: #594626; }
QPushButton[quiet="true"]:checked { background: rgba(122,36,28,.45); color: #fff2d2; border-color: #c09548; }
QPushButton[danger="true"] { background: #9b1c16; border-color: #df5b3f; }
QPushButton[milestone="active"] { background: rgba(122,36,28,.45); color: #fff2d2; border-color: #c09548; }
QPushButton[milestone="done"] { background: rgba(212,170,85,.14); color: #f0d48c; border-color: #9f7b38; }
QCheckBox { color: #d8cdb6; }
QCheckBox::indicator { background: #0e0c09; border-color: #6c5735; }
QCheckBox::indicator:checked { background: #d4aa55; border-color: #f0ca75; image: url(:/brand/check.svg); }
QScrollBar::handle:vertical { background: #6c5735; }
QToolTip { background: #d4aa55; color: #130f08; }
)CSS";

const char* lightTheme = R"CSS(
QMainWindow, QDialog { background: #f4f6fb; color: #161b2d; }
QLabel { color: #202840; }
QMenuBar { background: #f8f9fd; color: #4e5875; border-bottom: 1px solid #dfe4f1; padding: 4px; }
QMenuBar::item { padding: 7px 12px; border-radius: 7px; }
QMenuBar::item:selected { background: #6842e8; color: white; }
QMenu { background: #ffffff; color: #161b2d; border: 1px solid #d7ddec; padding: 7px; }
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 6px; }
QMenu::item:selected { background: #6842e8; color: white; }
#sidebar { background: rgba(248,249,253,.97); border-right: 1px solid #dfe4f1; }
#wordmark { font-size: 21px; font-weight: 850; letter-spacing: 3px; color: #161b2d; }
#brandSub { color: #087e96; font-size: 10px; font-weight: 750; letter-spacing: 2px; }
#pageTitle { font-size: 30px; font-weight: 820; color: #121728; }
#pageSubtitle { color: #606b88; font-size: 14px; }
#heroTitle { font-size: 34px; font-weight: 850; color: white; }
#sectionTitle { font-size: 17px; font-weight: 760; color: #171d31; }
#metric { font-size: 21px; font-weight: 820; color: #171d31; }
#eyebrow { color: #087e96; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
QPushButton[nav="true"] { background: transparent; color: #626d8a; border: 0; border-radius: 10px; padding: 13px 14px; text-align: left; font-weight: 680; }
QPushButton[nav="true"]:hover { background: rgba(15,143,168,.10); color: #151b2d; }
QPushButton[nav="true"]:checked { background: rgba(104,66,232,.12); color: #4f2fc5; border: 1px solid rgba(104,66,232,.28); }
QFrame[card="true"] { background: rgba(255,255,255,.94); border: 1px solid #dce2ef; border-radius: 16px; }
QFrame[accent="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #4e2fbe,stop:.52 #7046e8,stop:1 #087e96); border: 1px solid rgba(255,255,255,.5); border-radius: 20px; }
QLabel[muted="true"] { color: #68738e; }
QFrame[accent="true"] QLabel { color: white; }
QFrame[accent="true"] QCheckBox { color: white; }
QFrame[accent="true"] QLabel[muted="true"] { color: rgba(255,255,255,.82); }
QLabel[chip="true"] { background: rgba(15,143,168,.09); color: #086d81; border: 1px solid rgba(15,143,168,.25); border-radius: 11px; padding: 4px 10px; font-size: 11px; font-weight: 700; }
QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser, QListWidget { background: #ffffff; color: #171d31; border: 1px solid #cbd3e5; border-radius: 10px; padding: 10px; selection-background-color: #6842e8; selection-color: white; }
#strangeTranscript { background: #f8f9fd; border: 1px solid #c9d4ea; border-radius: 16px; padding: 14px; }
#strangeComposer { background: #ffffff; border: 1px solid #b9c5dc; border-radius: 14px; padding: 13px; font-size: 14px; }
#strangeComposer:focus { border-color: #0f8fa8; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextBrowser:focus { border-color: #0f8fa8; }
QComboBox::drop-down { border: 0; width: 28px; }
QComboBox QAbstractItemView { background: white; color: #171d31; border: 1px solid #cbd3e5; selection-background-color: #6842e8; selection-color: white; }
QPushButton { background: #6842e8; color: white; border: 1px solid #7b5aeb; border-radius: 10px; padding: 11px 17px; font-weight: 760; }
QPushButton:hover { background: #7653e9; }
QPushButton:pressed { background: #5433c5; }
QPushButton:focus { border: 2px solid #087e96; padding: 10px 16px; }
QPushButton[nav="true"]:focus { border: 1px solid #087e96; padding: 12px 13px; }
QPushButton:disabled { background: #e2e6ef; color: #8a93a8; border-color: #d3d9e5; }
QPushButton[quiet="true"] { background: #ffffff; color: #4c5875; border-color: #cbd3e5; }
QPushButton[quiet="true"]:checked { background: rgba(104,66,232,.12); color: #4f2fc5; border-color: rgba(104,66,232,.45); }
QPushButton[danger="true"] { background: #c83363; border-color: #d95079; }
QPushButton[milestone="active"] { background: rgba(104,66,232,.12); color: #4f2fc5; border-color: rgba(104,66,232,.45); }
QPushButton[milestone="done"] { background: rgba(25,145,102,.10); color: #146b50; border-color: rgba(25,145,102,.35); }
QCheckBox { color: #35405c; spacing: 9px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #8792ae; border-radius: 5px; background: white; }
QCheckBox::indicator:checked { background: #0f8fa8; border-color: #0f8fa8; image: url(:/brand/check.svg); }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #aab3c8; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #818ca7; }
QStatusBar { background: #f8f9fd; color: #606b88; border-top: 1px solid #dfe4f1; }
QToolTip { background: #172033; color: white; border: 0; padding: 6px; }
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
QIcon connectionTrayIcon(pqvpn::console::ConnectionPhase phase) {
    const QColor color(QString::fromUtf8(pqvpn::console::phase_color(phase).data()));
    QIcon icon;
    for(int size:{16,24,32,48,64,128}){
        QPixmap frame(size,size);frame.fill(Qt::transparent);QPainter painter(&frame);painter.setRenderHint(QPainter::Antialiasing);painter.scale(size/64.0,size/64.0);
        QPainterPath shield;shield.moveTo(32,5);shield.lineTo(55,16);shield.lineTo(55,32);shield.cubicTo(55,46,46,55,32,59);shield.cubicTo(18,55,9,46,9,32);shield.lineTo(9,16);shield.closeSubpath();
        painter.setPen(QPen(color,4));painter.setBrush(QColor("#10162c"));painter.drawPath(shield);
        QPainterPath eye;eye.moveTo(19,33);eye.cubicTo(27,22,37,22,45,33);eye.cubicTo(37,44,27,44,19,33);
        painter.setPen(QPen(Qt::white,4));painter.setBrush(Qt::NoBrush);painter.drawPath(eye);painter.setPen(Qt::NoPen);painter.setBrush(color);painter.drawEllipse(QPointF(32,33),5,5);painter.end();icon.addPixmap(frame);
    }
    return icon;
}

constexpr bool closeKeepsApplicationRunning(bool quitting) {
    return !quitting;
}

}

class Aurora final : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal phase READ phase WRITE setPhase)
public:
    explicit Aurora(QWidget* parent = nullptr) : QWidget(parent) { setAttribute(Qt::WA_TransparentForMouseEvents); }
    qreal phase() const { return phase_; }
    void setPhase(qreal value) { phase_ = value; update(); }
    void setDark(bool value) { dark_ = value; update(); }
    void setSouls(bool value) { souls_ = value; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), QColor(souls_ ? "#090806" : dark_ ? "#080b17" : "#f4f6fb"));
        const qreal extent = std::max(width(), height()) * .48;
        const QPointF points[] = {{width() * (.12 + .04 * std::sin(phase_)), height() * .17},
            {width() * (.80 + .05 * std::cos(phase_ * .8)), height() * .25},
            {width() * (.55 + .05 * std::sin(phase_ * .6)), height() * .84}};
        const QColor darkColors[] = {QColor(80,43,220,78), QColor(0,201,231,54), QColor(217,65,171,42)};
        const QColor soulsColors[] = {QColor(122,36,28,82), QColor(212,170,85,58), QColor(99,48,20,48)};
        const QColor lightColors[] = {QColor(104,66,232,32), QColor(15,143,168,27), QColor(217,65,171,20)};
        const QColor* colors = souls_ ? soulsColors : dark_ ? darkColors : lightColors;
        for (int i = 0; i < 3; ++i) {
            QRadialGradient gradient(points[i], extent);
            gradient.setColorAt(0, colors[i]); gradient.setColorAt(1, QColor(0,0,0,0));
            painter.setPen(Qt::NoPen); painter.setBrush(gradient);
            painter.drawEllipse(points[i], extent, extent);
        }
    }
private:
    qreal phase_ = 0;
    bool dark_ = true;
    bool souls_ = false;
};

class StatusOrb final : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal pulse READ pulse WRITE setPulse)
public:
    StatusOrb() { setFixedSize(112,112); }
    qreal pulse() const { return pulse_; }
    void setPulse(qreal value) { pulse_ = value; update(); }
    void setConnected(bool value) { connected_ = value; update(); }
    void setSouls(bool value) { souls_ = value; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this); painter.setRenderHint(QPainter::Antialiasing);
        const QPointF center(width()/2.0, height()/2.0);
        const QColor color = souls_ ? (connected_ ? QColor("#d4aa55") : QColor("#9b1c16"))
                                    : (connected_ ? QColor("#65e6ff") : QColor("#ff7aac"));
        painter.setPen(QPen(QColor(color.red(),color.green(),color.blue(),int(80*(1-pulse_))),2));
        painter.setBrush(Qt::NoBrush); painter.drawEllipse(center,34+pulse_*17,34+pulse_*17);
        QRadialGradient glow(center,34); glow.setColorAt(0,color.lighter(140)); glow.setColorAt(.52,color); glow.setColorAt(1,QColor(color.red(),color.green(),color.blue(),12));
        painter.setPen(Qt::NoPen); painter.setBrush(glow); painter.drawEllipse(center,29,29);
        painter.setBrush(Qt::white); painter.drawEllipse(center,7,7);
    }
private:
    qreal pulse_ = 0;
    bool connected_ = false;
    bool souls_ = false;
};

class RetroLobby final : public QWidget {
public:
    explicit RetroLobby(QWidget* parent=nullptr) : QWidget(parent) {
        setMinimumHeight(430);
        setFocusPolicy(Qt::StrongFocus);
        setCursor(Qt::PointingHandCursor);
        setAccessibleName("StrangeNet retro social lobby");
        setToolTip("Move with WASD/arrows, interact with E/Enter, or click a district. Network addresses are never displayed.");
        animation_.setInterval(50);
        connect(&animation_,&QTimer::timeout,this,[this]{
            bool moving=false;
            for(auto it=peers_.begin();it!=peers_.end();++it){
                const double nextX=it->renderX+(it->x-it->renderX)*0.28,nextY=it->renderY+(it->y-it->renderY)*0.28;
                moving=moving||std::abs(nextX-it->renderX)>0.15||std::abs(nextY-it->renderY)>0.15;
                it->renderX=nextX;it->renderY=nextY;
            }
            const qint64 now=QDateTime::currentMSecsSinceEpoch();
            for(auto it=bubbles_.begin();it!=bubbles_.end();)if(it->expiresAt<=now)it=bubbles_.erase(it);else ++it;
            pulse_=(pulse_+1)%120;
            if(moving||!bubbles_.isEmpty()||live_)update();
        });
        animation_.start();
    }
    std::function<void(const QString&)> roomSelected;
    std::function<void(const QString&)> actionSelected;
    std::function<void(const QString&)> districtDiscovered;
    std::function<void(int,int,const QString&,const QString&,const QString&)> worldMoved;
    void setPeerCount(int count){peerCount_=qMax(0,count);update();}
    void setLive(bool live){const bool entered=live&&!live_;live_=live;if(!live){peers_.clear();bubbles_.clear();}if(entered)emitWorld();update();}
    void setRoom(const QString& room){room_=room;update();}
    void removePeer(const QString& peer){peers_.remove(peer);bubbles_.remove(peer);update();}
    void setPeerWorldState(const QString& peer,int x,int y,const QString& zone,const QString& facing,const QString& emote){const bool fresh=!peers_.contains(peer);auto& avatar=peers_[peer];avatar.x=qBound(0,x,1000);avatar.y=qBound(0,y,1000);avatar.zone=zone;avatar.facing=facing;avatar.emote=emote;if(fresh){avatar.renderX=avatar.x;avatar.renderY=avatar.y;}update();}
    void setLocalEmote(const QString& emote){localEmote_=emote;emitWorld();update();}
    void showLocalBubble(const QString& value){setBubble("__local__",value);}
    void showPeerBubble(const QString& peer,const QString& value){if(peers_.contains(peer))setBubble(peer,value);}
    void setFeedback(const QString& stage,const QString& detail){feedbackStage_=stage.toUpper();feedbackDetail_=detail;feedbackUntil_=QDateTime::currentMSecsSinceEpoch()+2600;update();}
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);p.setRenderHint(QPainter::Antialiasing,false);
        p.fillRect(rect(),QColor("#11162a"));
        const QRect scene=rect().adjusted(12,12,-12,-12);
        p.fillRect(scene,QColor("#18203a"));
        p.fillRect(QRect(scene.left(),scene.top(),scene.width(),46),QColor("#27345a"));
        p.setPen(QColor("#7cecff"));QFont title=font();title.setBold(true);title.setLetterSpacing(QFont::AbsoluteSpacing,1.5);p.setFont(title);
        p.drawText(scene.adjusted(14,0,-14,scene.height()-46),Qt::AlignVCenter|Qt::AlignLeft,"PQVPN PRIVACY CITY · "+room_);
        p.setPen(QColor(live_?"#70efbc":"#aab5d2"));p.drawText(scene.adjusted(14,0,-14,scene.height()-46),Qt::AlignVCenter|Qt::AlignRight,live_?"● LIVE E2E":"○ SAFE PREVIEW");
        const int floorTop=scene.top()+46;floor_=QRect(scene.left()+8,floorTop+8,scene.width()-16,scene.height()-66);p.fillRect(floor_,QColor("#243050"));
        const int tile=qMax(12,floor_.width()/34);for(int y=floor_.top();y<floor_.bottom();y+=tile)for(int x=floor_.left();x<floor_.right();x+=tile){const bool alternate=((x-floor_.left())/tile+(y-floor_.top())/tile)%2;p.fillRect(QRect(x,y,tile,tile),QColor(alternate?"#2d3b60":"#334369"));}
        const struct ZonePaint{QRect area;const char* name;const char* key;const char* action;QColor color;} zones[]{
            {normalizedRect(18,18,218,172),"GATE\nCONNECT","gate","connect",QColor("#4d3b71")},
            {normalizedRect(782,18,982,172),"FORGE\nTRANSPORTS","forge","transports",QColor("#713d39")},
            {normalizedRect(18,828,218,982),"GARDEN\nSHIELD","garden","shield",QColor("#315f55")},
            {normalizedRect(782,828,982,982),"COMMONS\nCHAT","commons","conversation",QColor("#31507b")}};
        zoneActions_.clear();for(const auto& zone:zones){zoneActions_.append({zone.area,QString::fromLatin1(zone.action)});p.fillRect(zone.area,zone.color);p.setPen(QColor("#dbe3ff"));p.drawText(zone.area,Qt::AlignCenter,zone.name);}
        drawWorldFurniture(p);
        p.setPen(QColor("#96a7d0"));p.drawText(floor_.adjusted(210,8,-210,-8),Qt::AlignHCenter|Qt::AlignTop,"WASD / arrows move · E / Enter interacts · click districts · chat appears above avatars");
        auto drawAvatar=[&](double nx,double ny,const QColor& color,const QString& label,const QString& emote,const QString& bubbleKey){const QPoint point=toScene(qRound(nx),qRound(ny));const int bob=(emote=="cheer")?qRound(std::abs(std::sin(pulse_/6.0))*5.0):0;p.setPen(Qt::NoPen);p.setBrush(QColor(0,0,0,70));p.drawEllipse(QRect(point.x()-13,point.y()+13,26,8));p.setBrush(color);p.drawRect(point.x()-7,point.y()-18-bob,14,14);p.drawRect(point.x()-11,point.y()-3-bob,22,18);p.setBrush(color.lighter(125));p.drawRect(point.x()-10,point.y()+14-bob,8,8);p.drawRect(point.x()+2,point.y()+14-bob,8,8);p.setPen(QColor("#11162a"));p.drawPoint(point.x()-3,point.y()-13-bob);p.drawPoint(point.x()+3,point.y()-13-bob);const QPoint pet(point.x()+20,point.y()+10-bob);p.setPen(QPen(QColor("#11162a"),1));p.setBrush(color.lighter(150));p.drawRect(QRect(pet.x()-5,pet.y()-5,10,9));p.drawPoint(pet.x()-2,pet.y()-2);p.drawPoint(pet.x()+2,pet.y()-2);p.setPen(QColor("#f5f7ff"));p.drawText(QRect(point.x()-42,point.y()+23,84,16),Qt::AlignCenter,label);if(emote!="none"&&!emote.isEmpty()){p.setPen(QColor("#ffd166"));p.drawText(QRect(point.x()-40,point.y()-42-bob,80,16),Qt::AlignCenter,emote.toUpper());}drawBubble(p,point,bubbleKey,bob);};
        if(live_)drawAvatar(localX_,localY_,QColor("#65e6ff"),"YOU",localEmote_,"__local__");
        int index=0;for(auto it=peers_.cbegin();it!=peers_.cend()&&index<32;++it,++index)drawAvatar(it->renderX,it->renderY,QStringList{"#ff7aac","#70efbc","#ffd166","#9d8cff"}[qAbs(qHash(it.key()))%4],it.key().left(6)+"…",it->emote,it.key());
        const int progress=qMin(100,visited_.size()*25);p.fillRect(QRect(floor_.left()+8,floor_.bottom()-13,180,6),QColor("#12182b"));p.fillRect(QRect(floor_.left()+8,floor_.bottom()-13,180*progress/100,6),QColor("#70efbc"));p.setPen(QColor("#d4dcf2"));p.drawText(floor_.adjusted(198,0,-8,-5),Qt::AlignRight|Qt::AlignBottom,QString("%1 present · city map %2% · %3").arg(peers_.size()+1).arg(progress).arg(localZone_.toUpper()));
        if(feedbackUntil_>QDateTime::currentMSecsSinceEpoch()){const QRect feedback(floor_.left()+8,floor_.top()+34,310,28);p.setPen(QPen(QColor("#65e6ff"),1));p.setBrush(QColor(8,13,31,220));p.drawRoundedRect(feedback,8,8);p.setPen(QColor("#7cecff"));p.drawText(feedback.adjusted(9,0,-9,0),Qt::AlignVCenter|Qt::AlignLeft,"CRF · "+feedbackStage_+" · "+feedbackDetail_);}
        if(hasFocus()){p.setPen(QPen(QColor("#7cecff"),2,Qt::DashLine));p.setBrush(Qt::NoBrush);p.drawRect(scene.adjusted(2,2,-3,-3));}
    }
    void mousePressEvent(QMouseEvent* event) override {setFocus();const QPoint point=event->position().toPoint();for(const auto& zone:zoneActions_)if(zone.first.contains(point)){if(actionSelected)actionSelected(zone.second);event->accept();return;}if(!live_||!floor_.contains(point))return;tryMove((point.x()-floor_.left())*1000/qMax(1,floor_.width()),(point.y()-floor_.top())*1000/qMax(1,floor_.height()));event->accept();}
    void keyPressEvent(QKeyEvent* event) override {if(event->key()==Qt::Key_Return||event->key()==Qt::Key_Enter||event->key()==Qt::Key_E||event->key()==Qt::Key_Space){interact();event->accept();return;}int dx=0,dy=0;switch(event->key()){case Qt::Key_Left:case Qt::Key_A:dx=-38;facing_="west";break;case Qt::Key_Right:case Qt::Key_D:dx=38;facing_="east";break;case Qt::Key_Up:case Qt::Key_W:dy=-38;facing_="north";break;case Qt::Key_Down:case Qt::Key_S:dy=38;facing_="south";break;default:QWidget::keyPressEvent(event);return;}if(!live_){showLocalBubble("ENTER A ROOM TO WALK");return;}tryMove(localX_+dx,localY_+dy);event->accept();}
private:
    struct Avatar{int x=500,y=500;double renderX=500,renderY=500;QString zone="commons",facing="south",emote="none";};
    struct Bubble{QString text;qint64 expiresAt=0;};
    QPoint toScene(int x,int y)const{return {floor_.left()+x*floor_.width()/1000,floor_.top()+y*floor_.height()/1000};}
    QRect normalizedRect(int left,int top,int right,int bottom)const {const QPoint a=toScene(left,top),b=toScene(right,bottom);return QRect(a,b).normalized();}
    QString zoneFor(int x,int y)const {if(x<260)return y<500?"gate":"garden";if(x>740)return y<500?"forge":"commons";return "commons";}
    bool walkable(int x,int y)const {if(x<22||x>978||y<22||y>978)return false;const QPoint candidate(x,y);const QList<QRect> blockers{QRect(430,360,140,210),QRect(315,205,115,70),QRect(570,650,115,70),QRect(300,760,95,60),QRect(620,220,95,60)};for(const QRect& blocker:blockers)if(blocker.adjusted(-18,-28,18,18).contains(candidate))return false;return true;}
    void tryMove(int x,int y){x=qBound(0,x,1000);y=qBound(0,y,1000);if(!walkable(x,y)){setBubble("__local__","THAT WAY IS BLOCKED",1600);return;}localX_=x;localY_=y;localEmote_="none";updateZone();emitWorld();update();}
    void updateZone(){const QString next=zoneFor(localX_,localY_);if(next!=localZone_){localZone_=next;const bool discovered=!visited_.contains(localZone_);visited_.insert(localZone_);setBubble("__local__",QString("DISCOVERED %1 · %2/4").arg(localZone_.toUpper()).arg(visited_.size()),2500);if(discovered&&districtDiscovered)districtDiscovered(localZone_);}else localZone_=next;}
    void interact(){const QHash<QString,QString> actions{{"gate","connect"},{"forge","transports"},{"garden","shield"},{"commons","conversation"}};if(actionSelected)actionSelected(actions.value(localZone_,"conversation"));}
    void setBubble(const QString& key,const QString& value,int duration=6500){QString clean=value.simplified();if(clean.size()>72)clean=clean.left(69)+"…";if(clean.isEmpty())return;bubbles_[key]={clean,QDateTime::currentMSecsSinceEpoch()+duration};update();}
    void drawBubble(QPainter& p,const QPoint& point,const QString& key,int bob){const auto it=bubbles_.constFind(key);if(it==bubbles_.cend())return;QFont bubbleFont=font();bubbleFont.setPixelSize(11);bubbleFont.setBold(true);p.setFont(bubbleFont);const int width=qBound(92,QFontMetrics(bubbleFont).horizontalAdvance(it->text)+22,240);QRect bubble(point.x()-width/2,point.y()-72-bob,width,28);bubble.moveLeft(qBound(floor_.left()+3,bubble.left(),floor_.right()-width-3));p.setPen(QPen(QColor("#11162a"),2));p.setBrush(QColor("#f5f7ff"));p.drawRoundedRect(bubble,8,8);QPainterPath tail;tail.moveTo(point.x()-5,bubble.bottom());tail.lineTo(point.x(),bubble.bottom()+8);tail.lineTo(point.x()+5,bubble.bottom());p.drawPath(tail);p.setPen(QColor("#151a2e"));p.drawText(bubble.adjusted(8,2,-8,-2),Qt::AlignCenter,it->text);}
    void drawWorldFurniture(QPainter& p){const QRect fountain=normalizedRect(430,360,570,570);p.setPen(QPen(QColor("#7cecff"),3));p.setBrush(QColor("#263d66"));p.drawEllipse(fountain);p.setBrush(QColor("#65e6ff"));const int wave=qRound(std::sin(pulse_/8.0)*4.0);p.drawEllipse(fountain.adjusted(34+wave,34+wave,-34-wave,-34-wave));const QList<QPair<QRect,QColor>> furniture{{normalizedRect(315,205,430,275),QColor("#845b3b")},{normalizedRect(570,650,685,720),QColor("#845b3b")},{normalizedRect(300,760,395,820),QColor("#3e765b")},{normalizedRect(620,220,715,280),QColor("#85485f")}};for(const auto& item:furniture){p.setPen(QColor("#151a2e"));p.setBrush(item.second);p.drawRect(item.first);}p.setPen(QColor("#c9d4f4"));p.drawText(normalizedRect(390,585,610,635),Qt::AlignCenter,"THE ZERO-TRUST FOUNTAIN");}
    void emitWorld(){if(live_&&worldMoved)worldMoved(localX_,localY_,localZone_,facing_,localEmote_);}
    QString room_="mainnet/friends",localZone_="commons",facing_="south",localEmote_="none",feedbackStage_="READY",feedbackDetail_="local preview";QRect floor_;QList<QPair<QRect,QString>> zoneActions_;QHash<QString,Avatar> peers_;QHash<QString,Bubble> bubbles_;QSet<QString> visited_{"commons"};QTimer animation_;qint64 feedbackUntil_=0;int localX_=500,localY_=650,peerCount_=0,pulse_=0;bool live_=false;
};

class ResponsiveStack final : public QStackedWidget {
public:
    ResponsiveStack() { connect(this,&QStackedWidget::currentChanged,this,[this]{updateGeometry();}); }
    QSize sizeHint() const override { return currentWidget()?currentWidget()->sizeHint():QSize{}; }
    QSize minimumSizeHint() const override {
        const QSize hint=currentWidget()?currentWidget()->minimumSizeHint():QSize{};
        return {0,hint.height()};
    }
};

class StableScrollArea final : public QScrollArea {
public:
    StableScrollArea() {
        const QString platform=qEnvironmentVariable("QT_QPA_PLATFORM");
        const bool headless=platform=="offscreen"||platform=="minimal";
        const bool software=QApplication::arguments().contains("--software-rendering")||QApplication::arguments().contains("--smoke-test")||qEnvironmentVariableIsSet("PQVPN_DISABLE_OPENGL");
        // QOpenGLWidget is opt-in for the scroll viewport. On Wayland/GNOME,
        // embedding child controls in an OpenGL QAbstractScrollArea viewport
        // can produce stale frames and incorrect mouse hit coordinates after
        // scrolling. The native raster viewport is both faster for widgets and
        // reliable for buttons; OpenGL remains available for diagnostics.
        const bool openGlRequested=qEnvironmentVariableIntValue("PQVPN_ENABLE_OPENGL")>0;
        if(openGlRequested&&!headless&&!software){
            auto* glViewport=new QOpenGLWidget;
            glViewport->setUpdateBehavior(QOpenGLWidget::NoPartialUpdate);
            setViewport(glViewport);
            openGlViewport_=true;
        }
    }
    bool usesOpenGL() const { return openGlViewport_; }
protected:
    void scrollContentsBy(int dx,int dy) override {
        QScrollArea::scrollContentsBy(dx,dy);
        // Repaint the complete OpenGL surface after QScrollArea moves its child.
        // This avoids stale pixel copies on Wayland compositors.
        viewport()->update();
    }
private:
    bool openGlViewport_=false;
};

class ChatComposer final : public QPlainTextEdit {
public:
    explicit ChatComposer(QWidget* parent=nullptr) : QPlainTextEdit(parent) {
        setTabChangesFocus(true);
        setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    }
    void setPoemMode(bool enabled) { poemMode_=enabled; }
    std::function<void()> submit;
protected:
    void keyPressEvent(QKeyEvent* event) override {
        const bool enter=event->key()==Qt::Key_Return||event->key()==Qt::Key_Enter;
        if(!enter){QPlainTextEdit::keyPressEvent(event);return;}
        const auto modifiers=event->modifiers();
        const bool explicitSubmit=modifiers.testFlag(Qt::ControlModifier)||modifiers.testFlag(Qt::MetaModifier);
        const bool newline=(poemMode_&&!explicitSubmit)||(!poemMode_&&modifiers.testFlag(Qt::ShiftModifier));
        if(newline){QPlainTextEdit::keyPressEvent(event);return;}
        if(submit)submit();
        event->accept();
    }
private:
    bool poemMode_=false;
};

class Window final : public QMainWindow {
    Q_OBJECT
public:
    Window() {
        setWindowTitle("PQVPN");
        setWindowIcon(QIcon(":/brand/logo.svg"));
        setMinimumSize(940,650); resize(1240,800); setAcceptDrops(true);
        process_.setProcessChannelMode(QProcess::MergedChannels);
        buildMenus(); buildUi(); buildTray(); connectProcess(); applyPreferences(); applyStartupArguments(); loadConfig(configPath_->text());
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
        connect(QGuiApplication::styleHints(),&QStyleHints::colorSchemeChanged,this,[this](Qt::ColorScheme){if(themeMode_=="system")applyTheme("system");});
#else
        connect(qApp,&QGuiApplication::paletteChanged,this,[this](const QPalette& palette){systemDark_=palette.color(QPalette::Window).lightness()<128;if(themeMode_=="system")applyTheme("system");});
#endif
        statusBar()->showMessage("Ready — no connection starts without your action");
        QTimer::singleShot(0,this,[this]{ if(!configValid_ && !QApplication::arguments().contains("--smoke-test")) validateConfig(false); });
    }
    void prepareSmokePage(const QString& request) {
        QSignalBlocker guard(reduceMotion_); reduceMotion_->setChecked(true); setMotion(false);
        const QHash<QString,int> pages{{"connection",Connection},{"transports",Transports},{"strangenet",StrangeNet},{"wallet",Wallet},{"shield",Shield},{"activity",Activity},{"privacy",Privacy},{"about",About}};
        switchPage(pages.value(request,Overview)); QApplication::processEvents();
    }
    bool verifyInstallation() const {
        if(!QFileInfo(executablePath_->text()).isExecutable()){qCritical().noquote()<<"PQVPN installation check: node is not executable:"<<executablePath_->text();return false;}
        if(!QFileInfo(configPath_->text()).isFile()){qCritical().noquote()<<"PQVPN installation check: configuration is not a file:"<<configPath_->text();return false;}
        QProcess check;check.start(executablePath_->text(),{"--validate-config","--config",configPath_->text()});
        if(!check.waitForStarted(5000)){qCritical().noquote()<<"PQVPN installation check: could not start node:"<<check.errorString();return false;}
        if(!check.waitForFinished(10000)){check.kill();check.waitForFinished();qCritical()<<"PQVPN installation check: node validation timed out";return false;}
        if(check.exitStatus()!=QProcess::NormalExit||check.exitCode()!=0){qCritical().noquote()<<"PQVPN installation check: node validation failed with exit code"<<check.exitCode()<<QString::fromUtf8(check.readAll()).trimmed();return false;}
        return true;
    }
    bool verifyTrayIcons() const {
        using pqvpn::console::ConnectionPhase;
        for(auto phase:{ConnectionPhase::Disconnected,ConnectionPhase::Connecting,ConnectionPhase::Protected,ConnectionPhase::Failed}){
            const auto image=connectionTrayIcon(phase).pixmap(64,64).toImage();
            if(image.isNull()||image.pixelColor(32,33)!=QColor(QString::fromUtf8(pqvpn::console::phase_color(phase).data())))return false;
        }
        return true;
    }
    bool verifyVisualLayout() const {
        const auto fail=[](const QString& message){qCritical().noquote()<<message;const QString image=qEnvironmentVariable("PQVPN_SMOKE_IMAGE");if(!image.isEmpty()){QFile diagnostic(image+".error.txt");if(diagnostic.open(QIODevice::WriteOnly|QIODevice::Truncate))diagnostic.write(message.toUtf8());}return false;};
        // On Qt's offscreen Windows plugin, inFont('A') can return false for a
        // generic font even when Qt actually rasterizes the Latin glyph. Keep
        // the coverage check, but verify rendered glyph ink rather than trusting
        // only the font-database metadata.
        const auto rendersDistinctLatinGlyphs=[](const QFont& font){
            const auto render=[&font](QChar glyph){
                QImage ink(96,96,QImage::Format_ARGB32_Premultiplied);
                ink.fill(Qt::transparent);
                QPainter painter(&ink);
                painter.setRenderHint(QPainter::TextAntialiasing,true);
                painter.setPen(Qt::white);
                painter.setFont(font);
                painter.drawText(QPoint(8,64),QString(glyph));
                painter.end();
                return ink;
            };
            const QImage a=render(QChar('A'));
            const QImage w=render(QChar('W'));
            if(a==w) return false; // identical replacement glyphs or no ink
            const auto hasInk=[](const QImage& image){
                for(int y=0;y<image.height();++y)
                    for(int x=0;x<image.width();++x)
                        if(qAlpha(image.pixel(x,y))!=0) return true;
                return false;
            };
            return hasInk(a)&&hasInk(w);
        };
        QSet<QString> checkedFonts;
        const auto labels=findChildren<QLabel*>();
        for(const auto* label:labels){
            if(!label->isVisible()||!label->text().contains(QRegularExpression("[A-Za-z]"))) continue;
            if(label->fontMetrics().inFont(QChar('A'))) continue;
            const QFont font=label->font();
            const QString key=font.toString();
            if(checkedFonts.contains(key)) continue;
            if(!rendersDistinctLatinGlyphs(font))
                return fail("PQVPN visual check: UI font failed Latin glyph raster check: "+font.family());
            checkedFonts.insert(key);
        }
        const auto* scroll=findChild<QScrollArea*>("pageScroll");
        if(!scroll)return fail("PQVPN visual check: page scroll area is missing");
        if(scroll->horizontalScrollBar()->maximum()>2)return fail(QString("PQVPN visual check: page has horizontal overflow: %1 px").arg(scroll->horizontalScrollBar()->maximum()));
        return true;
    }
    bool verifyScrollNavigation() {
        if(!pageScroll_)return false;
        setMotion(false);
        bool exercisedScrolling=false;
        for(int index=0;index<pages_->count();++index){
            pages_->setCurrentIndex(index);
            pageScroll_->verticalScrollBar()->setValue(0);
            QApplication::processEvents();
            const int maximum=pageScroll_->verticalScrollBar()->maximum();
            const QImage before=pageScroll_->viewport()->grab().toImage();
            if(maximum>0){
                exercisedScrolling=true;
                for(int step=1;step<=6;++step){pageScroll_->verticalScrollBar()->setValue(maximum*step/6);QApplication::processEvents();}
                pageScroll_->verticalScrollBar()->setValue(0);
                QApplication::processEvents();
                const QImage after=pageScroll_->viewport()->grab().toImage();
                if(before.isNull()||after.isNull()||before.size()!=after.size()){
                    qCritical()<<"PQVPN rendering check: viewport changed after a round-trip scroll on page"<<index;
                    return false;
                }
                qint64 changedPixels=0;
                const qint64 totalPixels=qint64(before.width())*before.height();
                for(int y=0;y<before.height();++y)for(int x=0;x<before.width();++x){
                    const QColor lhs=before.pixelColor(x,y),rhs=after.pixelColor(x,y);
                    if(std::abs(lhs.red()-rhs.red())>16||std::abs(lhs.green()-rhs.green())>16||std::abs(lhs.blue()-rhs.blue())>16||std::abs(lhs.alpha()-rhs.alpha())>16)++changedPixels;
                }
                if(totalPixels>0&&changedPixels*100>totalPixels*2){
                    qCritical()<<"PQVPN rendering check: excessive viewport residue after scrolling page"<<index<<changedPixels<<"of"<<totalPixels<<"pixels";
                    return false;
                }
                pageScroll_->verticalScrollBar()->setValue(maximum);
            }
            QApplication::processEvents();
            const int next=(index+1)%pages_->count();
            pageButtons_.value(next)->click();
            QApplication::processEvents();
            if(pages_->currentIndex()!=next||pageScroll_->verticalScrollBar()->value()!=0){
                qCritical()<<"PQVPN interaction check: navigation failed after scrolling"<<index<<next;
                return false;
            }
            const QImage frame=pageScroll_->viewport()->grab().toImage();
            if(frame.isNull()){
                qCritical()<<"PQVPN interaction check: scroll viewport did not render";
                return false;
            }
        }
        if(!exercisedScrolling)qInfo()<<"PQVPN interaction check: all pages fit without scrolling at this platform's smoke-test size";
        return true;
    }
    bool verifyPrimaryActions() {
        if(!journeyConfigure_||!journeyAuthenticate_||!journeyProtect_)return false;
        const bool restoreGeek=geekTelemetry_&&geekTelemetry_->isChecked();
        setGeekMode(false);for(auto* widget:geekWidgets_)if(widget&&!widget->isHidden())return false;
        setGeekMode(true);for(auto* widget:geekWidgets_)if(widget&&widget->isHidden())return false;
        setGeekMode(restoreGeek);
        journeyConfigure_->click();QApplication::processEvents();if(pages_->currentIndex()!=Connection)return false;
        journeyAuthenticate_->click();QApplication::processEvents();if(pages_->currentIndex()!=Connection)return false;
        journeyProtect_->click();QApplication::processEvents();if(pages_->currentIndex()!=Connection)return false;
        pageButtons_.value(Overview)->click();QApplication::processEvents();
        return pages_->currentIndex()==Overview;
    }
    bool verifyControlSurfaceSanity() {
        const auto fail=[](const QString& message){qCritical()<<message;return false;};
        if(!menuBar()||menuBar()->actions().size()<3)
            return fail("PQVPN interaction check: expected File, View and Tools menus");
        for(const auto* rootAction:menuBar()->actions()){
            if(!rootAction||rootAction->text().trimmed().isEmpty()||!rootAction->menu()||rootAction->menu()->actions().isEmpty())
                return fail("PQVPN interaction check: empty or unusable top-level menu");
            for(const auto* action:rootAction->menu()->actions())
                if(action&&!action->isSeparator()&&action->text().trimmed().isEmpty())
                    return fail("PQVPN interaction check: menu contains an unlabeled action");
        }
        for(const auto* button:findChildren<QPushButton*>())
            if(button&&button->text().trimmed().isEmpty())
                return fail("PQVPN interaction check: push button has no accessible label");
        if(navButtons_.size()!=pages_->count()||sidebarSections_.size()!=3)
            return fail("PQVPN interaction check: navigation information architecture is incomplete");
        for(const auto* button:navButtons_){
            if(button->property("fullText").toString().isEmpty()||button->property("compactText").toString().isEmpty()||
               button->property("fullText").toString().contains(QRegularExpression("^\\s*\\d")))
                return fail("PQVPN interaction check: navigation must use meaningful labels, never ordinal numbers");
        }
        const QList<QPushButton*> required{
            overviewAction_,connectButton_,validateButton_,saveTransportButton_,innerTunnelBrowse_,
            strangeJoin_,strangeSend_,strangeReply_,strangeVoice_,strangeReaction_,strangeBoost_,
            strangeSearchNext_,strangeCopyPeer_,strangeBlockPeer_,strangeManageBlocked_,
            strangeShareProfile_,researchEnable_,researchDisable_,shieldApply_,shieldRefresh_,speedRun_};
        for(const auto* button:required)
            if(!button)return fail("PQVPN interaction check: required GUI action was not constructed");
        if(!strangeLobby_||strangeLobby_->minimumHeight()<430||strangeWorldButtons_.size()!=4)
            return fail("PQVPN interaction check: Privacy City interaction surface is incomplete");
        if(!themeGroup_||themeGroup_->actions().size()!=4||!reduceMotion_||!compactSidebar_||
           !geekTelemetry_||!strangeNotifications_||!automaticUpdates_||!installUpdate_||!trayMenu_||trayMenu_->actions().size()<5)
            return fail("PQVPN interaction check: menu or tray action set is incomplete");
        return true;
    }
    void prepareSmokeTheme(const QString& request) { applyTheme(request); QApplication::processEvents(); }
    bool verifyClosePolicy() const {
        return closeKeepsApplicationRunning(false) && !closeKeepsApplicationRunning(true);
    }
protected:
    void closeEvent(QCloseEvent* event) override {
        if (closeKeepsApplicationRunning(quitting_)) {
            savePreferences();
            const bool trayReady=tray_&&tray_->isVisible()&&QSystemTrayIcon::isSystemTrayAvailable();
            if(trayReady){
                hide();
                if(!trayNoticeShown_){tray_->showMessage("PQVPN is still running","The window was moved to the tray. Use Exit PQVPN to stop the application.",QSystemTrayIcon::Information,5000);trayNoticeShown_=true;}
            }else{
                // Never strand a running connection when the desktop has no
                // StatusNotifier/AppIndicator host. Keep a recoverable taskbar
                // window instead of interpreting the title-bar X as Exit.
                showMinimized();
                statusBar()->showMessage("PQVPN is still running · use File → Exit PQVPN to quit",5000);
            }
            event->ignore();
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
        if(process_.state()!=QProcess::NotRunning){event->ignore();log("Disconnect before changing configuration.");return;}
        const QString path=event->mimeData()->urls().constFirst().toLocalFile();
        if (loadConfig(path)) { configPath_->setText(path); log("Configuration selected · "+QDir::toNativeSeparators(path)); event->acceptProposedAction(); }
    }
protected:
    void resizeEvent(QResizeEvent* event) override {
        QMainWindow::resizeEvent(event);
        updateResponsiveChrome();
    }
private:
    void applySidebarWidth(bool compact) {
        if(!sidebar_||!brandWords_)return;
        const int target=compact?82:238;
        if(sidebar_->width()==target&&sidebar_->minimumWidth()==target)return;
        brandWords_->setVisible(!compact);for(auto* section:sidebarSections_)section->setVisible(!compact);
        for(auto* button:navButtons_){button->setText(compact?button->property("compactText").toString():button->property("fullText").toString());button->setToolTip(button->property("fullText").toString());}
        sidebar_->setFixedWidth(target);
    }
    void updateResponsiveChrome() {
        const…29718 tokens truncated…leDialog::getOpenFileName(this,"Choose existing "+id+" configuration",QDir::homePath());
        if(!path.isEmpty())settings.setValue(id+"ConfigPath",QFileInfo(path).absoluteFilePath());
        return path;
    }
    void editConfiguration(const QString& path,bool json){
        QFile source(path);if(!source.open(QIODevice::ReadOnly)||source.size()>1024*1024){QMessageBox::information(this,"Configuration unavailable","Choose an existing configuration file first.");return;}
        QDialog dialog(this);dialog.setWindowTitle("Edit configuration");dialog.resize(760,560);auto* layout=new QVBoxLayout(&dialog);auto* editor=new QPlainTextEdit;editor->setPlainText(QString::fromUtf8(source.readAll()));source.close();layout->addWidget(editor);auto* row=new QHBoxLayout;auto* cancel=new QPushButton("Cancel");auto* save=new QPushButton("Save");row->addWidget(cancel);row->addStretch();row->addWidget(save);layout->addLayout(row);connect(cancel,&QPushButton::clicked,&dialog,&QDialog::reject);
        connect(save,&QPushButton::clicked,&dialog,[&,this]{const QByteArray contents=editor->toPlainText().toUtf8();if(contents.size()>1024*1024)return;if(json){QJsonParseError error;const auto document=QJsonDocument::fromJson(contents,&error);if(error.error!=QJsonParseError::NoError||!document.isObject()){QMessageBox::information(&dialog,"Invalid configuration","Configuration must be a JSON object.");return;}}QSaveFile output(path);if(!output.open(QIODevice::WriteOnly)||!output.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)||output.write(contents)!=contents.size()||!output.commit()){QMessageBox::information(&dialog,"Save failed","The configuration could not be saved.");return;}if(QFileInfo(path).absoluteFilePath()==QFileInfo(configPath_->text()).absoluteFilePath()){invalidate("Configuration edited. Validate before connecting.");loadConfig(path);}dialog.accept();});dialog.exec();
    }
    void prepareUdp2rawProfile(){
        if(process_.state()!=QProcess::NotRunning){log("Disconnect before changing transport profiles.");return;}
        QJsonObject root;QFile source(configPath_->text());
        if(source.open(QIODevice::ReadOnly)){const auto document=QJsonDocument::fromJson(source.readAll());if(document.isObject())root=document.object();}
        if(root.isEmpty()){QMessageBox::information(this,"Choose configuration","Choose your existing PQVPN server configuration first. Engine keys stay in the engine's own configuration.");switchPage(Connection);return;}
        QSettings settings("PQVPN","Privacy Console");QString engineConfig=settings.value("udp2rawConfigPath").toString();
        if(!QFileInfo(engineConfig).isFile()){
            for(const QString& candidate:{QString::fromStdString((pqvpn::console::user_profile_directory()/"udp2raw.conf").generic_string()),QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)+"/udp2raw.conf",QDir::homePath()+"/.config/udp2raw/client.conf"})if(QFileInfo(candidate).isFile()){engineConfig=candidate;break;}
        }
        QString host="127.0.0.1";int port=9091;
        const auto existing=root.value("external_transport").toObject();const QString existingHost=existing.value("host").toString();const int existingPort=existing.value("port").toInt();
        if(existing.value("engine").toString()=="udp2raw"&&(existingHost=="127.0.0.1"||existingHost=="::1")&&existingPort>0&&existingPort<=65535){host=existingHost;port=existingPort;}
        if(QFileInfo(engineConfig).isFile()){
            QFile engine(engineConfig);if(!engine.open(QIODevice::ReadOnly))return;
            // Read only the local listener directive for coordination; never
            // copy or print engine credentials into the PQVPN profile/log.
            const QString contents=QString::fromUtf8(engine.read(1024*1024));
            const auto match=QRegularExpression("(?:^|\\n)\\s*-l\\s*(127\\.0\\.0\\.1|\\[::1\\]):([0-9]+)").match(contents);
            if(!match.hasMatch()){QMessageBox::information(this,"Local listener required","The existing udp2raw configuration needs a loopback -l listener. Review that configuration before connecting.");return;}
            host=match.captured(1)=="[::1]"?"::1":match.captured(1);port=match.captured(2).toInt();if(port<1||port>65535)return;
        }
        auto network=root.value("network").toObject();network["bind_address"]=host;if(network.value("port").toInt(9090)==port)network["port"]=port==9090?9092:9090;root["network"]=network;
        root["bootstrap"]=QJsonArray{QJsonObject{{"host",host},{"port",port}}};
        root["external_transport"]=QJsonObject{{"version",1},{"mode","attach"},{"engine","udp2raw"},{"host",host},{"port",port}};
        auto security=root.value("security").toObject();security["strict_sig_verify"]=true;
        const QString directory=QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)+"/profiles";if(!QDir().mkpath(directory))return;
        const QString known=security.value("known_peers_file").toString("known_peers.json");const QString originalKnown=QFileInfo(known).isRelative()?QFileInfo(configPath_->text()).dir().absoluteFilePath(known):known;const QString profileKnown=directory+"/known_peers.json";
        if(!QFileInfo(profileKnown).exists()&&QFileInfo(originalKnown).isFile()){if(!QFile::copy(originalKnown,profileKnown))return;QFile::setPermissions(profileKnown,QFileDevice::ReadOwner|QFileDevice::WriteOwner);}
        QString identity=security.value("identity_file").toString("node_keys.json");if(identity.isEmpty())identity="node_keys.json";
        const QString originalIdentity=QFileInfo(identity).isRelative()?QFileInfo(configPath_->text()).dir().absoluteFilePath(identity):identity;
        security["identity_file"]=QDir::cleanPath(QFileInfo(originalIdentity).absoluteFilePath());
        security["known_peers_file"]=profileKnown;root["security"]=security;
        QString profile=directory+"/udp2raw.json";if(QFileInfo(profile).exists()&&QDir::cleanPath(QFileInfo(configPath_->text()).absoluteFilePath())!=QDir::cleanPath(profile))profile=directory+"/udp2raw-"+QString::number(QDateTime::currentMSecsSinceEpoch())+".json";QSaveFile output(profile);if(!output.open(QIODevice::WriteOnly))return;if(!output.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner))return;const auto profileBytes=QJsonDocument(root).toJson(QJsonDocument::Indented);if(output.write(profileBytes)!=profileBytes.size()||!output.commit())return;
        configPath_->setText(profile);invalidate("Local udp2raw profile prepared. Verify the engine and server before connecting.");loadConfig(profile);switchPage(Connection);validateConfig();
        if(QFileInfo(engineConfig).isFile()){engines_->start("udp2raw",engineConfig);return;}
        QString executable;for(const QString& name:{QString("udp2raw"),QString("udp2raw_amd64"),QString("udp2raw_arm64"),QString("udp2raw_arm"),QString("udp2raw_mp")}){executable=QStandardPaths::findExecutable(name);if(!executable.isEmpty())break;}
        log(executable.isEmpty()?"udp2raw engine not found on PATH. Attach mode requires your installed forwarder.":"udp2raw executable detected; attach mode requires the engine to be running with your server configuration.");
    }
    void saveTransportSettings(){
        QFile source(configPath_->text());if(!source.open(QIODevice::ReadOnly)){log("Transport policy was not saved · configuration unavailable");return;}const QByteArray original=source.readAll();QJsonParseError error;auto document=QJsonDocument::fromJson(original,&error);source.close();if(error.error!=QJsonParseError::NoError||!document.isObject()){log("Transport policy was not saved · invalid JSON");return;}
        auto root=document.object();auto adaptive=root.value("adaptive_transport").toObject();adaptive["enabled"]=adaptiveEnabled_->isChecked();adaptive["mode"]=adaptiveMode_->currentData().toString();if(!adaptive.contains("loss_switch_percent"))adaptive["loss_switch_percent"]=12.0;if(!adaptive.contains("jitter_switch_ms"))adaptive["jitter_switch_ms"]=45.0;if(!adaptive.contains("failure_switch_count"))adaptive["failure_switch_count"]=3;if(!adaptive.contains("recovery_probe_count"))adaptive["recovery_probe_count"]=4;if(!adaptive.contains("minimum_dwell_ms"))adaptive["minimum_dwell_ms"]=5000;root["adaptive_transport"]=adaptive;
        auto shaping=root.value("traffic_shaping").toObject();shaping["enabled"]=shapingEnabled_->isChecked();shaping["mode"]=shapingMode_->currentData().toString();shaping["max_padding_bytes"]=shapingPadding_->value();shaping["max_delay_ms"]=shapingDelay_->value();if(!shaping.contains("max_queue_packets"))shaping["max_queue_packets"]=256;if(!shaping.contains("max_queue_bytes"))shaping["max_queue_bytes"]=524288;root["traffic_shaping"]=shaping;
        auto nativeTunnel=root.value("tunnel").toObject();if(nativeTunnel.value("plugin").toString()=="wireguard"||nativeTunnel.value("plugin").toString()=="openvpn"){nativeTunnel["plugin"]="pqvpn";nativeTunnel.remove("config_path");root["tunnel"]=nativeTunnel;}if(innerTunnelEnabled_->isChecked()){const QFileInfo innerConfig(innerTunnelConfig_->text());if(!innerConfig.isAbsolute()||!innerConfig.isFile()){QMessageBox::warning(this,"Inner VPN configuration","Choose an existing absolute WireGuard or OpenVPN 3 client configuration.");return;}root["inner_tunnel"]=QJsonObject{{"enabled",true},{"backend",innerTunnelBackend_->currentData().toString()},{"config_path",innerConfig.absoluteFilePath()}};}else root.remove("inner_tunnel");
        document.setObject(root);const QByteArray updated=document.toJson(QJsonDocument::Indented);if(updated==original){statusBar()->showMessage("Transport policy already matches this configuration",3000);log("Transport policy unchanged · idempotent save");return;}QSaveFile output(configPath_->text());if(!output.open(QIODevice::WriteOnly)||output.write(updated)<0||!output.commit()){log("Transport policy could not be written safely");return;}invalidate("Transport policy saved. Validate before connecting.");loadConfig(configPath_->text());log(QString("Transport policy saved · %1 · shaping %2 · inner %3").arg(adaptiveMode_->currentData().toString(),shapingEnabled_->isChecked()?"enabled":"disabled",innerTunnelEnabled_->isChecked()?innerTunnelBackend_->currentData().toString():"off"));
    }
    void invalidate(const QString& reason){configValid_=false;validatedConfigHash_.clear();validatedExecutableHash_.clear();connectButton_->setEnabled(true);configHealth_->setText(reason);refreshConnectionPresentation();}
    void chooseConfig(){if(process_.state()!=QProcess::NotRunning){log("Disconnect before choosing another configuration.");return;}const QString path=QFileDialog::getOpenFileName(this,"Choose PQVPN configuration",QFileInfo(configPath_->text()).absolutePath(),"JSON configuration (*.json)");if(!path.isEmpty())configPath_->setText(path);}
    void chooseExecutable(){if(process_.state()!=QProcess::NotRunning){log("Disconnect before choosing another executable.");return;}const QString path=QFileDialog::getOpenFileName(this,"Choose pqvpn_node",QFileInfo(executablePath_->text()).absolutePath());if(!path.isEmpty())executablePath_->setText(path);}
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
        configValid_=passed;configHealth_->setText(message);connectButton_->setEnabled(true);
        if(passed){validatedConfigHash_=fileFingerprint(configPath_->text());validatedExecutableHash_=fileFingerprint(executablePath_->text());
            if(validatedConfigHash_.isEmpty()||validatedExecutableHash_.isEmpty()){invalidate("Validated files are no longer readable. Validate again.");passed=false;}}
        else{validatedConfigHash_.clear();validatedExecutableHash_.clear();}
        validateButton_->setEnabled(true);refreshConnectionPresentation();log(passed?"Configuration and platform preflight passed":"Connection preflight failed");
        const bool continueConnection=pendingConnectAfterValidation_&&passed;pendingConnectAfterValidation_=false;
        if(continueConnection)QTimer::singleShot(0,this,&Window::toggleConnection);
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
            pendingConnectAfterValidation_=false;
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
    void toggleConnection(){if(process_.state()==QProcess::NotRunning){if(!configValid_){pendingConnectAfterValidation_=true;configHealth_->setText("One-click preflight in progress…");switchPage(Connection);if(validateButton_->isEnabled())validateConfig(false);return;}if(fileFingerprint(configPath_->text())!=validatedConfigHash_||fileFingerprint(executablePath_->text())!=validatedExecutableHash_){invalidate("Configuration or executable changed after validation. Validate again.");log("Connection blocked · validated files changed");pendingConnectAfterValidation_=true;validateConfig(false);return;}stopping_=false;processFailed_=false;bool noTunnel=false;
        noTunnel=noTunnel_&&noTunnel_->isChecked();
        log(QString("Connect requested · config %1 · log %2%3").arg(configPath_->text(),logLevel_->currentText(),noTunnel?" · no-tunnel":""));QStringList args={"--config",configPath_->text(),"--log-level",logLevel_->currentText(),"--control-stdin"};args<<"--shield-profile"<<shieldProfile_->currentData(Qt::UserRole+1).toString();if(noTunnel)args<<"--no-tunnel";
        process_.start(executablePath_->text(),args);
        }else requestStop();}
    QString strangeMarkup(QString value) const {return value.toHtmlEscaped().replace("\n","<br>");}
    void refreshSocialCreditPresentation(){if(strangeCredits_)strangeCredits_->setText(QString("%1 Commons credit%2").arg(socialCredits_).arg(socialCredits_==1?"":"s"));if(strangeBoost_){strangeBoost_->setEnabled(socialCredits_>0&&!boostInFlight_);strangeBoost_->setText(boostArmed_?"Boost armed · 1 credit":"Boost next · 1 credit");}}
    void appendStrangeSystem(const QString& value){if(!strangeTranscript_)return;strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='5'><tr><td align='center'><span style='color:#8fa4c9;font-size:9pt'>%1</span></td></tr></table>").arg(strangeMarkup(value)));}
    void appendStrangeText(const QString& value){appendStrangeSystem(value);}
    void appendStrangeMessageBubble(const QString& sender,const QString& value,qint64 timestamp,bool outbound,bool boosted=false){if(!strangeTranscript_)return;const QString label=outbound?QStringLiteral("You"):sender.left(12);const QString time=timestamp>0?QDateTime::fromMSecsSinceEpoch(timestamp).toLocalTime().toString("HH:mm"):QDateTime::currentDateTime().toString("HH:mm");const QString side=outbound?QStringLiteral("right"):QStringLiteral("left");const QString background=boosted?QStringLiteral("#9a5b00"):(outbound?QStringLiteral("#5432c9"):QStringLiteral("#202a48"));const QString badge=boosted?QStringLiteral(" · ✦ VISUAL BOOST"):QString{};strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='3'><tr><td align='%1'><table width='72%' cellspacing='0' cellpadding='12' bgcolor='%2'><tr><td><span style='color:#bfcaf0;font-size:8pt;font-weight:600'>%3 · %4%5</span><br><span style='color:#ffffff;font-size:11pt'>%6</span></td></tr></table></td></tr></table>").arg(side,background,label.toHtmlEscaped(),time,badge,strangeMarkup(value)));}
    void appendStrangeSticker(const QString& payload,const QString& sender){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),caption=object.value("caption").toString(),color=object.value("color").toString();const QStringList palette{"#5432c9","#0f8fa8","#b83280","#b86b18","#226c4a","#3d4d73"};if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16||caption.size()>48||!palette.contains(color)){appendStrangeSystem("A malformed sticker was discarded safely.");return;}const QString side=sender=="You"?QStringLiteral("right"):QStringLiteral("left");strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='3'><tr><td align='%1'><table width='46%' cellpadding='14' bgcolor='%2'><tr><td><span style='font-size:34pt'>%3</span><br><span style='color:white;font-size:12pt;font-weight:700'>%4</span><br><span style='color:#e8e9ff;font-size:8pt'>%5</span></td></tr></table></td></tr></table>").arg(side,color,emoji.toHtmlEscaped(),caption.toHtmlEscaped(),sender.toHtmlEscaped()));}
    void appendStrangeReaction(const QString& payload,const QString& sender,qulonglong fallbackSequence){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),target=object.value("target").toString().left(12);const auto sequence=object.value("sequence").toVariant().toULongLong();if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16){appendStrangeSystem("A malformed reaction was discarded safely.");return;}appendStrangeSystem(QString("%1 reacted %2 to %3 · message %4").arg(sender,emoji,target.isEmpty()?QString("the latest message"):target).arg(sequence?sequence:fallbackSequence));}
    void recordStrangeProof(const QString& name,const QJsonObject& event){if(!strangeProofEnabled_||!strangeProofEnabled_->isChecked())return;const QStringList committed{"strangenet.message","strangenet.direct","strangenet.sticker","strangenet.reaction","strangenet.delivered","strangenet.sent"};if(!committed.contains(name))return;const bool accepted=strangeProofChain_.append(QJsonDocument(event).toJson(QJsonDocument::Compact));if(!accepted){strangeProofStatus_->setText("Proof chain limit reached; copy this anchor before starting a new chain.");return;}strangeProofCopy_->setEnabled(true);strangeProofStatus_->setText(QString("%1 event(s) committed in memory · content excluded from the anchor.").arg(strangeProofChain_.size()));}
    void notifyStrangeActivity(bool priority=false){const QString policy=strangeNotificationMode_?strangeNotificationMode_->currentData().toString():QString("all");if(policy=="mute"||(policy=="priority"&&!priority))return;if(pages_->currentIndex()==StrangeNet&&isActiveWindow())return;unreadStrange_=qMin(unreadStrange_+1,999);const QString label=QString("StrangeNet · %1 new").arg(unreadStrange_);pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);const auto now=QDateTime::currentMSecsSinceEpoch();if(strangeNotifications_->isChecked()&&tray_->isVisible()&&now-lastStrangeNotificationMs_>=3000){lastStrangeNotificationMs_=now;tray_->showMessage(priority?"Priority StrangeNet activity":"New encrypted StrangeNet activity","Open PQVPN to view it.",QSystemTrayIcon::Information,3500);}}
    bool validStrangeRoom() { const QString room=strangeRoom_->text().trimmed();const bool valid=room.size()<=64&&room.split('/').size()<=8&&QRegularExpression("^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$").match(room).hasMatch();if(!valid)appendStrangeText("Use a safe room path: 1–64 characters, at most 8 levels, for example mainnet/friends/poetry.");return valid; }
    void sendControl(const QJsonObject& command){process_.write(QJsonDocument(command).toJson(QJsonDocument::Compact)+'\n');}
    void sendStrangeJoin(){const auto selected=peerDirectory_->selectedItems();activeStrangeGroup_.clear();if(selected.size()>=2){QJsonArray peers;for(const auto* item:selected){const QString peer=item->data(Qt::UserRole).toString();peers.append(peer);activeStrangeGroup_.append(peer);}sendControl({{"command","strangenet.join"},{"room",strangeRoom_->text().trimmed()},{"peer","auto"},{"peers",peers}});return;}sendControl({{"command","strangenet.join"},{"room",strangeRoom_->text().trimmed()},{"peer","auto"}});}
    void toggleStrangeNet(){if(strangeActive_){sendControl({{"command","strangenet.leave"}});return;}if(!validStrangeRoom())return;if(process_.state()==QProcess::NotRunning){if(!configValid_){appendStrangeText("Validate the mainnet configuration before joining.");switchPage(Connection);return;}pendingStrangeJoin_=true;appendStrangeText("Starting the mainnet connection for room '"+strangeRoom_->text().trimmed()+"'…");toggleConnection();return;}sendStrangeJoin();}
    void sendStrangeMessage(){const QString value=strangeMessage_->toPlainText();const QByteArray message=value.toUtf8();if(value.trimmed().isEmpty()){statusBar()->showMessage("Write something before sending.",2200);return;}if(message.size()>2048){appendStrangeSystem("Message not sent · the 2048-byte session limit was exceeded.");return;}if(!requireStrangeAction("Send"))return;boostInFlight_=boostArmed_&&socialCredits_>0;boostArmed_=false;if(strangeBoost_){QSignalBlocker guard(strangeBoost_);strangeBoost_->setChecked(false);}refreshSocialCreditPresentation();const QString direct=selectedDirectPeer();if(!direct.isEmpty())sendControl({{"command","strangenet.dm"},{"peer",direct},{"text",value}});else sendControl({{"command","strangenet.send"},{"text",value},{"reply_to",static_cast<qint64>(pendingReplyTo_)}});strangeSend_->setEnabled(false);}
    QAudioFormat strangeVoiceFormat() const {QAudioFormat format;format.setSampleRate(16000);format.setChannelCount(1);format.setSampleFormat(QAudioFormat::Int16);return format;}
    void startStrangeVoice(){
        if(strangeAudioSource_||!requireStrangeAction("Voice"))return;
        const auto device=QMediaDevices::defaultAudioInput();const auto format=strangeVoiceFormat();
        if(device.isNull()||!device.isFormatSupported(format)){appendStrangeSystem("Microphone unavailable · StrangeNet requires 16 kHz mono PCM support.");return;}
        strangeAudioSource_=new QAudioSource(device,format,this);strangeAudioSource_->setBufferSize(1280);strangeAudioInput_=strangeAudioSource_->start();
        if(!strangeAudioInput_){appendStrangeSystem("Microphone could not start.");strangeAudioSource_->deleteLater();strangeAudioSource_=nullptr;return;}
        strangeVoice_->setText("Release to stop");strangePresence_->setText("LIVE · SPEAKING");
        connect(strangeAudioInput_,&QIODevice::readyRead,this,[this]{while(strangeAudioInput_&&strangeAudioInput_->bytesAvailable()>=640){const QByteArray pcm=strangeAudioInput_->read(640);const QJsonObject packet{{"rate",16000},{"channels",1},{"sample","s16le"},{"audio",QString::fromLatin1(pcm.toBase64())}};sendControl({{"command","strangenet.voice"},{"text",QString::fromUtf8(QJsonDocument(packet).toJson(QJsonDocument::Compact))}});}});
    }
    void stopStrangeVoice(){if(!strangeAudioSource_)return;strangeAudioSource_->stop();strangeAudioSource_->deleteLater();strangeAudioSource_=nullptr;strangeAudioInput_=nullptr;strangeVoice_->setText("Hold to talk");strangePresence_->setText(strangeActive_?"LIVE · E2E":"OFFLINE");}
    void playStrangeVoice(const QString& payload){
        QJsonParseError error;const auto packet=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const auto pcm=QByteArray::fromBase64(packet.value("audio").toString().toLatin1());
        if(error.error!=QJsonParseError::NoError||packet.value("rate").toInt()!=16000||packet.value("channels").toInt()!=1||packet.value("sample").toString()!="s16le"||pcm.isEmpty()||pcm.size()>1024){appendStrangeSystem("Malformed voice data was discarded safely.");return;}
        if(!strangeAudioSink_){const auto device=QMediaDevices::defaultAudioOutput();const auto format=strangeVoiceFormat();if(device.isNull()||!device.isFormatSupported(format)){appendStrangeSystem("Audio output does not support the StrangeNet voice format.");return;}strangeAudioSink_=new QAudioSink(device,format,this);strangeAudioSink_->setBufferSize(6400);strangeAudioOutput_=strangeAudioSink_->start();}
        if(strangeAudioOutput_)strangeAudioOutput_->write(pcm);
    }
    QString piholeExecutable() const {return QStandardPaths::findExecutable("pihole");}
    void applyShieldProfile(){
        const QString profile=shieldProfile_->currentData(Qt::UserRole+1).toString();
        QSettings settings("PQVPN","Privacy Console");settings.setValue("shieldProfile",shieldProfile_->currentIndex());settings.setValue("shieldProfileId",profile);
        if(process_.state()!=QProcess::NotRunning){shieldStatus_->setText("Policy saved · disconnect and reconnect once so the exit receives the new authenticated choice.");return;}
        shieldStatus_->setText("Policy saved · the next connection applies it idempotently on the exit node.");
    }
    void runNextShieldCommand(){if(shieldQueue_.isEmpty()){shieldApply_->setEnabled(true);QSettings("PQVPN","Privacy Console").setValue("shieldProfile",shieldProfile_->currentIndex());QSettings("PQVPN","Privacy Console").setValue("shieldRegex",shieldRegex_->toPlainText());shieldStatus_->setText("Shield profile applied. Gravity updated; refreshing aggregate counters…");refreshShieldCounters();return;}QStringList command=shieldQueue_.takeFirst();const QString program=command.takeFirst();shieldProcess_.setProperty("shieldCommand",program+" "+command.join(' '));shieldProcess_.start(program,command);}
    void shieldCommandFinished(int code,QProcess::ExitStatus status){if(shieldProcess_.property("shieldStats").toBool())return;const bool oneClick=shieldProcess_.property("shieldOneClick").toBool();shieldProcess_.setProperty("shieldOneClick",false);const QString error=QString::fromUtf8(shieldProcess_.readAllStandardError()).trimmed().left(500);if(status!=QProcess::NormalExit||code!=0){shieldQueue_.clear();shieldApply_->setEnabled(true);shieldStatus_->setText("Shield update stopped safely · "+(error.isEmpty()?shieldProcess_.property("shieldCommand").toString():error));return;}if(oneClick){shieldApply_->setEnabled(true);QSettings("PQVPN","Privacy Console").setValue("shieldProfile",shieldProfile_->currentIndex());QSettings("PQVPN","Privacy Console").setValue("shieldRegex",shieldRegex_->toPlainText());shieldStatus_->setText("Shield applied in one operation. Gravity updated; refreshing aggregate counters…");refreshShieldCounters();return;}runNextShieldCommand();}
    void refreshShieldCounters(){if(shieldProcess_.state()!=QProcess::NotRunning)return;const QString executable=piholeExecutable();if(executable.isEmpty()){shieldStatus_->setText("Pi-hole CLI was not found; counters are unavailable.");return;}shieldRefresh_->setEnabled(false);shieldProcess_.setProperty("shieldStats",true);shieldProcess_.start(executable,QStringList{"-c","-j"});connect(&shieldProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus status){if(!shieldProcess_.property("shieldStats").toBool())return;shieldProcess_.setProperty("shieldStats",false);shieldRefresh_->setEnabled(true);if(status!=QProcess::NormalExit||code!=0){shieldStatus_->setText("Pi-hole did not return aggregate statistics.");return;}QJsonParseError error;const auto stats=QJsonDocument::fromJson(shieldProcess_.readAllStandardOutput(),&error).object();if(error.error!=QJsonParseError::NoError){shieldStatus_->setText("Pi-hole statistics were not valid JSON.");return;}const auto today=stats.value("ads_blocked_today").toVariant().toULongLong();const auto total=stats.value("domains_being_blocked").toVariant().toULongLong();if(!shieldBaseline_)shieldBaseline_=today;shieldSessionCount_=today>=shieldBaseline_?today-shieldBaseline_:0;shieldSession_->setText(QString::number(shieldSessionCount_));shieldToday_->setText(QString::number(today));shieldTotal_->setText(QString::number(total));shieldStatus_->setText("Aggregate counters refreshed · query history and client identities were not read.");},Qt::SingleShotConnection);}
    void runShieldSpeedTest(){if(speedProcess_.state()!=QProcess::NotRunning)return;const QString executable=QStandardPaths::findExecutable("iperf3");if(executable.isEmpty()){speedResult_->setText("iperf3 is not installed; no network test was started.");return;}const QString target=speedTarget_->text().trimmed();if(target.size()>253||!QRegularExpression("^[A-Za-z0-9][A-Za-z0-9.:_-]*$").match(target).hasMatch()){speedResult_->setText("Enter one explicit hostname or LAN address; subnet ranges are not accepted.");return;}speedRun_->setEnabled(false);speedResult_->setText("Testing the selected target for 5 seconds…");speedProcess_.start(executable,QStringList{"-c",target,"-p",QString::number(speedPort_->value()),"-J","-t","5"});}
    void speedTestFinished(int code,QProcess::ExitStatus status){speedRun_->setEnabled(true);if(status!=QProcess::NormalExit||code!=0){speedResult_->setText("Speed test failed · "+QString::fromUtf8(speedProcess_.readAllStandardError()).trimmed().left(300));return;}QJsonParseError error;const auto root=QJsonDocument::fromJson(speedProcess_.readAllStandardOutput(),&error).object();const auto end=root.value("end").toObject();const double down=end.value("sum_received").toObject().value("bits_per_second").toDouble()/1000000.0;const double up=end.value("sum_sent").toObject().value("bits_per_second").toDouble()/1000000.0;if(error.error!=QJsonParseError::NoError||down<=0){speedResult_->setText("iperf3 returned no usable throughput result.");return;}speedResult_->setText(QString("Selected target only · receive %1 Mbit/s · send %2 Mbit/s · 5 seconds").arg(down,0,'f',1).arg(up,0,'f',1));}
    QString researchHelper() const {QStringList candidates{"/usr/lib/pqvpn/pqvpn-research-compute",QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../lib/pqvpn/pqvpn-research-compute"),QDir::current().absoluteFilePath("packaging/linux/pqvpn-research-compute")};for(const auto& candidate:candidates)if(QFileInfo(candidate).isExecutable())return candidate;return QStandardPaths::findExecutable("pqvpn-research-compute");}
    void runResearchCommand(const QString& command){if(researchProcess_.state()!=QProcess::NotRunning)return;const QString helper=researchHelper();if(helper.isEmpty()){researchStatus_->setText("Research controller is not installed with this build.");return;}researchEnable_->setEnabled(false);researchDisable_->setEnabled(false);researchStatus_->setText(command=="enable"?"Applying a fail-closed 1% BOINC budget…":command=="disable"?"Stopping donated compute and restoring project state…":"Checking local BOINC research state…");researchProcess_.setProperty("researchCommand",command);researchProcess_.setProcessChannelMode(QProcess::MergedChannels);QStringList arguments{command};if(command=="enable")arguments<<"--topic"<<researchTopic_->currentData().toString();researchProcess_.start(helper,arguments);}
    void researchCommandFinished(int code,QProcess::ExitStatus status){const QString output=QString::fromUtf8(researchProcess_.readAll()).trimmed();QJsonParseError error;const auto result=QJsonDocument::fromJson(output.toUtf8(),&error).object();const bool active=status==QProcess::NormalExit&&code==0&&result.value("active").toBool();const int balance=result.contains("pqc_claims")?result.value("pqc_claims").toInt():result.value("pq_balance").toInt();researchReward_->setText(QString("%1 validator-pending PQC").arg(balance));researchEnable_->setEnabled(!active);researchDisable_->setEnabled(active);researchTopic_->setEnabled(!active);if(error.error!=QJsonParseError::NoError){researchStatus_->setText("Research controller returned an unreadable response; no new work was enabled.");return;}if(!result.value("error").toString().isEmpty()){researchStatus_->setText("Not enabled · "+result.value("error").toString());return;}if(active){const int awarded=result.contains("pqc_claimed_now")?result.value("pqc_claimed_now").toInt():result.value("pq_awarded_now").toInt();researchStatus_->setText(QString("Active · %1% CPU · %2%3").arg(result.value("cpu_percent").toDouble(),0,'f',0).arg(result.value("topic").toString()).arg(awarded?QString(" · +%1 validator-pending PQC claim(s)").arg(awarded):QString{}));}else researchStatus_->setText("Off · BOINC project state restored; privacy-minimized receipts remain local and unminted.");}
    void sendStrangeReaction(const QString& emoji){if(!requireStrangeAction("Reaction",true))return;const QJsonObject reaction{{"emoji",emoji},{"target",lastStrangeSender_},{"sequence",static_cast<qint64>(lastStrangeSequence_)}};sendControl({{"command","strangenet.react"},{"reply_to",static_cast<qint64>(lastStrangeSequence_)},{"text",QString::fromUtf8(QJsonDocument(reaction).toJson(QJsonDocument::Compact))}});}
    void createStrangeSticker(){if(!strangeActive_||!strangeRecipientReady()||QDateTime::currentMSecsSinceEpoch()<strangeSendBlockedUntilMs_){appendStrangeText("Join a room with an authenticated recipient and wait for antiflood readiness before creating a sticker.");return;}QDialog dialog(this);dialog.setWindowTitle("Create encrypted sticker");auto* layout=new QVBoxLayout(&dialog);auto* emoji=new QComboBox;emoji->addItems({"🚀","🔐","🛡️","🎉","🔥","💜","🌌","⚡","👋","👍"});auto* caption=new QLineEdit;caption->setMaxLength(48);caption->setPlaceholderText("Short caption");auto* color=new QComboBox;const QList<QPair<QString,QString>> colors{{"Violet","#5432c9"},{"Cyan","#0f8fa8"},{"Magenta","#b83280"},{"Amber","#b86b18"},{"Green","#226c4a"},{"Slate","#3d4d73"}};for(const auto& entry:colors)color->addItem(entry.first,entry.second);auto* preview=text("","heroTitle");auto refresh=[=]{preview->setText(emoji->currentText()+"  "+caption->text());preview->setStyleSheet("padding:18px;border-radius:14px;background:"+color->currentData().toString()+";color:white");};connect(emoji,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});connect(caption,&QLineEdit::textChanged,&dialog,[=]{refresh();});connect(color,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});layout->addWidget(text("EMOJI","eyebrow"));layout->addWidget(emoji);layout->addWidget(text("CAPTION","eyebrow"));layout->addWidget(caption);layout->addWidget(text("COLOR","eyebrow"));layout->addWidget(color);layout->addWidget(preview);auto* send=new QPushButton("Send sticker E2E");layout->addWidget(send);connect(send,&QPushButton::clicked,&dialog,&QDialog::accept);refresh();if(dialog.exec()!=QDialog::Accepted)return;const QJsonObject sticker{{"emoji",emoji->currentText()},{"caption",caption->text()},{"color",color->currentData().toString()}};sendControl({{"command","strangenet.sticker"},{"text",QString::fromUtf8(QJsonDocument(sticker).toJson(QJsonDocument::Compact))}});}
    void requestStop(){if(process_.state()==QProcess::NotRunning)return;stopping_=true;refreshConnectionPresentation();statusText_->setText("Disconnecting cleanly…");log("Disconnect requested");process_.write("{\"command\":\"node.shutdown\"}\n");process_.closeWriteChannel();QTimer::singleShot(5000,this,[this]{if(process_.state()!=QProcess::NotRunning){log("Clean shutdown timed out; process termination escalated");process_.kill();}});}
    void quitApplication(){quitting_=true;if(process_.state()!=QProcess::NotRunning){pendingQuit_=true;requestStop();}else{savePreferences();qApp->quit();}}
    void restoreFromTray(){showNormal();raise();activateWindow();}
    void fadeWidget(QWidget* widget,int duration=240){if(!widget||!reduceMotion_||reduceMotion_->isChecked())return;if(widget->graphicsEffect())widget->setGraphicsEffect(nullptr);auto* effect=new QGraphicsOpacityEffect(widget);widget->setGraphicsEffect(effect);auto* animation=new QPropertyAnimation(effect,"opacity",effect);animation->setDuration(duration);animation->setStartValue(0.18);animation->setEndValue(1.0);animation->setEasingCurve(QEasingCurve::OutCubic);connect(animation,&QPropertyAnimation::finished,widget,[widget,effect]{if(widget->graphicsEffect()!=effect)return;effect->setEnabled(false);QTimer::singleShot(0,widget,[widget,effect]{if(widget->graphicsEffect()==effect)widget->setGraphicsEffect(nullptr);});});animation->start(QAbstractAnimation::DeleteWhenStopped);}
    void switchPage(int index){if(!pages_||index<0||index>=pages_->count())return;pageButtons_.value(index)->setChecked(true);if(index==StrangeNet&&unreadStrange_){unreadStrange_=0;const QString label="StrangeNet";pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);}const bool changed=pages_->currentIndex()!=index;if(changed)pages_->setCurrentIndex(index);if(pageScroll_)pageScroll_->verticalScrollBar()->setValue(0);if(changed)fadeWidget(pages_->currentWidget(),260);}
    void setMotion(bool enabled){if(!auroraAnimation_){auroraAnimation_=new QPropertyAnimation(aurora_,"phase",this);auroraAnimation_->setStartValue(0.0);auroraAnimation_->setEndValue(6.283185307);auroraAnimation_->setDuration(15000);auroraAnimation_->setLoopCount(-1);pulseAnimation_=new QPropertyAnimation(orb_,"pulse",this);pulseAnimation_->setStartValue(0.0);pulseAnimation_->setEndValue(1.0);pulseAnimation_->setDuration(1700);pulseAnimation_->setEasingCurve(QEasingCurve::InOutSine);pulseAnimation_->setLoopCount(-1);}if(enabled){auroraAnimation_->start();pulseAnimation_->start();}else{auroraAnimation_->stop();pulseAnimation_->stop();aurora_->setPhase(0);orb_->setPulse(0);}}
    void setSidebarCompact(bool compact){QSettings("PQVPN","Privacy Console").setValue("compactSidebar",compact);applySidebarWidth(compact||width()<1080);}
    void applyTheme(QString mode){
        if(applyingTheme_)return;
        applyingTheme_=true;
        if(mode!="dark"&&mode!="light"&&mode!="souls")mode="system";
        bool dark=systemDark_;
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
        if(mode=="system")dark=QGuiApplication::styleHints()->colorScheme()==Qt::ColorScheme::Dark;
#endif
        if(mode=="dark"||mode=="souls")dark=true;else if(mode=="light")dark=false;
        const bool changed=themeMode_!=mode||activeDarkTheme_!=dark;
        themeMode_=mode;activeDarkTheme_=dark;
        const bool souls=mode=="souls";
        qApp->setStyleSheet(souls?QString::fromUtf8(darkTheme)+QString::fromUtf8(soulsThemeOverrides):QString::fromUtf8(dark?darkTheme:lightTheme));if(aurora_){aurora_->setDark(dark);aurora_->setSouls(souls);}if(orb_)orb_->setSouls(souls);
        const QColor pageColor(souls?"#090806":dark?"#080b17":"#f4f6fb");
        QList<QWidget*> opaquePages{pageScroll_,pageScroll_?pageScroll_->viewport():nullptr,pages_};
        if(pages_)for(int index=0;index<pages_->count();++index)opaquePages.append(pages_->widget(index));
        for(QWidget* widget:opaquePages){if(!widget)continue;QPalette palette=widget->palette();palette.setColor(QPalette::Window,pageColor);widget->setPalette(palette);widget->setAutoFillBackground(true);widget->setAttribute(Qt::WA_TranslucentBackground,false);widget->update();}
        for(auto* action:{systemTheme_,darkThemeAction_,lightThemeAction_,soulsThemeAction_})if(action){QSignalBlocker guard(action);action->setChecked(action->data().toString()==mode);}
        QSettings("PQVPN","Privacy Console").setValue("theme",mode);
        applyingTheme_=false;
        refreshConnectionPresentation();
        if(changed&&isVisible())fadeWidget(centralWidget(),220);
    }
    void applyPreferences(){QSettings settings("PQVPN","Privacy Console");systemDark_=qApp->palette().color(QPalette::Window).lightness()<128;restoreGeometry(settings.value("geometry").toByteArray());const QString stored=settings.value("config").toString();if(!stored.isEmpty()&&QFileInfo(stored).isFile())configPath_->setText(stored);else if(!stored.isEmpty())settings.remove("config");settings.remove("minimizeToTray");reduceMotion_->setChecked(settings.value("reduceMotion",false).toBool());compactSidebar_->setChecked(settings.value("compactSidebar",false).toBool());const bool geekEnabled=settings.value("geekTelemetry",false).toBool();geekTelemetry_->setChecked(geekEnabled);setGeekMode(geekEnabled);strangeNotifications_->setChecked(settings.value("strangeNotifications",true).toBool());if(strangeNotificationMode_){const int mode=strangeNotificationMode_->findData(settings.value("strangeNotificationMode","all").toString());strangeNotificationMode_->setCurrentIndex(mode<0?0:mode);}if(shieldProfile_)shieldProfile_->setCurrentIndex(qBound(0,settings.value("shieldProfile",0).toInt(),shieldProfile_->count()-1));if(shieldRegex_)shieldRegex_->setPlainText(settings.value("shieldRegex").toString());applyTheme(settings.value("theme","system").toString());}
    void savePreferences(){QSettings settings("PQVPN","Privacy Console");settings.setValue("geometry",saveGeometry());settings.setValue("config",configPath_->text());settings.remove("minimizeToTray");settings.setValue("strangeNotifications",strangeNotifications_->isChecked());settings.setValue("theme",themeMode_);}
    void log(const QString& message){const QString stamp=QDateTime::currentDateTime().toString("HH:mm:ss");for(const QString& line:message.split('\n',Qt::SkipEmptyParts))activity_->appendPlainText(stamp+"  "+line.left(16384));}
    void copyDiagnostics(){const auto phase=pqvpn::console::connection_phase({process_.state()!=QProcess::NotRunning,mainnetReady_,tunnelReady_,noTunnel_&&noTunnel_->isChecked(),stopping_,processFailed_});const QString state=QString::fromUtf8(pqvpn::console::phase_label(phase).data());const QString value=QString("PQVPN Privacy Console\nQt %1\nOS %2\nNode %3\nConfig %4\nState %5\nTransport %6\nShaping %7").arg(qVersion(),QSysInfo::prettyProductName(),executablePath_->text(),configPath_->text(),state,transportMetric_->text(),shapingMetric_->text());QApplication::clipboard()->setText(value);statusBar()->showMessage("Diagnostics copied — activity log excluded",3000);log("Diagnostics copied");}
    void showCommandPalette(){QDialog dialog(this);dialog.setWindowTitle("Command palette");dialog.resize(540,410);auto* layout=new QVBoxLayout(&dialog);auto* search=new QLineEdit;search->setPlaceholderText("Type a command…");auto* list=new QListWidget;const QList<QPair<QString,QString>> commands={{"Go to overview","overview"},{"Review connection","connection"},{"Inspect transports","transports"},{"Open StrangeNet","strangenet"},{"Open wallet","wallet"},{"Open DNS Shield","shield"},{"Open activity","activity"},{"Privacy principles","privacy"},{"Validate configuration","validate"},{"Copy diagnostics","diagnostics"},{"About PQVPN","about"}};for(const auto& command:commands){auto* item=new QListWidgetItem(command.first,list);item->setData(Qt::UserRole,command.second);}layout->addWidget(search);layout->addWidget(list);connect(search,&QLineEdit::textChanged,&dialog,[list](const QString& query){for(int row=0;row<list->count();++row)list->item(row)->setHidden(!list->item(row)->text().contains(query,Qt::CaseInsensitive));});connect(list,&QListWidget::itemActivated,&dialog,[this,&dialog](QListWidgetItem* item){const QString command=item->data(Qt::UserRole).toString();const QHash<QString,int> pages={{"overview",Overview},{"connection",Connection},{"transports",Transports},{"strangenet",StrangeNet},{"wallet",Wallet},{"shield",Shield},{"activity",Activity},{"privacy",Privacy},{"about",About}};if(pages.contains(command))switchPage(pages.value(command));else if(command=="validate")validateConfig();else if(command=="diagnostics")copyDiagnostics();dialog.accept();});list->setCurrentRow(0);search->setFocus();dialog.exec();}
};

int main(int argc,char** argv){bool softwareRendering=false;for(int index=1;index<argc;++index){const QString argument=QString::fromLocal8Bit(argv[index]);if(argument=="--software-rendering"||argument=="--smoke-test")softwareRendering=true;}const QString platform=qEnvironmentVariable("QT_QPA_PLATFORM");const bool headless=platform=="offscreen"||platform=="minimal";if(!headless&&!softwareRendering&&!qEnvironmentVariableIsSet("PQVPN_DISABLE_OPENGL"))QCoreApplication::setAttribute(Qt::AA_UseDesktopOpenGL);QApplication app(argc,argv);QFont uiFont=QFontDatabase::systemFont(QFontDatabase::GeneralFont);
#ifdef Q_OS_WIN
    for(const QString& name:QStringList{QStringLiteral("Segoe UI"),QStringLiteral("Arial"),QStringLiteral("Tahoma")}){
        const QFont candidate(name);
        if(QFontDatabase::families().contains(name,Qt::CaseInsensitive)&&QFontMetrics(candidate).inFont(QChar('A'))){uiFont=candidate;break;}
    }
#endif
    app.setFont(uiFont);app.setApplicationName("PQVPN Privacy Console");app.setApplicationDisplayName("PQVPN");app.setOrganizationName("PQVPN");
#if defined(Q_OS_LINUX)
    QGuiApplication::setDesktopFileName("pqvpn-monitor");
#endif
    app.setQuitOnLastWindowClosed(false);app.setWindowIcon(QIcon(":/brand/logo.svg"));Window window;if(qEnvironmentVariableIsSet("PQVPN_SMOKE_COMPACT"))window.resize(window.minimumSize());window.show();if(app.arguments().contains("--smoke-test")){if(!window.verifyTrayIcons()||!window.verifyClosePolicy()||!window.verifyPrimaryActions()||!window.verifyControlSurfaceSanity()||!pqvpn::console::StrangeNetProofChain::selfTest()||!pqvpn::console::ReleaseUpdater::selfTest())return 1;if(app.arguments().contains("--verify-installation")&&!window.verifyInstallation())return 1;window.prepareSmokePage(qEnvironmentVariable("PQVPN_SMOKE_PAGE"));window.prepareSmokeTheme(qEnvironmentVariable("PQVPN_SMOKE_THEME"));app.processEvents();if(!window.verifyScrollNavigation())return 1;window.prepareSmokePage(qEnvironmentVariable("PQVPN_SMOKE_PAGE"));app.processEvents();const QPixmap frame=window.grab();if(frame.isNull())return 1;const QString output=qEnvironmentVariable("PQVPN_SMOKE_IMAGE");if(!output.isEmpty()&&!frame.save(output))return 1;if(!window.verifyVisualLayout())return 1;return 0;}return app.exec();}

#include "pqvpn_monitor.moc"
