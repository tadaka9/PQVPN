#include "engine_manager.hpp"
#include <QAbstractAnimation>
#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QAudioSource>
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
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
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

namespace {
enum Page { Overview, Connection, Transports, StrangeNet, Shield, Activity, Privacy, About };

const char* darkTheme = R"CSS(
QMainWindow, QDialog { background: #080b17; color: #f8f9ff; }
QLabel { color: #dbe1f2; }
QMenuBar { background: #080b17; color: #aeb7d4; border-bottom: 1px solid rgba(255,255,255,.09); padding: 4px; }
QMenuBar::item { padding: 7px 12px; border-radius: 7px; }
QMenuBar::item:selected { background: #724cff; color: white; }
QMenu { background: #11162a; color: white; border: 1px solid #293252; padding: 7px; }
QMenu::item { padding: 8px 28px 8px 12px; border-radius: 6px; }
QMenu::item:selected { background: #724cff; }
#sidebar { background: rgba(7,10,24,.96); border-right: 1px solid rgba(255,255,255,.08); }
#wordmark { font-size: 21px; font-weight: 850; letter-spacing: 3px; color: white; }
#brandSub { color: #65e6ff; font-size: 10px; font-weight: 750; letter-spacing: 2px; }
#pageTitle { font-size: 30px; font-weight: 820; color: white; }
#pageSubtitle { color: #a5aec8; font-size: 14px; }
#heroTitle { font-size: 34px; font-weight: 850; color: white; }
#sectionTitle { font-size: 17px; font-weight: 760; color: white; }
#metric { font-size: 21px; font-weight: 820; color: white; }
#eyebrow { color: #7cecff; font-size: 10px; font-weight: 800; letter-spacing: 2px; }
QPushButton[nav="true"] { background: transparent; color: #8994b7; border: 0; border-radius: 10px; padding: 13px 14px; text-align: left; font-weight: 680; }
QPushButton[nav="true"]:hover { background: rgba(101,230,255,.10); color: white; }
QPushButton[nav="true"]:checked { background: rgba(114,76,255,.28); color: white; border: 1px solid rgba(146,117,255,.50); }
QFrame[card="true"] { background: rgba(15,21,43,.92); border: 1px solid rgba(142,162,221,.18); border-radius: 16px; }
QFrame[accent="true"] { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5432c9,stop:.52 #824cff,stop:1 #0fa9cb); border: 1px solid rgba(255,255,255,.22); border-radius: 20px; }
QLabel[muted="true"] { color: #9ba6c7; }
QFrame[accent="true"] QLabel { color: white; }
QFrame[accent="true"] QLabel[muted="true"] { color: rgba(255,255,255,.78); }
QLabel[chip="true"] { background: rgba(101,230,255,.10); color: #a5f3ff; border: 1px solid rgba(101,230,255,.28); border-radius: 11px; padding: 4px 10px; font-size: 11px; font-weight: 700; }
QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser, QListWidget { background: rgba(6,10,25,.82); color: #f4f6ff; border: 1px solid #303a60; border-radius: 10px; padding: 10px; selection-background-color: #724cff; }
#strangeTranscript { background: rgba(4,7,18,.94); border: 1px solid rgba(101,230,255,.24); border-radius: 16px; padding: 14px; }
#strangeComposer { background: rgba(10,15,34,.96); border: 1px solid #46527d; border-radius: 14px; padding: 13px; font-size: 14px; }
#strangeComposer:focus { border-color: #65e6ff; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextBrowser:focus { border-color: #65e6ff; }
QComboBox::drop-down { border: 0; width: 28px; }
QComboBox QAbstractItemView { background: #11162a; color: white; border: 1px solid #354064; selection-background-color: #724cff; }
QPushButton { background: #724cff; color: white; border: 1px solid #8e72ff; border-radius: 10px; padding: 11px 17px; font-weight: 760; }
QPushButton:hover { background: #825eff; }
QPushButton:pressed { background: #5e3bd8; }
QPushButton:disabled { background: #252a41; color: #68718f; border-color: #30364e; }
QPushButton[quiet="true"] { background: rgba(255,255,255,.04); color: #b9c2df; border-color: #343d61; }
QPushButton[quiet="true"]:checked { background: rgba(114,76,255,.28); color: white; border-color: #8e72ff; }
QPushButton[danger="true"] { background: #d94172; border-color: #ff6494; }
QPushButton[milestone="active"] { background: rgba(114,76,255,.28); color: white; border-color: #8e72ff; }
QPushButton[milestone="done"] { background: rgba(42,190,135,.16); color: #9ff3d0; border-color: rgba(77,224,166,.48); }
QCheckBox { color: #ced5ea; spacing: 9px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #586488; border-radius: 5px; background: #0b1022; }
QCheckBox::indicator:checked { background: #65e6ff; border-color: #65e6ff; }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #465174; border-radius: 4px; min-height: 28px; }
QStatusBar { background: #080b17; color: #8f9aba; border-top: 1px solid rgba(255,255,255,.08); }
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
QCheckBox::indicator:checked { background: #d4aa55; border-color: #f0ca75; }
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
QPushButton:disabled { background: #e2e6ef; color: #8a93a8; border-color: #d3d9e5; }
QPushButton[quiet="true"] { background: #ffffff; color: #4c5875; border-color: #cbd3e5; }
QPushButton[quiet="true"]:checked { background: rgba(104,66,232,.12); color: #4f2fc5; border-color: rgba(104,66,232,.45); }
QPushButton[danger="true"] { background: #c83363; border-color: #d95079; }
QPushButton[milestone="active"] { background: rgba(104,66,232,.12); color: #4f2fc5; border-color: rgba(104,66,232,.45); }
QPushButton[milestone="done"] { background: rgba(25,145,102,.10); color: #146b50; border-color: rgba(25,145,102,.35); }
QCheckBox { color: #35405c; spacing: 9px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #8792ae; border-radius: 5px; background: white; }
QCheckBox::indicator:checked { background: #0f8fa8; border-color: #0f8fa8; }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #aab3c8; border-radius: 4px; min-height: 28px; }
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
        const QHash<QString,int> pages{{"connection",Connection},{"transports",Transports},{"strangenet",StrangeNet},{"shield",Shield},{"activity",Activity},{"privacy",Privacy},{"about",About}};
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
private:
    QProcess process_;
    pqvpn::console::EngineManager* engines_=nullptr;
    pqvpn::console::ReleaseUpdater* updater_=nullptr;
    QStackedWidget* pages_=nullptr; QScrollArea* pageScroll_=nullptr; QWidget* sidebar_=nullptr; QWidget* brandWords_=nullptr;
    Aurora* aurora_=nullptr; StatusOrb* orb_=nullptr; QPropertyAnimation *auroraAnimation_=nullptr,*pulseAnimation_=nullptr;
    QHash<int,QPushButton*> pageButtons_; QList<QPushButton*> navButtons_;
    QLineEdit *configPath_=nullptr,*executablePath_=nullptr; QComboBox *logLevel_=nullptr,*adaptiveMode_=nullptr; QCheckBox* noTunnel_=nullptr;
    QPushButton* overviewAction_=nullptr;
    QLabel *configurationStep_=nullptr,*peerStep_=nullptr,*protectionStep_=nullptr;
    QPushButton *connectButton_=nullptr,*validateButton_=nullptr; QLabel *stateLabel_=nullptr,*statusText_=nullptr,*endpointMetric_=nullptr,*verificationMetric_=nullptr,*shapingMetric_=nullptr,*mainnetMetric_=nullptr,*tunnelMetric_=nullptr,*egressMetric_=nullptr,*transportMetric_=nullptr,*transportDetails_=nullptr,*configHealth_=nullptr;
    QCheckBox *adaptiveEnabled_=nullptr,*shapingEnabled_=nullptr; QLabel *adaptiveMetric_=nullptr,*transportStatus_=nullptr; QPushButton* saveTransportButton_=nullptr;
    QSpinBox *shapingPadding_=nullptr,*shapingDelay_=nullptr;
    QHash<QString,QPushButton*> engineStartButtons_,engineStopButtons_,engineConfigButtons_;
    QLineEdit* strangeRoom_=nullptr;
    ChatComposer* strangeMessage_=nullptr;
    QComboBox *strangeAudience_=nullptr,*strangeWritingMode_=nullptr; QListWidget* peerDirectory_=nullptr;
    QTextBrowser* strangeTranscript_=nullptr; QPushButton *strangeJoin_=nullptr,*strangeSend_=nullptr,*strangeReply_=nullptr,*strangeVoice_=nullptr,*strangeReaction_=nullptr,*strangeProofCopy_=nullptr; QLabel *strangeBytes_=nullptr,*peerCount_=nullptr,*strangeProofStatus_=nullptr,*strangeFloodStatus_=nullptr,*strangePresence_=nullptr,*strangeComposerHint_=nullptr;QCheckBox* strangeProofEnabled_=nullptr;
    QAudioSource* strangeAudioSource_=nullptr;QIODevice* strangeAudioInput_=nullptr;QAudioSink* strangeAudioSink_=nullptr;QIODevice* strangeAudioOutput_=nullptr;
    QPlainTextEdit* activity_=nullptr; QAction *reduceMotion_=nullptr,*compactSidebar_=nullptr,*strangeNotifications_=nullptr,*geekTelemetry_=nullptr;
    QComboBox* shieldProfile_=nullptr;QPlainTextEdit* shieldRegex_=nullptr;QLabel *shieldProfileDetail_=nullptr,*shieldStatus_=nullptr,*shieldSession_=nullptr,*shieldToday_=nullptr,*shieldTotal_=nullptr,*speedResult_=nullptr;QLineEdit* speedTarget_=nullptr;QSpinBox* speedPort_=nullptr;QPushButton *shieldApply_=nullptr,*shieldRefresh_=nullptr,*speedRun_=nullptr;QProcess shieldProcess_,speedProcess_;QList<QStringList> shieldQueue_;qulonglong shieldSessionCount_=0,shieldBaseline_=0;
    QActionGroup* themeGroup_=nullptr; QAction *systemTheme_=nullptr,*darkThemeAction_=nullptr,*lightThemeAction_=nullptr,*soulsThemeAction_=nullptr;
    QSystemTrayIcon* tray_=nullptr; QMenu* trayMenu_=nullptr; QAction *trayStatus_=nullptr,*trayToggle_=nullptr;
    QPushButton *journeyConfigure_=nullptr,*journeyAuthenticate_=nullptr,*journeyProtect_=nullptr,*geekToggle_=nullptr; QLabel* geekReadout_=nullptr;QList<QWidget*> geekWidgets_;
    QByteArray processBuffer_;
    QByteArray validatedConfigHash_,validatedExecutableHash_;
    pqvpn::console::StrangeNetProofChain strangeProofChain_;
    QString themeMode_="system";
    QString lastStrangeSender_,activeStrangePeer_="auto";QStringList activeStrangeGroup_;QHash<QString,QString> authenticatedPeers_;QSet<qulonglong> ownStrangeSequences_;qulonglong lastStrangeSequence_=0,pendingReplyTo_=0;int unreadStrange_=0;qint64 lastStrangeNotificationMs_=0,strangeSendBlockedUntilMs_=0;
    bool processFailed_=false;
    bool configValid_=false,stopping_=false,quitting_=false,pendingQuit_=false,trayNoticeShown_=false,strangeActive_=false,mainnetReady_=false,tunnelReady_=false,pendingStrangeJoin_=false,systemDark_=false,activeDarkTheme_=true,applyingTheme_=false,protectedRewardShown_=false;

    void setGeekMode(bool enabled){
        if(geekReadout_)geekReadout_->setVisible(enabled);
        if(geekToggle_&&geekToggle_->isChecked()!=enabled){QSignalBlocker guard(geekToggle_);geekToggle_->setChecked(enabled);}
        for(auto* widget:geekWidgets_)if(widget)widget->setVisible(enabled);
        if(pageScroll_)pageScroll_->widget()->updateGeometry();
    }

    void refreshConnectionPresentation() {
        const QString previousTitle=stateLabel_->text();
        const bool active=process_.state()!=QProcess::NotRunning;
        const bool relay=noTunnel_&&noTunnel_->isChecked();
        QString title="Disconnected", detail="Disconnected. No node process is running from this console.";
        bool protectedPath=false;
        if(active&&!mainnetReady_){title="Connecting";detail="Negotiating an authenticated mainnet session…";}
        else if(active&&mainnetReady_&&relay){title="Mainnet connected · relay mode";detail="Authenticated peer ready. Local system traffic is not routed through PQVPN.";}
        else if(active&&mainnetReady_&&!tunnelReady_){title="Peer ready · securing routes";detail="The peer is authenticated; waiting for the operating-system tunnel and fail-closed routes.";}
        else if(active&&mainnetReady_&&tunnelReady_){title="Protected";detail="Authenticated peer, tunnel adapter and leak-safe routes are ready.";protectedPath=true;}
        stateLabel_->setText(title);statusText_->setText(detail);orb_->setConnected(protectedPath&&!stopping_);
        if(previousTitle!=title){fadeWidget(stateLabel_,220);fadeWidget(statusText_,280);}
        const auto phase=pqvpn::console::connection_phase({active,mainnetReady_,tunnelReady_,relay,stopping_,processFailed_});
        if(phase==pqvpn::console::ConnectionPhase::Stopping){title="Disconnecting";statusText_->setText("Stopping the node and restoring its owned network state…");}
        if(phase==pqvpn::console::ConnectionPhase::Failed){title="Connection failed";statusText_->setText("Open Activity for the node error, then review and validate the configuration.");}
        if(themeMode_=="souls"){
            using Phase=pqvpn::console::ConnectionPhase;
            if(phase==Phase::Disconnected){title="UNLIT";statusText_->setText("No tunnel is active. Begin again when you are ready.");}
            else if(phase==Phase::Connecting){title="ENTERING THE FOG";statusText_->setText("Seeking an authenticated path through the mainnet…");}
            else if(phase==Phase::Securing){title="KINDLING THE ROUTE";statusText_->setText("The peer answered. Fail-closed routes are not yet ready.");}
            else if(phase==Phase::Relay){title="WAY OF WHITE · RELAY";statusText_->setText("The peer is authenticated; this computer's traffic remains outside the tunnel.");}
            else if(phase==Phase::Protected){title="EMBER RESTORED";statusText_->setText("Peer, tunnel and leak-safe routes stand together.");}
            else if(phase==Phase::Stopping){title="RETURNING TO BONFIRE";statusText_->setText("Restoring the network state owned by PQVPN…");}
            else if(phase==Phase::Failed){title="YOU DIED · FAIL CLOSED";statusText_->setText("The protected path fell. Traffic remains sealed; inspect Activity before trying again.");}
        }
        const auto setMilestone=[](QPushButton* button,const QString& value,const QString& label){
            if(!button)return;
            if(button->property("milestone").toString()!=value){button->setProperty("milestone",value);button->style()->unpolish(button);button->style()->polish(button);}
            button->setText(label);
        };
        setMilestone(journeyConfigure_,configValid_?"done":"active",configValid_?"✓  Configured":"1  Configure");
        setMilestone(journeyAuthenticate_,mainnetReady_&&active?"done":configValid_&&active?"active":"pending",mainnetReady_&&active?"✓  Authenticated":"2  Authenticate");
        setMilestone(journeyProtect_,protectedPath?"done":mainnetReady_&&active?"active":"pending",protectedPath?"✓  Protected":"3  Protect");
        if(geekReadout_){geekReadout_->setText(QString("%1 · %2 · %3").arg(endpointMetric_?endpointMetric_->text():"UDP",verificationMetric_?verificationMetric_->text():"hybrid auth",transportMetric_?transportMetric_->text():"direct path"));geekReadout_->setVisible(geekTelemetry_&&geekTelemetry_->isChecked());}
        if(protectedPath&&!protectedRewardShown_){protectedRewardShown_=true;statusBar()->showMessage("Protected path complete · peer, tunnel and fail-closed routes verified",7000);fadeWidget(journeyProtect_,360);}
        if(!active)protectedRewardShown_=false;
        stateLabel_->setText(title);
        tray_->setIcon(connectionTrayIcon(phase));
        trayStatus_->setText(title);tray_->setToolTip("PQVPN · "+title);
        if(overviewAction_){overviewAction_->setText(active?"Disconnect":configValid_?"Connect securely":"Configure connection");overviewAction_->setProperty("danger",active);overviewAction_->style()->unpolish(overviewAction_);overviewAction_->style()->polish(overviewAction_);}
        if(configurationStep_)configurationStep_->setText(configValid_?"1  Configuration verified":"1  Choose and verify configuration");
        if(peerStep_)peerStep_->setText(mainnetReady_&&active?"2  Peer authenticated":"2  Peer session pending");
        if(protectionStep_)protectionStep_->setText(protectedPath?"3  System traffic protected":relay?"3  Relay mode · local traffic unchanged":"3  Tunnel and routes pending");
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
        auto* view=menuBar()->addMenu("View");auto* themeMenu=view->addMenu("Appearance");themeGroup_=new QActionGroup(this);themeGroup_->setExclusive(true);systemTheme_=themeMenu->addAction("Follow system");darkThemeAction_=themeMenu->addAction("Dark");lightThemeAction_=themeMenu->addAction("Light");soulsThemeAction_=themeMenu->addAction("Dark Souls mode · fail closed");for(auto* action:{systemTheme_,darkThemeAction_,lightThemeAction_,soulsThemeAction_}){action->setCheckable(true);themeGroup_->addAction(action);}systemTheme_->setData("system");darkThemeAction_->setData("dark");lightThemeAction_->setData("light");soulsThemeAction_->setData("souls");systemTheme_->setChecked(true);view->addSeparator();reduceMotion_=view->addAction("Reduce motion"); reduceMotion_->setCheckable(true); compactSidebar_=view->addAction("Compact sidebar"); compactSidebar_->setCheckable(true);geekTelemetry_=view->addAction("Geek telemetry");geekTelemetry_->setCheckable(true);strangeNotifications_=view->addAction("Private StrangeNet notifications");strangeNotifications_->setCheckable(true);strangeNotifications_->setChecked(true);
        connect(themeGroup_,&QActionGroup::triggered,this,[this](QAction* action){applyTheme(action->data().toString());});
        connect(reduceMotion_,&QAction::toggled,this,[this](bool checked){QSettings("PQVPN","Privacy Console").setValue("reduceMotion",checked);setMotion(!checked);});
        connect(compactSidebar_,&QAction::toggled,this,&Window::setSidebarCompact);
        connect(geekTelemetry_,&QAction::toggled,this,[this](bool checked){QSettings("PQVPN","Privacy Console").setValue("geekTelemetry",checked);setGeekMode(checked);});
        connect(strangeNotifications_,&QAction::toggled,this,[](bool checked){QSettings("PQVPN","Privacy Console").setValue("strangeNotifications",checked);});
        auto* tools=menuBar()->addMenu("Tools"); tools->addAction("Command palette…",QKeySequence("Ctrl+K"),this,&Window::showCommandPalette); tools->addAction("Copy diagnostics",QKeySequence("Ctrl+Shift+C"),this,&Window::copyDiagnostics);
    }
    void buildUi() {
        auto* root=new QWidget; auto* stack=new QStackedLayout(root); stack->setStackingMode(QStackedLayout::StackAll); aurora_=new Aurora;
        auto* shell=new QWidget; auto* row=new QHBoxLayout(shell); row->setContentsMargins(0,0,0,0); row->setSpacing(0); buildSidebar(row);
        pages_=new ResponsiveStack;pages_->setAutoFillBackground(true);pages_->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);pages_->addWidget(buildOverview());pages_->addWidget(buildConnection());pages_->addWidget(buildTransports());pages_->addWidget(buildStrangeNet());pages_->addWidget(buildShield());pages_->addWidget(buildActivity());pages_->addWidget(buildPrivacy());pages_->addWidget(buildAbout());for(int index=0;index<pages_->count();++index){pages_->widget(index)->setMinimumWidth(0);pages_->widget(index)->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);pages_->widget(index)->setAutoFillBackground(true);}pageScroll_=new StableScrollArea;pageScroll_->setObjectName("pageScroll");pageScroll_->setFrameShape(QFrame::NoFrame);pageScroll_->setWidgetResizable(true);pageScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);pageScroll_->setAutoFillBackground(true);pageScroll_->viewport()->setAutoFillBackground(true);pageScroll_->setWidget(pages_);
        auto* content=new QWidget;auto* contentLayout=new QVBoxLayout(content);contentLayout->setContentsMargins(16,12,16,0);contentLayout->setSpacing(10);auto* journey=new QFrame;journey->setProperty("card",true);auto* journeyLayout=new QHBoxLayout(journey);journeyLayout->setContentsMargins(14,10,14,10);journeyLayout->setSpacing(9);auto* route=text("YOUR ROUTE","eyebrow");journeyLayout->addWidget(route);journeyConfigure_=new QPushButton("1  Configure");journeyAuthenticate_=new QPushButton("2  Authenticate");journeyProtect_=new QPushButton("3  Protect");for(auto* step:{journeyConfigure_,journeyAuthenticate_,journeyProtect_}){step->setProperty("quiet",true);journeyLayout->addWidget(step);}geekReadout_=text("UDP · hybrid auth · fail-closed state","eyebrow");geekReadout_->setProperty("muted",true);journeyLayout->addStretch();journeyLayout->addWidget(geekReadout_);geekToggle_=new QPushButton("Geek");geekToggle_->setCheckable(true);geekToggle_->setProperty("quiet",true);geekToggle_->setToolTip("Reveal engine, benchmark and protocol controls without changing the active connection.");journeyLayout->addWidget(geekToggle_);connect(journeyConfigure_,&QPushButton::clicked,this,[this]{switchPage(Connection);});connect(journeyAuthenticate_,&QPushButton::clicked,this,[this]{switchPage(process_.state()==QProcess::NotRunning?Connection:Activity);});connect(journeyProtect_,&QPushButton::clicked,this,[this]{switchPage(process_.state()==QProcess::NotRunning?Connection:Overview);});connect(geekToggle_,&QPushButton::toggled,geekTelemetry_,&QAction::setChecked);contentLayout->addWidget(journey);contentLayout->addWidget(pageScroll_,1);row->addWidget(content,1);
        stack->addWidget(aurora_); stack->addWidget(shell); stack->setCurrentWidget(shell); setCentralWidget(root); switchPage(Overview); setMotion(true);
    }
    void buildSidebar(QHBoxLayout* shell) {
        sidebar_=new QWidget; sidebar_->setObjectName("sidebar"); sidebar_->setMinimumWidth(238); sidebar_->setMaximumWidth(238);
        auto* layout=new QVBoxLayout(sidebar_); layout->setContentsMargins(18,24,18,20); layout->setSpacing(8);
        auto* brand=new QHBoxLayout; auto* icon=new QLabel; icon->setPixmap(QIcon(":/brand/logo.svg").pixmap(46,46)); brandWords_=new QWidget; auto* words=new QVBoxLayout(brandWords_); words->setContentsMargins(0,0,0,0); words->setSpacing(0); words->addWidget(text("PQVPN","wordmark")); words->addWidget(text("PRIVACY CONSOLE","brandSub")); brand->addWidget(icon); brand->addWidget(brandWords_,1); layout->addLayout(brand); layout->addSpacing(24);
        auto* group=new QButtonGroup(this); group->setExclusive(true); const QList<QPair<QString,int>> items{{"Overview",Overview},{"Connect",Connection},{"Transports",Transports},{"StrangeNet",StrangeNet},{"Shield",Shield},{"Activity",Activity},{"Privacy",Privacy},{"About",About}};
        for (const auto& [name,page]:items) { auto* button=new QPushButton(QString("%1   %2").arg(page+1,2,10,QChar('0')).arg(name)); button->setProperty("fullText",button->text()); button->setProperty("nav",true); button->setCheckable(true); group->addButton(button,page); pageButtons_[page]=button; navButtons_.append(button); layout->addWidget(button); connect(button,&QPushButton::clicked,this,[this,page]{switchPage(page);}); }
        layout->addStretch(); auto* ethics=text("YOU CHOOSE WHEN TO CONNECT\nNO TRACKING · NO DARK PATTERNS"); ethics->setObjectName("eyebrow"); layout->addWidget(ethics); shell->addWidget(sidebar_);
    }
    QWidget* pageShell(const QString& title,const QString& subtitle,QVBoxLayout** body) { auto* page=new QWidget; auto* outer=new QVBoxLayout(page); outer->setContentsMargins(34,28,34,28); outer->setSpacing(18); outer->addWidget(text(title,"pageTitle")); outer->addWidget(text(subtitle,"pageSubtitle")); *body=outer; return page; }
    QLabel* metric(const QString& title,const QString& value,QHBoxLayout* row) { auto* layout=new QVBoxLayout; layout->setContentsMargins(20,18,20,18); layout->addWidget(text(title,"eyebrow")); auto* result=text(value,"metric"); layout->addWidget(result); row->addWidget(card(layout),1); return result; }
    QWidget* buildOverview() {
        QVBoxLayout* body; auto* page=pageShell("Your private route, at a glance","Real state only. Nothing connects or changes routes until you ask.",&body);
        auto* hero=new QHBoxLayout; hero->setContentsMargins(28,25,28,25); auto* copy=new QVBoxLayout; copy->addWidget(text("POST-QUANTUM PRIVACY","eyebrow")); stateLabel_=text("Disconnected","heroTitle"); copy->addWidget(stateLabel_); statusText_=text("Choose a configuration, validate it, then connect when you are ready."); statusText_->setProperty("muted",true); copy->addWidget(statusText_); overviewAction_=new QPushButton("Configure connection"); connect(overviewAction_,&QPushButton::clicked,this,[this]{if(process_.state()!=QProcess::NotRunning||configValid_)toggleConnection();else switchPage(Connection);}); copy->addWidget(overviewAction_,0,Qt::AlignLeft); hero->addLayout(copy,1); orb_=new StatusOrb; hero->addWidget(orb_,0,Qt::AlignCenter); body->addWidget(card(hero,true));
        auto* metrics=new QHBoxLayout; mainnetMetric_=metric("MAINNET BOOTSTRAP","Not loaded",metrics); endpointMetric_=metric("LOCAL LISTENER","Not loaded",metrics); verificationMetric_=metric("PEER POLICY","Unknown",metrics); body->addLayout(metrics);
        auto* capabilities=new QHBoxLayout; tunnelMetric_=metric("TUNNEL BOUNDARY","Unknown",capabilities); egressMetric_=metric("EXIT MODE","Off",capabilities); shapingMetric_=metric("TRAFFIC SHAPING","Off",capabilities); body->addLayout(capabilities);
        auto* explain=new QVBoxLayout; explain->setContentsMargins(22,20,22,20); explain->setSpacing(10); explain->addWidget(text("Connection checklist","sectionTitle"));
        configurationStep_=text("1  Choose and verify configuration");peerStep_=text("2  Peer session pending");protectionStep_=text("3  Tunnel and routes pending");
        for(auto* step:{configurationStep_,peerStep_,protectionStep_})explain->addWidget(step);
        auto* note=text("Green means an authenticated connection. Relay mode leaves this computer's traffic unchanged; Protected additionally requires a ready tunnel and fail-closed routes.");note->setProperty("muted",true);explain->addWidget(note);body->addWidget(card(explain));body->addStretch(); return page;
    }
    QWidget* buildConnection() {
        QVBoxLayout* body; auto* page=pageShell("Connect","A short, reversible flow with validation before execution.",&body); auto* form=new QVBoxLayout; form->setContentsMargins(23,21,23,21); form->setSpacing(12);
        auto* journey=new QGridLayout;journey->setSpacing(10);journey->addWidget(capability("01 · CONFIGURE","Choose node + policy","Local",true),0,0);journey->addWidget(capability("02 · VERIFY","Real node validation","Required",true),0,1);journey->addWidget(capability("03 · CONNECT","Hybrid mainnet session","Observed",true),1,0);journey->addWidget(capability("04 · USE","Tunnel + StrangeNet","One session",true),1,1);journey->setColumnStretch(0,1);journey->setColumnStretch(1,1);body->addLayout(journey);
        form->addWidget(text("CONFIGURATION","eyebrow")); auto* cr=new QHBoxLayout; configPath_=new QLineEdit(QString::fromStdString(pqvpn::console::default_profile(QFileInfo(defaultExecutable()).absolutePath().toStdString()).generic_string())); auto* cb=new QPushButton("Choose…"); cb->setProperty("quiet",true); cr->addWidget(configPath_,1); cr->addWidget(cb); form->addLayout(cr);
        auto* nodeAdvanced=new QWidget;auto* nodeAdvancedLayout=new QVBoxLayout(nodeAdvanced);nodeAdvancedLayout->setContentsMargins(0,0,0,0);nodeAdvancedLayout->setSpacing(8);nodeAdvancedLayout->addWidget(text("NODE EXECUTABLE","eyebrow")); auto* er=new QHBoxLayout; executablePath_=new QLineEdit(defaultExecutable()); auto* eb=new QPushButton("Choose…"); eb->setProperty("quiet",true); er->addWidget(executablePath_,1); er->addWidget(eb);nodeAdvancedLayout->addLayout(er);form->addWidget(nodeAdvanced);geekWidgets_.append(nodeAdvanced);
        auto* options=new QHBoxLayout; options->addWidget(text("LOG DETAIL","eyebrow")); logLevel_=new QComboBox; logLevel_->addItems({"info","debug","warning","error"}); options->addWidget(logLevel_);
        noTunnel_=new QCheckBox("Relay / exit only (no local tunnel)"); noTunnel_->setToolTip("Run the authenticated node without the operating-system tunnel boundary. Mainnet and StrangeNet still work, but local system traffic is not tunneled."); noTunnel_->setChecked(false); options->addWidget(noTunnel_);
        options->addStretch();auto* connectionAdvanced=new QWidget;connectionAdvanced->setLayout(options);form->addWidget(connectionAdvanced);geekWidgets_.append(connectionAdvanced); configHealth_=text("Configuration has not been validated."); configHealth_->setProperty("muted",true); form->addWidget(configHealth_); body->addWidget(card(form));
        auto* utilities=new QHBoxLayout;auto* inspect=new QPushButton("Inspect system");inspect->setProperty("quiet",true);auto* normalized=new QPushButton("Review normalized config");normalized->setProperty("quiet",true);auto* editNode=new QPushButton("Edit configuration");editNode->setProperty("quiet",true);utilities->addWidget(editNode);connect(editNode,&QPushButton::clicked,this,[this]{if(process_.state()==QProcess::NotRunning)editConfiguration(configPath_->text(),true);});utilities->addWidget(inspect);utilities->addWidget(normalized);utilities->addStretch();form->addLayout(utilities);
        auto* actions=new QHBoxLayout; validateButton_=new QPushButton("Validate first"); validateButton_->setProperty("quiet",true); connectButton_=new QPushButton("Connect securely"); connectButton_->setEnabled(false); actions->addWidget(validateButton_); actions->addStretch(); actions->addWidget(connectButton_); body->addLayout(actions); auto* consent=text("Starting may create a tunnel adapter or change routes according to your configuration and OS permissions. Closing the window can keep PQVPN in the tray without changing the connection."); consent->setProperty("muted",true); body->addWidget(consent); body->addStretch();
        connect(cb,&QPushButton::clicked,this,&Window::chooseConfig); connect(eb,&QPushButton::clicked,this,&Window::chooseExecutable); connect(validateButton_,&QPushButton::clicked,this,&Window::validateConfig); connect(connectButton_,&QPushButton::clicked,this,&Window::toggleConnection);connect(inspect,&QPushButton::clicked,this,[this]{runNodeTool({"--platform-info"},"System inspection");});connect(normalized,&QPushButton::clicked,this,[this]{runNodeTool({"--print-config","--config",configPath_->text()},"Normalized configuration");});
        connect(configPath_,&QLineEdit::textChanged,this,[this](const QString& path){invalidate("Configuration changed. Validate before connecting.");loadConfig(path);}); connect(executablePath_,&QLineEdit::textChanged,this,[this]{invalidate("Executable changed. Validate before connecting.");}); connect(noTunnel_,&QCheckBox::toggled,this,[this]{invalidate("Connection mode changed. Validate before connecting.");loadConfig(configPath_->text());}); return page;
    }
    QFrame* capability(const QString& name,const QString& kind,const QString& status,bool available) { auto* layout=new QVBoxLayout; layout->setContentsMargins(17,14,17,14);layout->setSpacing(5);layout->addWidget(text(name,"sectionTitle")); auto* type=text(kind); type->setProperty("muted",true); layout->addWidget(type); auto* chip=text(available?status:"Not integrated · "+status); chip->setProperty("chip",true); layout->addWidget(chip,0,Qt::AlignLeft);auto* result=card(layout);result->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Maximum);return result; }
    QWidget* buildTransports() {
        QVBoxLayout* body; auto* page=pageShell("Transports","Capabilities read from configuration — no implied support.",&body); auto* current=new QVBoxLayout; current->setContentsMargins(23,21,23,21); current->addWidget(text("SELECTED OUTER PATH","eyebrow")); transportMetric_=text("Direct PQVPN UDP","heroTitle"); current->addWidget(transportMetric_); transportDetails_=text("Load a configuration to inspect its transport constraints."); transportDetails_->setProperty("muted",true); current->addWidget(transportDetails_); body->addWidget(card(current,true));
        auto* adaptive=new QVBoxLayout; adaptive->setContentsMargins(20,18,20,18); adaptive->addWidget(text("PQTP ADAPTIVE PATH","eyebrow")); adaptiveMetric_=text("Disabled","sectionTitle"); adaptive->addWidget(adaptiveMetric_); adaptiveEnabled_=new QCheckBox("Enable automatic UDP/TCP failover");adaptive->addWidget(adaptiveEnabled_);auto* adaptiveRow=new QHBoxLayout; adaptiveMode_=new QComboBox; adaptiveMode_->addItem("Automatic · prefer UDP", "auto"); adaptiveMode_->addItem("UDP only", "udp"); adaptiveMode_->addItem("TCP only", "tcp"); saveTransportButton_=new QPushButton("Save transport policy"); saveTransportButton_->setProperty("quiet",true); adaptiveRow->addWidget(adaptiveMode_); adaptiveRow->addStretch(); adaptiveRow->addWidget(saveTransportButton_); adaptive->addLayout(adaptiveRow); auto* adaptiveCopy=text("Automatic mode preserves the authenticated PQVPN frame, uses UDP for low latency, falls back to TCP after measured loss, jitter or blocking, and probes UDP before returning."); adaptiveCopy->setProperty("muted",true); adaptive->addWidget(adaptiveCopy); body->addWidget(card(adaptive)); connect(saveTransportButton_,&QPushButton::clicked,this,&Window::saveTransportSettings);
        auto* shaping=new QVBoxLayout;shaping->setContentsMargins(20,18,20,18);shaping->addWidget(text("PRIVACY TRAFFIC SHAPING","eyebrow"));shapingEnabled_=new QCheckBox("Enable bounded encrypted padding and timing shaping");shaping->addWidget(shapingEnabled_);auto* shapingRow=new QHBoxLayout;shapingRow->addWidget(text("Maximum padding (bytes)"));shapingPadding_=new QSpinBox;shapingPadding_->setRange(0,4096);shapingPadding_->setValue(1024);shapingRow->addWidget(shapingPadding_);shapingRow->addSpacing(18);shapingRow->addWidget(text("Maximum delay (ms)"));shapingDelay_=new QSpinBox;shapingDelay_->setRange(0,100);shapingDelay_->setValue(20);shapingRow->addWidget(shapingDelay_);shapingRow->addStretch();shaping->addLayout(shapingRow);auto* shapingCopy=text("Shaping stays inside authenticated encryption, uses bounded local predictors, and never downloads a model or sends telemetry. Both peers must support shaped frames.");shapingCopy->setProperty("muted",true);shaping->addWidget(shapingCopy);body->addWidget(card(shaping));
        engines_=new pqvpn::console::EngineManager(this);transportStatus_=text("Transport engines are idle. Choose a configuration before starting one.");transportStatus_->setProperty("muted",true);body->addWidget(transportStatus_);engines_->report=[this](const QString& message){transportStatus_->setText(message);statusBar()->showMessage(message,6000);log(message);};engines_->activityChanged=[this](const QString& id,bool active){if(engineStartButtons_.contains(id))engineStartButtons_[id]->setEnabled(!active);if(engineStopButtons_.contains(id))engineStopButtons_[id]->setEnabled(active);if(engineConfigButtons_.contains(id))engineConfigButtons_[id]->setEnabled(!active);};
        auto* controls=new QVBoxLayout;controls->setContentsMargins(20,18,20,18);
        controls->addWidget(text("ENGINES ON DEMAND","eyebrow"));
        QList<QPair<QString,QCheckBox*>> selected;
        for(const QString& id:QStringList{"udp2raw","shadowsocks","v2ray","obfs4"}){
            auto* engineBlock=new QVBoxLayout;auto* row=new QHBoxLayout;auto* enabled=new QCheckBox(id);row->addWidget(enabled);selected.append({id,enabled});
            auto* choose=new QPushButton("Choose config…");auto* edit=new QPushButton("Edit config");auto* start=new QPushButton("Install / start");auto* stop=new QPushButton("Stop");
            engineStartButtons_[id]=start;engineStopButtons_[id]=stop;engineConfigButtons_[id]=choose;stop->setEnabled(false);
            for(auto* button:{choose,edit,stop})button->setProperty("quiet",true);
            row->addStretch();row->addWidget(start);row->addWidget(stop);engineBlock->addLayout(row);auto* configRow=new QHBoxLayout;configRow->addWidget(choose);configRow->addWidget(edit);configRow->addStretch();engineBlock->addLayout(configRow);controls->addLayout(engineBlock);
            connect(choose,&QPushButton::clicked,this,[this,id]{if(engines_->active(id))return;const QString path=QFileDialog::getOpenFileName(this,"Choose "+id+" configuration",QDir::homePath());if(!path.isEmpty())QSettings("PQVPN","Privacy Console").setValue(id+"ConfigPath",QFileInfo(path).absoluteFilePath());});
            connect(edit,&QPushButton::clicked,this,[this,id]{if(!engines_->active(id))editConfiguration(QSettings("PQVPN","Privacy Console").value(id+"ConfigPath").toString(),id!="udp2raw");});
            connect(start,&QPushButton::clicked,this,[this,id]{engines_->start(id,engineConfiguration(id));});
            connect(stop,&QPushButton::clicked,this,[this,id]{engines_->stop(id);});
        }
        auto* startSelected=new QPushButton("Start selected engines");controls->addWidget(startSelected,0,Qt::AlignRight);
        connect(startSelected,&QPushButton::clicked,this,[this,selected]{for(const auto& item:selected)if(item.second->isChecked()&&!engines_->active(item.first))engines_->start(item.first,engineConfiguration(item.first));});
        auto* note=text("Downloads are verified and stored separately from PQVPN. Multiple engines can run together using your matching configurations. PQVPN can attach directly to udp2raw; SOCKS and TCP engines require a configured UDP relay. Engine startup alone does not mean the VPN is connected.");note->setProperty("muted",true);controls->addWidget(note);auto* engineControls=card(controls);body->addWidget(engineControls);geekWidgets_.append(engineControls);
        auto* presets=new QHBoxLayout;auto* udpPreset=new QPushButton("Auto-configure udp2raw");auto* engineInfo=text("Preserves your identity and installs / starts udp2raw from your existing server configuration.");engineInfo->setProperty("muted",true);presets->addWidget(udpPreset);auto* chooseEngine=new QPushButton("Choose engine config…");chooseEngine->setProperty("quiet",true);presets->addWidget(chooseEngine);presets->addWidget(engineInfo,1);
        connect(chooseEngine,&QPushButton::clicked,this,[this]{if(process_.state()!=QProcess::NotRunning)return;const QString path=QFileDialog::getOpenFileName(this,"Choose existing udp2raw client configuration",QDir::homePath(),"Engine configuration (*.conf *.cfg);;All files (*)");if(!path.isEmpty()){QSettings("PQVPN","Privacy Console").setValue("udp2rawConfigPath",path);prepareUdp2rawProfile();}});auto* enginePresets=new QWidget;enginePresets->setLayout(presets);body->addWidget(enginePresets);geekWidgets_.append(enginePresets);
        connect(udpPreset,&QPushButton::clicked,this,&Window::prepareUdp2rawProfile);
        body->addStretch(); return page;
    }
    QWidget* buildStrangeNet() {
        QVBoxLayout* body; auto* page=pageShell("StrangeNet","A living room for ordinary words and uncommon ones.",&body);
        auto* intro=new QVBoxLayout; intro->setContentsMargins(24,21,24,21); intro->addWidget(text("STRANGENET · SESSION-ONLY P2P CHAT","eyebrow")); intro->addWidget(text("Speak plainly. Write beautifully. Keep the room yours.","heroTitle")); auto* note=text("Every message is encrypted separately for authenticated recipients. No public history, no required account, no promise of perfect anonymity. PQVPN remains experimental and has not received an independent security audit."); note->setProperty("muted",true); intro->addWidget(note); body->addWidget(card(intro,true));

        auto* session=new QVBoxLayout; session->setContentsMargins(20,18,20,18);auto* sessionHeader=new QHBoxLayout;sessionHeader->addWidget(text("ROOM PATH & AUDIENCE","eyebrow"));strangePresence_=text("OFFLINE");strangePresence_->setProperty("chip",true);sessionHeader->addStretch();sessionHeader->addWidget(strangePresence_);session->addLayout(sessionHeader);auto* fields=new QHBoxLayout; strangeRoom_=new QLineEdit("mainnet/friends"); strangeRoom_->setAccessibleName("StrangeNet room path");strangeRoom_->setPlaceholderText("Community/channel · mainnet/friends"); strangeRoom_->setMaxLength(64); strangeAudience_=new QComboBox;strangeAudience_->setAccessibleName("StrangeNet audience");strangeAudience_->addItem("Room · authenticated Peer IDs only","auto"); fields->addWidget(strangeRoom_,1);fields->addWidget(strangeAudience_,2); session->addLayout(fields); auto* actions=new QHBoxLayout; strangeJoin_=new QPushButton("Enter room");strangeJoin_->setAccessibleName("Enter or leave StrangeNet room"); actions->addWidget(strangeJoin_);actions->addStretch();auto* privacy=text("Peer IDs are visible. Participant IP addresses are never shown.");privacy->setProperty("muted",true);actions->addWidget(privacy);session->addLayout(actions); body->addWidget(card(session));

        auto* conversationHeader=new QHBoxLayout;conversationHeader->addWidget(text("THE CONVERSATION","eyebrow"));conversationHeader->addStretch();auto* copyChat=new QPushButton("Copy visible text");copyChat->setProperty("quiet",true);auto* clearChat=new QPushButton("Clear view");clearChat->setProperty("quiet",true);conversationHeader->addWidget(copyChat);conversationHeader->addWidget(clearChat);body->addLayout(conversationHeader);
        strangeTranscript_=new QTextBrowser;strangeTranscript_->setObjectName("strangeTranscript");strangeTranscript_->setAccessibleName("StrangeNet conversation");strangeTranscript_->setOpenExternalLinks(false);strangeTranscript_->setOpenLinks(false);strangeTranscript_->document()->setMaximumBlockCount(1000);strangeTranscript_->setMinimumHeight(330);strangeTranscript_->setPlaceholderText("The room is quiet. Your words will appear here after you join.");body->addWidget(strangeTranscript_);

        auto* writingBar=new QHBoxLayout;writingBar->addWidget(text("WRITING MODE","eyebrow"));strangeWritingMode_=new QComboBox;strangeWritingMode_->addItem("Conversation · Enter sends",false);strangeWritingMode_->addItem("Poem · Enter makes a new line",true);strangeWritingMode_->setAccessibleName("StrangeNet writing mode");writingBar->addWidget(strangeWritingMode_);writingBar->addStretch();body->addLayout(writingBar);
        strangeMessage_=new ChatComposer;strangeMessage_->setObjectName("strangeComposer");strangeMessage_->setAccessibleName("StrangeNet message composer");strangeMessage_->setPlaceholderText("Write a message…  Enter to send · Shift+Enter for a new line");strangeMessage_->setFixedHeight(104);body->addWidget(strangeMessage_);
        auto* composer=new QHBoxLayout;auto* emoji=new QPushButton("Emoji");emoji->setProperty("quiet",true);auto* emojiMenu=new QMenu(emoji);for(const QString& value:QStringList{"😀","😂","😍","🤔","😮","😢","👍","👏","🎉","🔥","❤️","🚀","🔐","🛡️","🌙","✨"}){auto* action=emojiMenu->addAction(value);connect(action,&QAction::triggered,this,[this,value]{strangeMessage_->insertPlainText(value);strangeMessage_->setFocus();});}emoji->setMenu(emojiMenu);strangeReply_=new QPushButton("Reply to latest");strangeReply_->setProperty("quiet",true);strangeReply_->setEnabled(false);strangeVoice_=new QPushButton("Hold to talk");strangeVoice_->setProperty("quiet",true);strangeVoice_->setEnabled(false);strangeReaction_=new QPushButton("React to latest");strangeReaction_->setProperty("quiet",true);strangeReaction_->setEnabled(false);auto* reactionMenu=new QMenu(strangeReaction_);for(const QString& value:QStringList{"👍","❤️","😂","😮","🎉","🔥"}){auto* action=reactionMenu->addAction(value);connect(action,&QAction::triggered,this,[this,value]{sendStrangeReaction(value);});}strangeReaction_->setMenu(reactionMenu);strangeSend_=new QPushButton("Send securely");strangeSend_->setEnabled(false);composer->addWidget(emoji);composer->addWidget(strangeReply_);composer->addWidget(strangeVoice_);composer->addWidget(strangeReaction_);composer->addStretch();composer->addWidget(strangeSend_);body->addLayout(composer);
        auto* composerStatus=new QHBoxLayout;strangeComposerHint_=text("Enter sends · Shift+Enter writes a new line");strangeComposerHint_->setProperty("muted",true);composerStatus->addWidget(strangeComposerHint_,1);strangeFloodStatus_=text("Antiflood ready","eyebrow");strangeFloodStatus_->setProperty("muted",true);composerStatus->addWidget(strangeFloodStatus_);strangeBytes_=text("0 / 2048 bytes");strangeBytes_->setProperty("muted",true);composerStatus->addWidget(strangeBytes_,0,Qt::AlignRight);body->addLayout(composerStatus);

        auto* peers=new QVBoxLayout;peers->setContentsMargins(20,18,20,18);auto* peerHeader=new QHBoxLayout;peerHeader->addWidget(text("AUTHENTICATED PEER IDS","eyebrow"));peerCount_=text("0 authenticated","sectionTitle");peerHeader->addStretch();peerHeader->addWidget(peerCount_);peers->addLayout(peerHeader);auto* peerNote=text("The room includes authenticated peers. Select at least two IDs only when you want to pin a group of three or more including you; StrangeNet has no one-to-one DM mode and never reveals participant IP addresses.");peerNote->setProperty("muted",true);peers->addWidget(peerNote);peerDirectory_=new QListWidget;peerDirectory_->setAccessibleName("Authenticated StrangeNet peer IDs");peerDirectory_->setSelectionMode(QAbstractItemView::ExtendedSelection);peerDirectory_->setMaximumHeight(150);peers->addWidget(peerDirectory_);body->addWidget(card(peers));

        auto* proof=new QVBoxLayout;proof->setContentsMargins(20,18,20,18);auto* proofHeader=new QHBoxLayout;proofHeader->addWidget(text("OPTIONAL SESSION ANCHOR","eyebrow"));strangeProofEnabled_=new QCheckBox("Build a private proof chain in memory");proofHeader->addStretch();proofHeader->addWidget(strangeProofEnabled_);proof->addLayout(proofHeader);strangeProofStatus_=text("Off · no StrangeNet content is recorded.");strangeProofStatus_->setProperty("muted",true);proof->addWidget(strangeProofStatus_);auto* proofActions=new QHBoxLayout;strangeProofCopy_=new QPushButton("Copy chain anchor");strangeProofCopy_->setProperty("quiet",true);strangeProofCopy_->setEnabled(false);proofActions->addStretch();proofActions->addWidget(strangeProofCopy_);proof->addLayout(proofActions);auto* proofNote=text("Opt in to build a salted SHA-256 continuity chain in memory. PQVPN does not publish a transaction or persist messages, identities, rooms, or the private salt.");proofNote->setProperty("muted",true);proof->addWidget(proofNote);body->addWidget(card(proof));
        connect(strangeProofEnabled_,&QCheckBox::toggled,this,[this](bool enabled){strangeProofChain_.reset();strangeProofCopy_->setEnabled(false);strangeProofStatus_->setText(enabled?"Ready · the in-memory chain starts with the next StrangeNet event.":"Off · no StrangeNet content is recorded.");});connect(strangeProofCopy_,&QPushButton::clicked,this,[this]{const auto anchor=strangeProofChain_.anchor();if(anchor.isEmpty())return;QApplication::clipboard()->setText(QString::fromUtf8(QJsonDocument(anchor).toJson(QJsonDocument::Compact)));statusBar()->showMessage("StrangeNet chain anchor copied",3000);});
        connect(copyChat,&QPushButton::clicked,this,[this]{QApplication::clipboard()->setText(strangeTranscript_->toPlainText());statusBar()->showMessage("Visible StrangeNet text copied",2500);});connect(clearChat,&QPushButton::clicked,this,[this]{strangeTranscript_->clear();appendStrangeSystem("View cleared locally · the room and network session were not changed.");});
        connect(strangeWritingMode_,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){const bool poem=strangeWritingMode_->currentData().toBool();strangeMessage_->setPoemMode(poem);strangeMessage_->setPlaceholderText(poem?"Write without flattening the lines…  Ctrl+Enter to send":"Write a message…  Enter to send · Shift+Enter for a new line");strangeComposerHint_->setText(poem?"Poem mode · Enter writes a new line · Ctrl+Enter sends":"Enter sends · Shift+Enter writes a new line");strangeMessage_->setFocus();});
        connect(strangeJoin_,&QPushButton::clicked,this,&Window::toggleStrangeNet);connect(strangeSend_,&QPushButton::clicked,this,&Window::sendStrangeMessage);connect(strangeVoice_,&QPushButton::pressed,this,&Window::startStrangeVoice);connect(strangeVoice_,&QPushButton::released,this,&Window::stopStrangeVoice);connect(strangeReply_,&QPushButton::clicked,this,[this]{if(pendingReplyTo_){pendingReplyTo_=0;strangeReply_->setText("Reply to latest");strangeComposerHint_->setText("Enter sends · Shift+Enter writes a new line");}else if(lastStrangeSequence_){pendingReplyTo_=lastStrangeSequence_;strangeComposerHint_->setText(QString("Replying to Peer %1… · message %2 · click again to cancel").arg(lastStrangeSender_.left(12)).arg(lastStrangeSequence_));strangeReply_->setText("Cancel reply");}strangeMessage_->setFocus();});strangeMessage_->submit=[this]{sendStrangeMessage();};connect(strangeMessage_,&QPlainTextEdit::textChanged,this,[this]{QString value=strangeMessage_->toPlainText();while(value.toUtf8().size()>2048){if(value.size()>=2&&value.back().isLowSurrogate()&&value.at(value.size()-2).isHighSurrogate())value.chop(2);else value.chop(1);}if(!value.isEmpty()&&value.back().isHighSurrogate())value.chop(1);if(value!=strangeMessage_->toPlainText()){QSignalBlocker guard(strangeMessage_);strangeMessage_->setPlainText(value);strangeMessage_->moveCursor(QTextCursor::End);}const auto bytes=value.toUtf8().size();strangeBytes_->setText(QString("%1 / 2048 bytes").arg(bytes));refreshStrangeSendEnabled();});
        appendStrangeSystem("Welcome to StrangeNet · join a room when an authenticated peer is available. Nothing here is written to chat history on disk.");
        return page;
    }
    QWidget* buildShield() {
        QVBoxLayout* body;auto* page=pageShell("Shield","Pi-hole profiles, aggregate blocking evidence and bounded LAN speed tests.",&body);
        auto* hero=new QVBoxLayout;hero->setContentsMargins(24,21,24,21);hero->addWidget(text("DNS SHIELD · PRIVACY-PRESERVING","eyebrow"));hero->addWidget(text("Block harm. Keep people out of the log.","heroTitle"));auto* disclosure=text("DNS filtering reduces exposure; it cannot inspect encrypted page content or guarantee child safety. PQVPN reads aggregate counters only and never imports Pi-hole query history or client IP addresses.");disclosure->setProperty("muted",true);hero->addWidget(disclosure);body->addWidget(card(hero,true));
        auto* counters=new QHBoxLayout;shieldSession_=metric("🛡 SESSION","0",counters);shieldToday_=metric("🛡 BLOCKED TODAY","Unavailable",counters);shieldTotal_=metric("FILTERED DOMAINS","Unavailable",counters);body->addLayout(counters);
        auto* profile=new QVBoxLayout;profile->setContentsMargins(20,18,20,18);profile->addWidget(text("ONE-CLICK PI-HOLE SHIELD","eyebrow"));shieldProfile_=new QComboBox;const auto addShield=[this](const QString& name,const QString& id,const QString& detail,const QStringList& sources){const int row=shieldProfile_->count();shieldProfile_->addItem(name,sources);shieldProfile_->setItemData(row,id,Qt::UserRole+1);shieldProfile_->setItemData(row,detail,Qt::UserRole+2);};addShield("Balanced privacy · recommended","privacy","OISD Big · broad privacy coverage · low-to-moderate site-breakage risk",QStringList{"https://big.oisd.nl/"});addShield("Threat defence","security","OISD Big + HaGeZi TIF · malware, phishing and command-and-control · low-to-moderate risk",QStringList{"https://big.oisd.nl/","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt"});addShield("Family boundaries","family","Threat defence + adult and gambling categories · intentional content restrictions · review with household members",QStringList{"https://big.oisd.nl/","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nsfw.txt","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/gambling.txt"});addShield("Maximum · expert","maximum","HaGeZi Pro + TIF + family categories · strongest preset · higher false-positive and breakage risk",QStringList{"https://big.oisd.nl/","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nsfw.txt","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/gambling.txt"});profile->addWidget(shieldProfile_);shieldProfileDetail_=text(shieldProfile_->itemData(0,Qt::UserRole+2).toString());shieldProfileDetail_->setProperty("muted",true);profile->addWidget(shieldProfileDetail_);profile->addWidget(text("CUSTOM DENY REGEX · optional · one Pi-hole ERE per line","eyebrow"));shieldRegex_=new QPlainTextEdit;shieldRegex_->setMaximumHeight(110);shieldRegex_->setPlaceholderText("(^|\\.)example\\.invalid$");profile->addWidget(shieldRegex_);auto* actions=new QHBoxLayout;shieldApply_=new QPushButton("Apply shield in one click");shieldRefresh_=new QPushButton("Refresh shield counters");shieldRefresh_->setProperty("quiet",true);actions->addWidget(shieldApply_);actions->addWidget(shieldRefresh_);actions->addStretch();profile->addLayout(actions);shieldStatus_=text("Ready. The Linux package uses one narrowly scoped administrator action; Pi-hole must already be installed.");shieldStatus_->setProperty("muted",true);profile->addWidget(shieldStatus_);body->addWidget(card(profile));
        auto* speed=new QVBoxLayout;speed->setContentsMargins(20,18,20,18);speed->addWidget(text("BOUNDED LAN / VPN SPEED TEST","eyebrow"));auto* speedFields=new QHBoxLayout;speedTarget_=new QLineEdit;speedTarget_->setPlaceholderText("Explicit iperf3 server hostname or LAN address");speedPort_=new QSpinBox;speedPort_->setRange(1,65535);speedPort_->setValue(5201);speedRun_=new QPushButton("Run 5-second test");speedFields->addWidget(speedTarget_,1);speedFields->addWidget(speedPort_);speedFields->addWidget(speedRun_);speed->addLayout(speedFields);speedResult_=text("No test run. PQVPN never scans your subnet; it contacts only the target you enter.");speedResult_->setProperty("muted",true);speed->addWidget(speedResult_);auto* speedCard=card(speed);body->addWidget(speedCard);geekWidgets_.append(speedCard);body->addStretch();
        connect(shieldProfile_,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int row){shieldProfileDetail_->setText(shieldProfile_->itemData(row,Qt::UserRole+2).toString());});connect(shieldApply_,&QPushButton::clicked,this,&Window::applyShieldProfile);connect(shieldRefresh_,&QPushButton::clicked,this,&Window::refreshShieldCounters);connect(speedRun_,&QPushButton::clicked,this,&Window::runShieldSpeedTest);
        connect(&shieldProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,&Window::shieldCommandFinished);connect(&speedProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,&Window::speedTestFinished);
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
        QVBoxLayout* body; auto* page=pageShell("About PQVPN","A native C++23 console for the post-quantum node.",&body); auto* info=new QVBoxLayout; info->setContentsMargins(27,25,27,25); auto* logo=new QLabel; logo->setPixmap(QIcon(":/brand/logo.svg").pixmap(96,96)); info->addWidget(logo,0,Qt::AlignLeft); info->addWidget(text("PQVPN","heroTitle")); info->addWidget(text("Privacy Console · Qt 6 · C++23 · " PQVPN_BUILD_VERSION,"sectionTitle")); auto* detail=text("The node owns cryptography, sessions, routing, shaping and transport policy. Qt owns presentation and launches the same pqvpn_node executable used by the CLI."); detail->setProperty("muted",true); info->addWidget(detail); auto* diagnostic=new QPushButton("Copy diagnostics"); diagnostic->setProperty("quiet",true); connect(diagnostic,&QPushButton::clicked,this,&Window::copyDiagnostics); info->addWidget(diagnostic,0,Qt::AlignLeft); body->addWidget(card(info,true));
        auto* updates=new QVBoxLayout;updates->setContentsMargins(20,18,20,18);updates->addWidget(text("RELEASE UPDATES","eyebrow"));auto* updateStatus=text("Updates are checked only when you ask.");updateStatus->setProperty("muted",true);updates->addWidget(updateStatus);auto* updateActions=new QHBoxLayout;auto* checkUpdate=new QPushButton("Check releases");auto* downloadUpdate=new QPushButton("Download verified update");downloadUpdate->setEnabled(false);downloadUpdate->setProperty("quiet",true);updateActions->addWidget(checkUpdate);updateActions->addWidget(downloadUpdate);updateActions->addStretch();updates->addLayout(updateActions);auto* updateNote=text("PQVPN requires a platform package and SHA256SUMS from the same GitHub Release. The console verifies the download, opens its folder, and leaves installation under your control.");updateNote->setProperty("muted",true);updates->addWidget(updateNote);body->addWidget(card(updates));
        updater_=new pqvpn::console::ReleaseUpdater(PQVPN_BUILD_VERSION,this);updater_->report=[this,updateStatus,checkUpdate](const QString& value){updateStatus->setText(value);log(value);checkUpdate->setEnabled(true);};updater_->downloadable=[downloadUpdate](bool enabled){downloadUpdate->setEnabled(enabled);};connect(checkUpdate,&QPushButton::clicked,this,[this,checkUpdate]{checkUpdate->setEnabled(false);updater_->check();});connect(downloadUpdate,&QPushButton::clicked,this,[this]{updater_->download();});body->addStretch(); return page;
    }
    void buildTray() {
        tray_=new QSystemTrayIcon(connectionTrayIcon(pqvpn::console::ConnectionPhase::Disconnected),this); trayMenu_=new QMenu; trayStatus_=trayMenu_->addAction("Disconnected"); trayStatus_->setEnabled(false); trayMenu_->addSeparator(); auto* show=trayMenu_->addAction("Show Privacy Console"); connect(show,&QAction::triggered,this,&Window::restoreFromTray); trayToggle_=trayMenu_->addAction("Connect securely"); connect(trayToggle_,&QAction::triggered,this,[this]{restoreFromTray(); if(process_.state()==QProcess::NotRunning&&!configValid_)switchPage(Connection); else toggleConnection();}); trayMenu_->addSeparator(); auto* exit=trayMenu_->addAction("Exit PQVPN"); connect(exit,&QAction::triggered,this,&Window::quitApplication); tray_->setContextMenu(trayMenu_); connect(tray_,&QSystemTrayIcon::activated,this,[this](QSystemTrayIcon::ActivationReason reason){if(reason==QSystemTrayIcon::Trigger||reason==QSystemTrayIcon::DoubleClick)restoreFromTray();}); tray_->show();
    }
    QString defaultExecutable() const { const QString name=
#ifdef _WIN32
        "pqvpn_node.exe";
#else
        "pqvpn_node";
#endif
        const QDir directory(QCoreApplication::applicationDirPath());
        for(const QString& candidate:{directory.absoluteFilePath(name),directory.absoluteFilePath("../../../bin/"+name),directory.absoluteFilePath("../../../"+name)})if(QFileInfo::exists(candidate))return QDir::cleanPath(candidate);
        return QDir::current().absoluteFilePath("build/"+name); }

    void applyStartupArguments(){
        const QStringList arguments=QApplication::arguments();
        for(int index=1;index<arguments.size();++index){
            if((arguments[index]=="--config"||arguments[index]=="--node")&&index+1<arguments.size()){
                const QString value=QFileInfo(arguments[++index]).absoluteFilePath();
                if(arguments[index-1]=="--config")configPath_->setText(value);else executablePath_->setText(value);
            }
        }
    }

    bool strangeRecipientReady() const {if(!mainnetReady_)return false;if(!activeStrangeGroup_.isEmpty()){for(const auto& peer:activeStrangeGroup_)if(!authenticatedPeers_.contains(peer))return false;return true;}return activeStrangePeer_=="auto"||authenticatedPeers_.contains(activeStrangePeer_);}
    void refreshStrangeSendEnabled(){if(!strangeSend_||!strangeMessage_)return;const auto bytes=strangeMessage_->toPlainText().trimmed().toUtf8().size();const bool outboundReady=strangeActive_&&strangeRecipientReady()&&process_.state()==QProcess::Running&&QDateTime::currentMSecsSinceEpoch()>=strangeSendBlockedUntilMs_;strangeSend_->setEnabled(outboundReady&&bytes>0&&bytes<=2048);if(strangeReply_)strangeReply_->setEnabled(outboundReady&&lastStrangeSequence_!=0);if(strangeVoice_)strangeVoice_->setEnabled(outboundReady);if(strangeReaction_)strangeReaction_->setEnabled(outboundReady&&lastStrangeSequence_!=0);}
    void applyStrangeRateLimit(qint64 retryAfterMs){if(retryAfterMs<1)retryAfterMs=1;else if(retryAfterMs>60000)retryAfterMs=60000;const qint64 deadline=QDateTime::currentMSecsSinceEpoch()+retryAfterMs;strangeSendBlockedUntilMs_=qMax(strangeSendBlockedUntilMs_,deadline);strangeFloodStatus_->setText(QString("Antiflood engaged · retry available in %1 ms").arg(retryAfterMs));refreshStrangeSendEnabled();QTimer::singleShot(retryAfterMs,this,[this,deadline]{if(strangeSendBlockedUntilMs_!=deadline)return;strangeSendBlockedUntilMs_=0;strangeFloodStatus_->setText("Antiflood ready");refreshStrangeSendEnabled();});}
    void resetStrangeRateLimit(){strangeSendBlockedUntilMs_=0;if(strangeFloodStatus_)strangeFloodStatus_->setText("Antiflood ready");refreshStrangeSendEnabled();}
    void refreshPeerDirectory(){
        if(!strangeAudience_||!peerDirectory_)return;QSignalBlocker guard(strangeAudience_);strangeAudience_->clear();strangeAudience_->addItem(QString("Room fanout · %1 authenticated Peer ID(s)").arg(authenticatedPeers_.size()),"auto");peerDirectory_->clear();QStringList identities=authenticatedPeers_.keys();identities.sort(Qt::CaseInsensitive);for(const QString& identity:identities){const QString label=QString("Peer %1… · authenticated + policy accepted").arg(identity.left(20));auto* item=new QListWidgetItem(label,peerDirectory_);item->setData(Qt::UserRole,identity);item->setToolTip("Peer ID: "+identity);}strangeAudience_->setCurrentIndex(0);peerCount_->setText(QString("%1 authenticated").arg(authenticatedPeers_.size()));fadeWidget(peerDirectory_,180);
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
                recordStrangeProof(name,event);
                if(name=="peer.connected"){
                    const QString peer=event.value("peer").toString().toLower();if(QRegularExpression("^[0-9a-f]{64}$").match(peer).hasMatch())authenticatedPeers_.insert(peer,"authenticated");refreshPeerDirectory();mainnetReady_=!authenticatedPeers_.isEmpty();refreshConnectionPresentation();refreshStrangeSendEnabled();
                }else if(name=="peer.disconnected"){
                    const QString peer=event.value("peer").toString().toLower();authenticatedPeers_.remove(peer);refreshPeerDirectory();mainnetReady_=!authenticatedPeers_.isEmpty();refreshConnectionPresentation();refreshStrangeSendEnabled();if(strangeActive_&&activeStrangePeer_==peer){strangeReaction_->setEnabled(false);appendStrangeText("Selected peer disconnected. Zero-trust targeting remains pinned; leave the room to choose another peer.");}
                }else if(name=="tunnel.ready"){
                    tunnelReady_=event.value("fail_closed").toBool(false)&&event.value("ipv4").toString()=="full";
                    refreshConnectionPresentation();
                }else if(name=="strangenet.joined"){
                    strangeActive_=true;pendingStrangeJoin_=false;activeStrangePeer_=event.value("peer").toString("auto").toLower();strangeJoin_->setText("Leave room");
                    strangeRoom_->setEnabled(false);strangeAudience_->setEnabled(false);peerDirectory_->setEnabled(false);resetStrangeRateLimit();
                    strangePresence_->setText("LIVE · E2E");const int groupSize=event.value("group_size").toInt();appendStrangeSystem(groupSize>=3?QString("Entered %1 · pinned group · %2 participants").arg(event.value("room").toString()).arg(groupSize):(activeStrangePeer_=="auto"?QString("Entered %1 · authenticated audience").arg(event.value("room").toString()):QString("Entered %1 · pinned to %2…").arg(event.value("room").toString(),activeStrangePeer_.left(16))));strangeMessage_->setFocus();
                }else if(name=="strangenet.left"){
                    strangeActive_=false;strangeJoin_->setText("Enter room");strangePresence_->setText("OFFLINE");resetStrangeRateLimit();strangeReaction_->setEnabled(false);
                    strangeRoom_->setEnabled(true);strangeAudience_->setEnabled(true);peerDirectory_->setEnabled(true);activeStrangePeer_="auto";activeStrangeGroup_.clear();appendStrangeText("Left room.");
                }else if(name=="strangenet.message"){
                    lastStrangeSender_=event.value("sender").toString();lastStrangeSequence_=event.value("sequence").toVariant().toULongLong();refreshStrangeSendEnabled();appendStrangeMessageBubble(lastStrangeSender_,event.value("text").toString(),event.value("timestamp_ms").toVariant().toLongLong(),false);notifyStrangeActivity();
                    const auto replyTo=event.value("reply_to").toVariant().toULongLong();if(replyTo&&ownStrangeSequences_.contains(replyTo)){tray_->showMessage("Someone replied to you",QString("Open %1 to read the reply.").arg(event.value("room").toString()),QSystemTrayIcon::Information,5000);}
                }else if(name=="strangenet.sticker"){
                    lastStrangeSender_=event.value("sender").toString();lastStrangeSequence_=event.value("sequence").toVariant().toULongLong();refreshStrangeSendEnabled();appendStrangeSticker(event.value("text").toString(),lastStrangeSender_.left(12));notifyStrangeActivity();
                }else if(name=="strangenet.reaction"){
                    appendStrangeReaction(event.value("text").toString(),event.value("sender").toString().left(12),event.value("reply_to").toVariant().toULongLong());notifyStrangeActivity();
                }else if(name=="strangenet.voice"){
                    playStrangeVoice(event.value("text").toString());appendStrangeSystem(QString("Voice from Peer %1… · live, not stored").arg(event.value("sender").toString().left(12)));notifyStrangeActivity();
                }else if(name=="strangenet.delivered"){
                    appendStrangeSystem(QString("Delivered · message %1 · peer %2").arg(event.value("sequence").toVariant().toULongLong()).arg(event.value("peer").toString().left(12)));
                }else if(name=="strangenet.sent"){
                    const QString kind=event.value("kind").toString();if(kind=="voice")appendStrangeSystem("Voice sent live · not stored");else if(kind=="sticker")appendStrangeSticker(event.value("text").toString(),"You");else if(kind=="reaction")appendStrangeReaction(event.value("text").toString(),"You",0);else{appendStrangeMessageBubble("You",event.value("text").toString(),QDateTime::currentMSecsSinceEpoch(),true);strangeMessage_->clear();ownStrangeSequences_.insert(event.value("sequence").toVariant().toULongLong());while(ownStrangeSequences_.size()>256)ownStrangeSequences_.erase(ownStrangeSequences_.begin());pendingReplyTo_=0;strangeReply_->setText("Reply to latest");strangeComposerHint_->setText("Enter sends · Shift+Enter writes a new line");}appendStrangeSystem(QString("Encrypted separately for %1 authenticated peer(s).").arg(event.value("recipients").toInt()));refreshStrangeSendEnabled();
                }else if(name=="strangenet.rate_limited"){
                    const qint64 retry=event.value("retry_after_ms").toVariant().toLongLong();appendStrangeText(QString("Antiflood · message paused; retry in %1 ms.").arg(retry));applyStrangeRateLimit(retry);strangeMessage_->setFocus();
                }else if(name=="strangenet.deferred"||name=="control.error"){
                    appendStrangeText("Notice · "+event.value("message").toString());refreshStrangeSendEnabled();strangeMessage_->setFocus();
                }
            }
        });
        connect(&process_,&QProcess::stateChanged,this,[this](QProcess::ProcessState state){const bool active=state!=QProcess::NotRunning,running=state==QProcess::Running;if(!active){stopStrangeVoice();mainnetReady_=false;tunnelReady_=false;authenticatedPeers_.clear();refreshPeerDirectory();}refreshConnectionPresentation();connectButton_->setText(active?"Disconnect":"Connect securely"); connectButton_->setProperty("danger",active); connectButton_->style()->unpolish(connectButton_);connectButton_->style()->polish(connectButton_); validateButton_->setEnabled(!active); configPath_->setEnabled(!active);executablePath_->setEnabled(!active);noTunnel_->setEnabled(!active);logLevel_->setEnabled(!active);adaptiveEnabled_->setEnabled(!active);adaptiveMode_->setEnabled(!active);shapingEnabled_->setEnabled(!active);shapingPadding_->setEnabled(!active);shapingDelay_->setEnabled(!active);saveTransportButton_->setEnabled(!active); trayToggle_->setText(active?"Disconnect":"Connect securely");if(strangeJoin_){strangeJoin_->setEnabled(running||(!active&&configValid_));refreshStrangeSendEnabled();strangeReaction_->setEnabled(strangeActive_&&strangeRecipientReady()&&lastStrangeSequence_!=0);strangeRoom_->setEnabled(!strangeActive_);strangeAudience_->setEnabled(!strangeActive_);peerDirectory_->setEnabled(!strangeActive_);}if(!active){strangeActive_=false;pendingStrangeJoin_=false;activeStrangePeer_="auto";activeStrangeGroup_.clear();resetStrangeRateLimit();strangeJoin_->setText("Enter room");if(strangePresence_)strangePresence_->setText("OFFLINE");}});
        connect(&process_,&QProcess::started,this,[this]{log("Node process started");if(strangeProofEnabled_&&strangeProofEnabled_->isChecked()){strangeProofChain_.reset();strangeProofCopy_->setEnabled(false);strangeProofStatus_->setText("Ready · new node session, waiting for StrangeNet events.");}if(pendingStrangeJoin_)sendStrangeJoin();}); connect(&process_,&QProcess::errorOccurred,this,[this](QProcess::ProcessError){processFailed_=true;refreshConnectionPresentation();log("Process error · "+process_.errorString());statusText_->setText("The node could not continue: "+process_.errorString());});
        connect(&process_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus status){if(!processBuffer_.isEmpty()){log(QString::fromUtf8(processBuffer_).trimmed());processBuffer_.clear();}log(QString("Node stopped · exit %1 · %2").arg(code).arg(status==QProcess::NormalExit?"normal":"crashed"));statusText_->setText(stopping_&&status==QProcess::NormalExit?"Disconnected cleanly.":QString("Node stopped with exit code %1. Review Activity.").arg(code));processFailed_=!stopping_&&(status!=QProcess::NormalExit||code!=0);stopping_=false;refreshConnectionPresentation();connectButton_->setEnabled(configValid_);if(pendingQuit_){pendingQuit_=false;quitting_=true;savePreferences();qApp->quit();}});
    }
    bool loadConfig(const QString& path) {
        QFile file(path); if(!file.open(QIODevice::ReadOnly)){setUnknownConfig();return false;} QJsonParseError error; const auto doc=QJsonDocument::fromJson(file.readAll(),&error); if(error.error!=QJsonParseError::NoError||!doc.isObject()){configHealth_->setText("JSON could not be read: "+error.errorString());return false;}
        const auto root=doc.object(),network=root.value("network").toObject(),security=root.value("security").toObject(),shaping=root.value("traffic_shaping").toObject(),external=root.value("external_transport").toObject(),adaptive=root.value("adaptive_transport").toObject(),tunnel=root.value("tunnel").toObject(),egress=root.value("egress").toObject();
        const auto bootstrap=root.value("bootstrap").toArray();
        mainnetMetric_->setText(bootstrap.isEmpty()?"Listener only":QString("%1 bootstrap route(s)").arg(bootstrap.size()));
        endpointMetric_->setText(QString("UDP port %1").arg(network.value("port").toInt(9090)));
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
        const bool shapingOn=shaping.value("enabled").toBool(false);shapingEnabled_->setChecked(shapingOn);shapingPadding_->setValue(shaping.value("max_padding_bytes").toInt(1024));shapingDelay_->setValue(shaping.value("max_delay_ms").toInt(20));
        const bool adaptiveOn=adaptive.value("enabled").toBool(false);const QString adaptiveMode=adaptive.value("mode").toString("auto");adaptiveEnabled_->setChecked(adaptiveOn);adaptiveMode_->setCurrentIndex(qMax(0,adaptiveMode_->findData(adaptiveMode)));adaptiveMetric_->setText(adaptiveOn?QString("Enabled · %1").arg(adaptiveMode.toUpper()):"Disabled · direct UDP");if(external.isEmpty()){transportMetric_->setText(adaptiveOn?"PQTP adaptive path":"Direct PQVPN UDP");transportDetails_->setText(adaptiveOn?"Policy is configured; runtime events report every lane change.":"No external transport selected.");}else{transportMetric_->setText(external.value("engine").toString("Unknown"));transportDetails_->setText(QString("Attach mode · local port %1 · external process required").arg(external.value("port").toInt()));}return !root.isEmpty();
    }
    void setUnknownConfig(){mainnetMetric_->setText("Not loaded");endpointMetric_->setText("Not loaded");verificationMetric_->setText("Unknown");tunnelMetric_->setText("Unknown");egressMetric_->setText("Unknown");shapingMetric_->setText("Unknown");transportMetric_->setText("Configuration unavailable");transportDetails_->setText("Choose a readable JSON configuration.");if(adaptiveMetric_)adaptiveMetric_->setText("Configuration unavailable");}
    QString engineConfiguration(const QString& id){
        QSettings settings("PQVPN","Privacy Console");QString path=settings.value(id+"ConfigPath").toString();if(QFileInfo(path).isFile())return path;
        const QString extension=id=="udp2raw"?".conf":".json";
        for(const QString& candidate:QStringList{QString::fromStdString(pqvpn::console::user_profile_directory().generic_string())+"/"+id+extension,QDir::homePath()+"/.config/"+id+"/config"+extension,QDir::homePath()+"/.config/"+id+"/client"+extension})if(QFileInfo(candidate).isFile()){path=candidate;break;}
        if(!QFileInfo(path).isFile())path=QFileDialog::getOpenFileName(this,"Choose existing "+id+" configuration",QDir::homePath());
        if(!path.isEmpty())settings.setValue(id+"ConfigPath",QFileInfo(path).absoluteFilePath());return path;
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
    void saveTransportSettings(){QFile source(configPath_->text());if(!source.open(QIODevice::ReadOnly)){log("Transport policy was not saved · configuration unavailable");return;}QJsonParseError error;auto document=QJsonDocument::fromJson(source.readAll(),&error);source.close();if(error.error!=QJsonParseError::NoError||!document.isObject()){log("Transport policy was not saved · invalid JSON");return;}auto root=document.object();auto adaptive=root.value("adaptive_transport").toObject();adaptive["enabled"]=adaptiveEnabled_->isChecked();adaptive["mode"]=adaptiveMode_->currentData().toString();if(!adaptive.contains("loss_switch_percent"))adaptive["loss_switch_percent"]=12.0;if(!adaptive.contains("jitter_switch_ms"))adaptive["jitter_switch_ms"]=45.0;if(!adaptive.contains("failure_switch_count"))adaptive["failure_switch_count"]=3;if(!adaptive.contains("recovery_probe_count"))adaptive["recovery_probe_count"]=4;if(!adaptive.contains("minimum_dwell_ms"))adaptive["minimum_dwell_ms"]=5000;root["adaptive_transport"]=adaptive;auto shaping=root.value("traffic_shaping").toObject();shaping["enabled"]=shapingEnabled_->isChecked();shaping["max_padding_bytes"]=shapingPadding_->value();shaping["max_delay_ms"]=shapingDelay_->value();if(!shaping.contains("max_queue_packets"))shaping["max_queue_packets"]=256;if(!shaping.contains("max_queue_bytes"))shaping["max_queue_bytes"]=524288;root["traffic_shaping"]=shaping;document.setObject(root);QSaveFile output(configPath_->text());if(!output.open(QIODevice::WriteOnly)||output.write(document.toJson(QJsonDocument::Indented))<0||!output.commit()){log("Transport policy could not be written safely");return;}invalidate("Transport policy saved. Validate before connecting.");loadConfig(configPath_->text());log(QString("Transport policy saved · %1 · shaping %2").arg(adaptiveMode_->currentData().toString(),shapingEnabled_->isChecked()?"enabled":"disabled"));}
    void invalidate(const QString& reason){configValid_=false;validatedConfigHash_.clear();validatedExecutableHash_.clear();connectButton_->setEnabled(false);configHealth_->setText(reason);refreshConnectionPresentation();}
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
        configValid_=passed;configHealth_->setText(message);connectButton_->setEnabled(passed);
        if(passed){validatedConfigHash_=fileFingerprint(configPath_->text());validatedExecutableHash_=fileFingerprint(executablePath_->text());
            if(validatedConfigHash_.isEmpty()||validatedExecutableHash_.isEmpty()){invalidate("Validated files are no longer readable. Validate again.");passed=false;}}
        else{validatedConfigHash_.clear();validatedExecutableHash_.clear();}
        validateButton_->setEnabled(true);refreshConnectionPresentation();log(passed?"Configuration and platform preflight passed":"Connection preflight failed");
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
    void toggleConnection(){if(process_.state()==QProcess::NotRunning){if(!configValid_)return;if(fileFingerprint(configPath_->text())!=validatedConfigHash_||fileFingerprint(executablePath_->text())!=validatedExecutableHash_){invalidate("Configuration or executable changed after validation. Validate again.");log("Connection blocked · validated files changed");return;}stopping_=false;processFailed_=false;bool noTunnel=false;
        noTunnel=noTunnel_&&noTunnel_->isChecked();
        log(QString("Connect requested · config %1 · log %2%3").arg(configPath_->text(),logLevel_->currentText(),noTunnel?" · no-tunnel":""));QStringList args={"--config",configPath_->text(),"--log-level",logLevel_->currentText(),"--control-stdin"};if(noTunnel)args<<"--no-tunnel";
        process_.start(executablePath_->text(),args);
        }else requestStop();}
    QString strangeMarkup(QString value) const {return value.toHtmlEscaped().replace("\n","<br>");}
    void appendStrangeSystem(const QString& value){if(!strangeTranscript_)return;strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='5'><tr><td align='center'><span style='color:#8fa4c9;font-size:9pt'>%1</span></td></tr></table>").arg(strangeMarkup(value)));}
    void appendStrangeText(const QString& value){appendStrangeSystem(value);}
    void appendStrangeMessageBubble(const QString& sender,const QString& value,qint64 timestamp,bool outbound){if(!strangeTranscript_)return;const QString label=outbound?QStringLiteral("You"):sender.left(12);const QString time=timestamp>0?QDateTime::fromMSecsSinceEpoch(timestamp).toLocalTime().toString("HH:mm"):QDateTime::currentDateTime().toString("HH:mm");const QString side=outbound?QStringLiteral("right"):QStringLiteral("left");const QString background=outbound?QStringLiteral("#5432c9"):QStringLiteral("#202a48");strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='3'><tr><td align='%1'><table width='72%' cellspacing='0' cellpadding='12' bgcolor='%2'><tr><td><span style='color:#bfcaf0;font-size:8pt;font-weight:600'>%3 · %4</span><br><span style='color:#ffffff;font-size:11pt'>%5</span></td></tr></table></td></tr></table>").arg(side,background,label.toHtmlEscaped(),time,strangeMarkup(value)));}
    void appendStrangeSticker(const QString& payload,const QString& sender){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),caption=object.value("caption").toString(),color=object.value("color").toString();const QStringList palette{"#5432c9","#0f8fa8","#b83280","#b86b18","#226c4a","#3d4d73"};if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16||caption.size()>48||!palette.contains(color)){appendStrangeSystem("A malformed sticker was discarded safely.");return;}const QString side=sender=="You"?QStringLiteral("right"):QStringLiteral("left");strangeTranscript_->append(QString("<table width='100%' cellspacing='0' cellpadding='3'><tr><td align='%1'><table width='46%' cellpadding='14' bgcolor='%2'><tr><td><span style='font-size:34pt'>%3</span><br><span style='color:white;font-size:12pt;font-weight:700'>%4</span><br><span style='color:#e8e9ff;font-size:8pt'>%5</span></td></tr></table></td></tr></table>").arg(side,color,emoji.toHtmlEscaped(),caption.toHtmlEscaped(),sender.toHtmlEscaped()));}
    void appendStrangeReaction(const QString& payload,const QString& sender,qulonglong fallbackSequence){QJsonParseError error;const auto object=QJsonDocument::fromJson(payload.toUtf8(),&error).object();const QString emoji=object.value("emoji").toString(),target=object.value("target").toString().left(12);const auto sequence=object.value("sequence").toVariant().toULongLong();if(error.error!=QJsonParseError::NoError||emoji.isEmpty()||emoji.size()>16){appendStrangeSystem("A malformed reaction was discarded safely.");return;}appendStrangeSystem(QString("%1 reacted %2 to %3 · message %4").arg(sender,emoji,target.isEmpty()?QString("the latest message"):target).arg(sequence?sequence:fallbackSequence));}
    void recordStrangeProof(const QString& name,const QJsonObject& event){if(!strangeProofEnabled_||!strangeProofEnabled_->isChecked())return;const QStringList committed{"strangenet.message","strangenet.sticker","strangenet.reaction","strangenet.delivered","strangenet.sent"};if(!committed.contains(name))return;const bool accepted=strangeProofChain_.append(QJsonDocument(event).toJson(QJsonDocument::Compact));if(!accepted){strangeProofStatus_->setText("Proof chain limit reached; copy this anchor before starting a new chain.");return;}strangeProofCopy_->setEnabled(true);strangeProofStatus_->setText(QString("%1 event(s) committed in memory · content excluded from the anchor.").arg(strangeProofChain_.size()));}
    void notifyStrangeActivity(){if(pages_->currentIndex()==StrangeNet&&isActiveWindow())return;unreadStrange_=qMin(unreadStrange_+1,999);const QString label=QString("04   StrangeNet · %1").arg(unreadStrange_);pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);const auto now=QDateTime::currentMSecsSinceEpoch();if(strangeNotifications_->isChecked()&&tray_->isVisible()&&now-lastStrangeNotificationMs_>=3000){lastStrangeNotificationMs_=now;tray_->showMessage("New encrypted StrangeNet activity","Open PQVPN to view it.",QSystemTrayIcon::Information,3500);}}
    bool validStrangeRoom() { const QString room=strangeRoom_->text().trimmed();const bool valid=room.size()<=64&&room.split('/').size()<=8&&QRegularExpression("^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$").match(room).hasMatch();if(!valid)appendStrangeText("Use a safe room path: 1–64 characters, at most 8 levels, for example mainnet/friends/poetry.");return valid; }
    void sendControl(const QJsonObject& command){process_.write(QJsonDocument(command).toJson(QJsonDocument::Compact)+'\n');}
    void sendStrangeJoin(){const auto selected=peerDirectory_->selectedItems();activeStrangeGroup_.clear();if(selected.size()>=2){QJsonArray peers;for(const auto* item:selected){const QString peer=item->data(Qt::UserRole).toString();peers.append(peer);activeStrangeGroup_.append(peer);}sendControl({{"command","strangenet.join"},{"room",strangeRoom_->text().trimmed()},{"peer","auto"},{"peers",peers}});return;}sendControl({{"command","strangenet.join"},{"room",strangeRoom_->text().trimmed()},{"peer","auto"}});}
    void toggleStrangeNet(){if(strangeActive_){sendControl({{"command","strangenet.leave"}});return;}if(!validStrangeRoom())return;if(process_.state()==QProcess::NotRunning){if(!configValid_){appendStrangeText("Validate the mainnet configuration before joining.");switchPage(Connection);return;}pendingStrangeJoin_=true;appendStrangeText("Starting the mainnet connection for room '"+strangeRoom_->text().trimmed()+"'…");toggleConnection();return;}sendStrangeJoin();}
    void sendStrangeMessage(){const QString value=strangeMessage_->toPlainText();const QByteArray message=value.toUtf8();if(!strangeActive_||!strangeRecipientReady()||process_.state()!=QProcess::Running||QDateTime::currentMSecsSinceEpoch()<strangeSendBlockedUntilMs_||value.trimmed().isEmpty()||message.size()>2048)return;sendControl({{"command","strangenet.send"},{"text",value},{"reply_to",static_cast<qint64>(pendingReplyTo_)}});strangeSend_->setEnabled(false);}
    QAudioFormat strangeVoiceFormat() const {QAudioFormat format;format.setSampleRate(16000);format.setChannelCount(1);format.setSampleFormat(QAudioFormat::Int16);return format;}
    void startStrangeVoice(){
        if(strangeAudioSource_||!strangeActive_||!strangeRecipientReady())return;
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
        if(shieldProcess_.state()!=QProcess::NotRunning)return;const QString executable=piholeExecutable(),ftl=QStandardPaths::findExecutable("pihole-FTL");if(executable.isEmpty()||ftl.isEmpty()){shieldStatus_->setText("Pi-hole CLI/FTL was not found. Install local Pi-hole before applying a profile.");return;}
        QStringList regexes;for(const QString& raw:shieldRegex_->toPlainText().split('\n')){const QString expression=raw.trimmed();if(expression.isEmpty())continue;if(expression.toUtf8().size()>512||regexes.size()>=128){shieldStatus_->setText("Regex rejected: maximum 128 rules and 512 bytes per rule.");return;}QString base=expression;int cut=base.size();const int queryType=base.indexOf(";querytype=");const int invert=base.indexOf(";invert");if(queryType>=0)cut=qMin(cut,queryType);if(invert>=0)cut=qMin(cut,invert);base.truncate(cut);QRegularExpression compiled(base);if(!compiled.isValid()||compiled.match("").hasMatch()){shieldStatus_->setText("Regex rejected: invalid or capable of matching every domain · "+expression.left(80));return;}regexes.append(expression);}
#ifdef __linux__
        QString helper="/usr/lib/pqvpn/pqvpn-shield-helper";if(!QFileInfo(helper).isExecutable())helper=QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../pqvpn-shield-helper");const QString pkexec=QStandardPaths::findExecutable("pkexec");if(QFileInfo(helper).isExecutable()&&!pkexec.isEmpty()){QStringList arguments{helper,"apply",shieldProfile_->currentData(Qt::UserRole+1).toString()};arguments.append(regexes);shieldQueue_.clear();shieldApply_->setEnabled(false);shieldProcess_.setProperty("shieldOneClick",true);shieldProcess_.setProperty("shieldCommand","PQVPN Shield profile update");shieldStatus_->setText(QString("Applying %1 source(s) and %2 validated regex rule(s) in one authorized operation…").arg(shieldProfile_->currentData().toStringList().size()).arg(regexes.size()));shieldProcess_.start(pkexec,arguments);return;}
#endif
        shieldQueue_.clear();for(const QString& url:shieldProfile_->currentData().toStringList()){const QString sql=QString("INSERT OR IGNORE INTO adlist (address,enabled,comment) VALUES ('%1',1,'PQVPN Shield');").arg(url);shieldQueue_.append(QStringList{ftl,"sqlite3","-ni","/etc/pihole/gravity.db",sql});}for(const QString& expression:regexes)shieldQueue_.append(QStringList{executable,"--regex",expression});shieldQueue_.append(QStringList{executable,"-g"});shieldApply_->setEnabled(false);shieldStatus_->setText(QString("Applying %1 source(s) and %2 validated regex rule(s)…").arg(shieldProfile_->currentData().toStringList().size()).arg(regexes.size()));runNextShieldCommand();
    }
    void runNextShieldCommand(){if(shieldQueue_.isEmpty()){shieldApply_->setEnabled(true);QSettings("PQVPN","Privacy Console").setValue("shieldProfile",shieldProfile_->currentIndex());QSettings("PQVPN","Privacy Console").setValue("shieldRegex",shieldRegex_->toPlainText());shieldStatus_->setText("Shield profile applied. Gravity updated; refreshing aggregate counters…");refreshShieldCounters();return;}QStringList command=shieldQueue_.takeFirst();const QString program=command.takeFirst();shieldProcess_.setProperty("shieldCommand",program+" "+command.join(' '));shieldProcess_.start(program,command);}
    void shieldCommandFinished(int code,QProcess::ExitStatus status){if(shieldProcess_.property("shieldStats").toBool())return;const bool oneClick=shieldProcess_.property("shieldOneClick").toBool();shieldProcess_.setProperty("shieldOneClick",false);const QString error=QString::fromUtf8(shieldProcess_.readAllStandardError()).trimmed().left(500);if(status!=QProcess::NormalExit||code!=0){shieldQueue_.clear();shieldApply_->setEnabled(true);shieldStatus_->setText("Shield update stopped safely · "+(error.isEmpty()?shieldProcess_.property("shieldCommand").toString():error));return;}if(oneClick){shieldApply_->setEnabled(true);QSettings("PQVPN","Privacy Console").setValue("shieldProfile",shieldProfile_->currentIndex());QSettings("PQVPN","Privacy Console").setValue("shieldRegex",shieldRegex_->toPlainText());shieldStatus_->setText("Shield applied in one operation. Gravity updated; refreshing aggregate counters…");refreshShieldCounters();return;}runNextShieldCommand();}
    void refreshShieldCounters(){if(shieldProcess_.state()!=QProcess::NotRunning)return;const QString executable=piholeExecutable();if(executable.isEmpty()){shieldStatus_->setText("Pi-hole CLI was not found; counters are unavailable.");return;}shieldRefresh_->setEnabled(false);shieldProcess_.setProperty("shieldStats",true);shieldProcess_.start(executable,QStringList{"-c","-j"});connect(&shieldProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus status){if(!shieldProcess_.property("shieldStats").toBool())return;shieldProcess_.setProperty("shieldStats",false);shieldRefresh_->setEnabled(true);if(status!=QProcess::NormalExit||code!=0){shieldStatus_->setText("Pi-hole did not return aggregate statistics.");return;}QJsonParseError error;const auto stats=QJsonDocument::fromJson(shieldProcess_.readAllStandardOutput(),&error).object();if(error.error!=QJsonParseError::NoError){shieldStatus_->setText("Pi-hole statistics were not valid JSON.");return;}const auto today=stats.value("ads_blocked_today").toVariant().toULongLong();const auto total=stats.value("domains_being_blocked").toVariant().toULongLong();if(!shieldBaseline_)shieldBaseline_=today;shieldSessionCount_=today>=shieldBaseline_?today-shieldBaseline_:0;shieldSession_->setText(QString::number(shieldSessionCount_));shieldToday_->setText(QString::number(today));shieldTotal_->setText(QString::number(total));shieldStatus_->setText("Aggregate counters refreshed · query history and client identities were not read.");},Qt::SingleShotConnection);}
    void runShieldSpeedTest(){if(speedProcess_.state()!=QProcess::NotRunning)return;const QString executable=QStandardPaths::findExecutable("iperf3");if(executable.isEmpty()){speedResult_->setText("iperf3 is not installed; no network test was started.");return;}const QString target=speedTarget_->text().trimmed();if(target.size()>253||!QRegularExpression("^[A-Za-z0-9][A-Za-z0-9.:_-]*$").match(target).hasMatch()){speedResult_->setText("Enter one explicit hostname or LAN address; subnet ranges are not accepted.");return;}speedRun_->setEnabled(false);speedResult_->setText("Testing the selected target for 5 seconds…");speedProcess_.start(executable,QStringList{"-c",target,"-p",QString::number(speedPort_->value()),"-J","-t","5"});}
    void speedTestFinished(int code,QProcess::ExitStatus status){speedRun_->setEnabled(true);if(status!=QProcess::NormalExit||code!=0){speedResult_->setText("Speed test failed · "+QString::fromUtf8(speedProcess_.readAllStandardError()).trimmed().left(300));return;}QJsonParseError error;const auto root=QJsonDocument::fromJson(speedProcess_.readAllStandardOutput(),&error).object();const auto end=root.value("end").toObject();const double down=end.value("sum_received").toObject().value("bits_per_second").toDouble()/1000000.0;const double up=end.value("sum_sent").toObject().value("bits_per_second").toDouble()/1000000.0;if(error.error!=QJsonParseError::NoError||down<=0){speedResult_->setText("iperf3 returned no usable throughput result.");return;}speedResult_->setText(QString("Selected target only · receive %1 Mbit/s · send %2 Mbit/s · 5 seconds").arg(down,0,'f',1).arg(up,0,'f',1));}
    void sendStrangeReaction(const QString& emoji){if(!strangeActive_||!strangeRecipientReady()||QDateTime::currentMSecsSinceEpoch()<strangeSendBlockedUntilMs_||lastStrangeSequence_==0)return;const QJsonObject reaction{{"emoji",emoji},{"target",lastStrangeSender_},{"sequence",static_cast<qint64>(lastStrangeSequence_)}};sendControl({{"command","strangenet.react"},{"reply_to",static_cast<qint64>(lastStrangeSequence_)},{"text",QString::fromUtf8(QJsonDocument(reaction).toJson(QJsonDocument::Compact))}});}
    void createStrangeSticker(){if(!strangeActive_||!strangeRecipientReady()||QDateTime::currentMSecsSinceEpoch()<strangeSendBlockedUntilMs_){appendStrangeText("Join a room with an authenticated recipient and wait for antiflood readiness before creating a sticker.");return;}QDialog dialog(this);dialog.setWindowTitle("Create encrypted sticker");auto* layout=new QVBoxLayout(&dialog);auto* emoji=new QComboBox;emoji->addItems({"🚀","🔐","🛡️","🎉","🔥","💜","🌌","⚡","👋","👍"});auto* caption=new QLineEdit;caption->setMaxLength(48);caption->setPlaceholderText("Short caption");auto* color=new QComboBox;const QList<QPair<QString,QString>> colors{{"Violet","#5432c9"},{"Cyan","#0f8fa8"},{"Magenta","#b83280"},{"Amber","#b86b18"},{"Green","#226c4a"},{"Slate","#3d4d73"}};for(const auto& entry:colors)color->addItem(entry.first,entry.second);auto* preview=text("","heroTitle");auto refresh=[=]{preview->setText(emoji->currentText()+"  "+caption->text());preview->setStyleSheet("padding:18px;border-radius:14px;background:"+color->currentData().toString()+";color:white");};connect(emoji,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});connect(caption,&QLineEdit::textChanged,&dialog,[=]{refresh();});connect(color,&QComboBox::currentTextChanged,&dialog,[=]{refresh();});layout->addWidget(text("EMOJI","eyebrow"));layout->addWidget(emoji);layout->addWidget(text("CAPTION","eyebrow"));layout->addWidget(caption);layout->addWidget(text("COLOR","eyebrow"));layout->addWidget(color);layout->addWidget(preview);auto* send=new QPushButton("Send sticker E2E");layout->addWidget(send);connect(send,&QPushButton::clicked,&dialog,&QDialog::accept);refresh();if(dialog.exec()!=QDialog::Accepted)return;const QJsonObject sticker{{"emoji",emoji->currentText()},{"caption",caption->text()},{"color",color->currentData().toString()}};sendControl({{"command","strangenet.sticker"},{"text",QString::fromUtf8(QJsonDocument(sticker).toJson(QJsonDocument::Compact))}});}
    void requestStop(){if(process_.state()==QProcess::NotRunning)return;stopping_=true;refreshConnectionPresentation();statusText_->setText("Disconnecting cleanly…");log("Disconnect requested");process_.write("{\"command\":\"node.shutdown\"}\n");process_.closeWriteChannel();QTimer::singleShot(5000,this,[this]{if(process_.state()!=QProcess::NotRunning){log("Clean shutdown timed out; process termination escalated");process_.kill();}});}
    void quitApplication(){quitting_=true;if(process_.state()!=QProcess::NotRunning){pendingQuit_=true;requestStop();}else{savePreferences();qApp->quit();}}
    void restoreFromTray(){showNormal();raise();activateWindow();}
    void fadeWidget(QWidget* widget,int duration=240){if(!widget||!reduceMotion_||reduceMotion_->isChecked())return;if(widget->graphicsEffect())widget->setGraphicsEffect(nullptr);auto* effect=new QGraphicsOpacityEffect(widget);widget->setGraphicsEffect(effect);auto* animation=new QPropertyAnimation(effect,"opacity",effect);animation->setDuration(duration);animation->setStartValue(0.18);animation->setEndValue(1.0);animation->setEasingCurve(QEasingCurve::OutCubic);connect(animation,&QPropertyAnimation::finished,widget,[widget,effect]{if(widget->graphicsEffect()!=effect)return;effect->setEnabled(false);QTimer::singleShot(0,widget,[widget,effect]{if(widget->graphicsEffect()==effect)widget->setGraphicsEffect(nullptr);});});animation->start(QAbstractAnimation::DeleteWhenStopped);}
    void switchPage(int index){if(!pages_||index<0||index>=pages_->count())return;pageButtons_.value(index)->setChecked(true);if(index==StrangeNet&&unreadStrange_){unreadStrange_=0;const QString label="04   StrangeNet";pageButtons_[StrangeNet]->setProperty("fullText",label);if(sidebar_->width()>100)pageButtons_[StrangeNet]->setText(label);}const bool changed=pages_->currentIndex()!=index;if(changed)pages_->setCurrentIndex(index);if(pageScroll_)pageScroll_->verticalScrollBar()->setValue(0);if(changed)fadeWidget(pages_->currentWidget(),260);}
    void setMotion(bool enabled){if(!auroraAnimation_){auroraAnimation_=new QPropertyAnimation(aurora_,"phase",this);auroraAnimation_->setStartValue(0.0);auroraAnimation_->setEndValue(6.283185307);auroraAnimation_->setDuration(15000);auroraAnimation_->setLoopCount(-1);pulseAnimation_=new QPropertyAnimation(orb_,"pulse",this);pulseAnimation_->setStartValue(0.0);pulseAnimation_->setEndValue(1.0);pulseAnimation_->setDuration(1700);pulseAnimation_->setEasingCurve(QEasingCurve::InOutSine);pulseAnimation_->setLoopCount(-1);}if(enabled){auroraAnimation_->start();pulseAnimation_->start();}else{auroraAnimation_->stop();pulseAnimation_->stop();aurora_->setPhase(0);orb_->setPulse(0);}}
    void setSidebarCompact(bool compact){QSettings("PQVPN","Privacy Console").setValue("compactSidebar",compact);const int width=compact?82:238;brandWords_->setVisible(!compact);for(int i=0;i<navButtons_.size();++i)navButtons_[i]->setText(compact?QString("%1").arg(i+1,2,10,QChar('0')):navButtons_[i]->property("fullText").toString());sidebar_->setFixedWidth(width);}
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
    void applyPreferences(){QSettings settings("PQVPN","Privacy Console");systemDark_=qApp->palette().color(QPalette::Window).lightness()<128;restoreGeometry(settings.value("geometry").toByteArray());const QString stored=settings.value("config").toString();if(!stored.isEmpty()&&QFileInfo(stored).isFile())configPath_->setText(stored);else if(!stored.isEmpty())settings.remove("config");settings.remove("minimizeToTray");reduceMotion_->setChecked(settings.value("reduceMotion",false).toBool());compactSidebar_->setChecked(settings.value("compactSidebar",false).toBool());const bool geekEnabled=settings.value("geekTelemetry",false).toBool();geekTelemetry_->setChecked(geekEnabled);setGeekMode(geekEnabled);strangeNotifications_->setChecked(settings.value("strangeNotifications",true).toBool());if(shieldProfile_)shieldProfile_->setCurrentIndex(qBound(0,settings.value("shieldProfile",0).toInt(),shieldProfile_->count()-1));if(shieldRegex_)shieldRegex_->setPlainText(settings.value("shieldRegex").toString());applyTheme(settings.value("theme","system").toString());}
    void savePreferences(){QSettings settings("PQVPN","Privacy Console");settings.setValue("geometry",saveGeometry());settings.setValue("config",configPath_->text());settings.remove("minimizeToTray");settings.setValue("strangeNotifications",strangeNotifications_->isChecked());settings.setValue("theme",themeMode_);}
    void log(const QString& message){const QString stamp=QDateTime::currentDateTime().toString("HH:mm:ss");for(const QString& line:message.split('\n',Qt::SkipEmptyParts))activity_->appendPlainText(stamp+"  "+line.left(16384));}
    void copyDiagnostics(){const auto phase=pqvpn::console::connection_phase({process_.state()!=QProcess::NotRunning,mainnetReady_,tunnelReady_,noTunnel_&&noTunnel_->isChecked(),stopping_,processFailed_});const QString state=QString::fromUtf8(pqvpn::console::phase_label(phase).data());const QString value=QString("PQVPN Privacy Console\nQt %1\nOS %2\nNode %3\nConfig %4\nState %5\nTransport %6\nShaping %7").arg(qVersion(),QSysInfo::prettyProductName(),executablePath_->text(),configPath_->text(),state,transportMetric_->text(),shapingMetric_->text());QApplication::clipboard()->setText(value);statusBar()->showMessage("Diagnostics copied — activity log excluded",3000);log("Diagnostics copied");}
    void showCommandPalette(){QDialog dialog(this);dialog.setWindowTitle("Command palette");dialog.resize(540,410);auto* layout=new QVBoxLayout(&dialog);auto* search=new QLineEdit;search->setPlaceholderText("Type a command…");auto* list=new QListWidget;const QList<QPair<QString,QString>> commands={{"Go to overview","overview"},{"Review connection","connection"},{"Inspect transports","transports"},{"Open StrangeNet","strangenet"},{"Open DNS Shield","shield"},{"Open activity","activity"},{"Privacy principles","privacy"},{"Validate configuration","validate"},{"Copy diagnostics","diagnostics"},{"About PQVPN","about"}};for(const auto& command:commands){auto* item=new QListWidgetItem(command.first,list);item->setData(Qt::UserRole,command.second);}layout->addWidget(search);layout->addWidget(list);connect(search,&QLineEdit::textChanged,&dialog,[list](const QString& query){for(int row=0;row<list->count();++row)list->item(row)->setHidden(!list->item(row)->text().contains(query,Qt::CaseInsensitive));});connect(list,&QListWidget::itemActivated,&dialog,[this,&dialog](QListWidgetItem* item){const QString command=item->data(Qt::UserRole).toString();const QHash<QString,int> pages={{"overview",Overview},{"connection",Connection},{"transports",Transports},{"strangenet",StrangeNet},{"shield",Shield},{"activity",Activity},{"privacy",Privacy},{"about",About}};if(pages.contains(command))switchPage(pages.value(command));else if(command=="validate")validateConfig();else if(command=="diagnostics")copyDiagnostics();dialog.accept();});list->setCurrentRow(0);search->setFocus();dialog.exec();}
};

int main(int argc,char** argv){bool softwareRendering=false;for(int index=1;index<argc;++index){const QString argument=QString::fromLocal8Bit(argv[index]);if(argument=="--software-rendering"||argument=="--smoke-test")softwareRendering=true;}const QString platform=qEnvironmentVariable("QT_QPA_PLATFORM");const bool headless=platform=="offscreen"||platform=="minimal";if(!headless&&!softwareRendering&&!qEnvironmentVariableIsSet("PQVPN_DISABLE_OPENGL"))QCoreApplication::setAttribute(Qt::AA_UseDesktopOpenGL);QApplication app(argc,argv);QFont uiFont=QFontDatabase::systemFont(QFontDatabase::GeneralFont);
#ifdef Q_OS_WIN
    for(const QString& name:QStringList{QStringLiteral("Segoe UI"),QStringLiteral("Arial"),QStringLiteral("Tahoma")}){
        const QFont candidate(name);
        if(QFontDatabase::families().contains(name,Qt::CaseInsensitive)&&QFontMetrics(candidate).inFont(QChar('A'))){uiFont=candidate;break;}
    }
#endif
    app.setFont(uiFont);app.setApplicationName("PQVPN Privacy Console");app.setOrganizationName("PQVPN");app.setQuitOnLastWindowClosed(false);app.setWindowIcon(QIcon(":/brand/logo.svg"));Window window;if(qEnvironmentVariableIsSet("PQVPN_SMOKE_COMPACT"))window.resize(window.minimumSize());window.show();if(app.arguments().contains("--smoke-test")){if(!window.verifyTrayIcons()||!window.verifyClosePolicy()||!window.verifyPrimaryActions()||!pqvpn::console::StrangeNetProofChain::selfTest()||!pqvpn::console::ReleaseUpdater::selfTest())return 1;if(app.arguments().contains("--verify-installation")&&!window.verifyInstallation())return 1;window.prepareSmokePage(qEnvironmentVariable("PQVPN_SMOKE_PAGE"));window.prepareSmokeTheme(qEnvironmentVariable("PQVPN_SMOKE_THEME"));app.processEvents();if(!window.verifyScrollNavigation())return 1;window.prepareSmokePage(qEnvironmentVariable("PQVPN_SMOKE_PAGE"));app.processEvents();const QPixmap frame=window.grab();if(frame.isNull())return 1;const QString output=qEnvironmentVariable("PQVPN_SMOKE_IMAGE");if(!output.isEmpty()&&!frame.save(output))return 1;if(!window.verifyVisualLayout())return 1;return 0;}return app.exec();}

#include "pqvpn_monitor.moc"
