#include <QGuiApplication>
#include <QQmlApplicationEngine>

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("PQVPN Mobile Preview");
    app.setOrganizationName("PQVPN");
    app.setOrganizationDomain("io.github.tadaka9");

    QQmlApplicationEngine engine;
    engine.loadFromModule("PQVPN.Mobile", "Main");
    if (engine.rootObjects().isEmpty()) return 1;
    return app.exec();
}
