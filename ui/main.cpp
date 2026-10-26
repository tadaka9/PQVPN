#include <QGuiApplication>
#include <QQuickWindow>
#include <QTimer>
#include <QQmlApplicationEngine>

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("PQVPN");
    app.setOrganizationName("PQVPN");
    app.setOrganizationDomain("io.github.tadaka9");

    QQmlApplicationEngine engine;
    engine.loadFromModule("PQVPN.App", "Main");
    if (engine.rootObjects().isEmpty()) return 1;
    const auto pageIndex = app.arguments().indexOf("--page");
    if (pageIndex >= 0) {
        if (pageIndex + 1 >= app.arguments().size()) return 5;
        bool validPage = false;
        const auto page = app.arguments().at(pageIndex + 1).toInt(&validPage);
        if (!validPage || page < 0 || page > 2) return 5;
        auto* rootObject = engine.rootObjects().constFirst();
        QTimer::singleShot(0, &app, [rootObject, page]() {
            rootObject->setProperty("page", page);
        });
    }
    if (app.arguments().contains("--smoke-test")) {
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    }
    const auto screenshotIndex = app.arguments().indexOf("--screenshot");
    if (screenshotIndex >= 0) {
        if (screenshotIndex + 1 >= app.arguments().size()) return 2;
        const auto screenshotPath = app.arguments().at(screenshotIndex + 1);
        auto* window = qobject_cast<QQuickWindow*>(engine.rootObjects().constFirst());
        if (window == nullptr) return 3;
        QTimer::singleShot(250, &app, [window, screenshotPath, &app]() {
            app.exit(window->grabWindow().save(screenshotPath) ? 0 : 4);
        });
    }
    return app.exec();
}
