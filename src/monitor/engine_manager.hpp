#pragma once
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <QStandardPaths>
#include <QSysInfo>
#include <QTemporaryDir>
#include <QTimer>
#include <functional>
#include <memory>

namespace pqvpn::console {
class EngineManager : public QObject {
public:
    std::function<void(const QString&)> report;
    explicit EngineManager(QObject* parent) : QObject(parent) {}
    ~EngineManager() override { for (auto* process : jobs_) { process->kill(); process->waitForFinished(300); } }
    bool active(const QString& id) const { return jobs_.contains(id); }
    void stop(const QString& id) {
        if (auto* process = jobs_.value(id)) {
            process->terminate();
            QTimer::singleShot(2000, process, [process] { if (process->state() != QProcess::NotRunning) process->kill(); });
        }
    }
    void start(const QString& id, const QString& configuration) {
        if (active(id)) { message(id + ": already starting or running"); return; }
        if (!QFileInfo(configuration).isFile()) { message(id + ": choose an existing engine configuration first"); return; }
        QFile manifest(":/transports/engines.json");
        if (!manifest.open(QIODevice::ReadOnly)) return;
        QString family;
#if defined(Q_OS_WIN)
        family = "windows";
#elif defined(Q_OS_MACOS)
        family = "macos";
#elif defined(Q_OS_LINUX)
        family = "linux";
#endif
        QString architecture = QSysInfo::currentCpuArchitecture();
        if (architecture == "aarch64") architecture = "arm64";
        const auto entries = QJsonDocument::fromJson(manifest.readAll()).object().value("engines").toArray();
        QJsonObject entry;
        for (const auto& value : entries) {
            const auto candidate = value.toObject();
            if (candidate.value("engine").toString() == id && candidate.value("platform").toString() == family + "-" + architecture) entry = candidate;
        }
        if (entry.isEmpty()) { message(id + ": no verified automatic installer for this platform"); return; }
        const QString directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/engines/" + id + "/" + entry.value("version").toString();
        if (!QDir().mkpath(directory)) { message(id + ": cannot create engine cache"); return; }
        const QString archive = directory + "/verified-archive";
        const auto verified = [entry](const QString& path) {
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly)) return false;
            QCryptographicHash hash(QCryptographicHash::Sha256);
            return hash.addData(&file) && hash.result().toHex() == entry.value("sha256").toString().toLatin1();
        };
        if (verified(archive)) { extract(id, configuration, entry, archive, directory); return; }
        const QString curl = QStandardPaths::findExecutable("curl");
        if (curl.isEmpty()) { message(id + ": curl is required for verified downloads"); return; }
        auto temporary = std::make_shared<QTemporaryDir>(directory + "/download-XXXXXX");
        if (!temporary->isValid()) return;
        const QString downloaded = temporary->filePath("archive");
        auto* process = new QProcess(this);
        jobs_[id] = process;
        message(id + ": downloading pinned " + entry.value("version").toString());
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [=, this](int code, QProcess::ExitStatus status) {
                jobs_.remove(id); process->deleteLater();
                if (status != QProcess::NormalExit || code != 0 || !verified(downloaded)) {
                    message(id + ": download failed or checksum mismatch; nothing executed"); return;
                }
                QFile::remove(archive);
                if (!QFile::rename(downloaded, archive)) { message(id + ": cannot store verified archive"); return; }
                extract(id, configuration, entry, archive, directory);
            });
        connect(process, &QProcess::errorOccurred, this, [=, this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) { jobs_.remove(id); process->deleteLater(); message(id + ": downloader could not start"); }
        });
        process->start(curl, {"--fail", "--location", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https", "--max-time", "120", "--max-filesize", "67108864", "--output", downloaded, entry.value("url").toString()});
        QTimer::singleShot(150000, process, [process] { if (process->state() != QProcess::NotRunning) process->kill(); });
    }
private:
    QMap<QString, QProcess*> jobs_;
    void message(const QString& text) { if (report) report(text); }
    void extract(const QString& id, const QString& configuration, const QJsonObject& entry,
                 const QString& archive, const QString& directory) {
        auto temporary = std::make_shared<QTemporaryDir>(directory + "/extract-XXXXXX");
        if (!temporary->isValid()) return;
        const bool deb = entry.value("format").toString() == "deb";
        const QString tool = QStandardPaths::findExecutable(deb ? "dpkg-deb" : "tar");
        if (tool.isEmpty()) { message(id + ": archive extraction tool unavailable"); return; }
        auto* process = new QProcess(this); jobs_[id] = process;
        const QString executable = directory + "/" + QFileInfo(entry.value("member").toString()).fileName();
        auto output = std::make_shared<QSaveFile>(executable);
        if (!output->open(QIODevice::WriteOnly) || !output->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) {
            jobs_.remove(id); process->deleteLater(); message(id + ": cannot create private engine executable"); return;
        }
        auto size = std::make_shared<qint64>(0);
        auto good = std::make_shared<bool>(true);
        const auto drain = [=] {
            const QByteArray bytes = process->readAllStandardOutput(); *size += bytes.size();
            if (*size > 128 * 1024 * 1024 || output->write(bytes) != bytes.size()) { *good = false; process->kill(); }
        };
        if (!deb) connect(process, &QProcess::readyReadStandardOutput, this, drain);
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [=, this](int code, QProcess::ExitStatus status) {
                jobs_.remove(id);
                if (!deb) drain();
                if (deb && code == 0) {
                    QFile file(temporary->filePath(entry.value("member").toString()));
                    if (!file.open(QIODevice::ReadOnly) || file.size() > 128 * 1024 * 1024) *good = false;
                    else { const auto bytes = file.readAll(); *size = bytes.size(); if (output->write(bytes) != bytes.size()) *good = false; }
                }
                process->deleteLater();
                if (status != QProcess::NormalExit || code != 0 || !*good || *size == 0 || !output->commit()) {
                    message(id + ": extraction failed; nothing executed"); return;
                }
                launch(id, executable, configuration, directory);
            });
        connect(process, &QProcess::errorOccurred, this, [=, this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) { jobs_.remove(id); process->deleteLater(); message(id + ": extractor could not start"); }
        });
        if (deb) process->start(tool, {"--extract", archive, temporary->path()});
        else process->start(tool, {"-xOf", archive, entry.value("member").toString()});
        QTimer::singleShot(30000, process, [process] { if (process->state() != QProcess::NotRunning) process->kill(); });
    }
    void launch(const QString& id, const QString& executable, const QString& configuration, const QString& directory) {
        auto* process = new QProcess(this); jobs_[id] = process;
        process->setWorkingDirectory(QFileInfo(configuration).absolutePath());
        QStringList arguments;
        if (id == "shadowsocks") arguments = {"-c", configuration};
        else if (id == "v2ray") arguments = {"run", "-c", configuration};
        else if (id == "udp2raw") arguments = {"--conf-file", configuration};
        else {
            QFile file(configuration);
            if (!file.open(QIODevice::ReadOnly)) { jobs_.remove(id); process->deleteLater(); return; }
            const auto config = QJsonDocument::fromJson(file.readAll()).object();
            const auto variables = config.value("environment").toObject();
            if (variables.isEmpty()) { jobs_.remove(id); process->deleteLater(); message(id + ": configuration needs managed-transport environment settings"); return; }
            auto environment = QProcessEnvironment::systemEnvironment();
            for (auto it = variables.begin(); it != variables.end(); ++it) {
                if (!it.key().startsWith("TOR_PT_") || !it.value().isString()) { jobs_.remove(id); process->deleteLater(); message(id + ": invalid managed-transport configuration"); return; }
                environment.insert(it.key(), it.value().toString());
            }
            environment.insert("TOR_PT_STATE_LOCATION", directory + "/state");
            process->setProcessEnvironment(environment);
        }
        // Engine output may contain credentials. Consume it without forwarding to logs.
        connect(process, &QProcess::readyReadStandardOutput, this, [process] { process->readAllStandardOutput(); });
        connect(process, &QProcess::readyReadStandardError, this, [process] { process->readAllStandardError(); });
        connect(process, &QProcess::started, this, [=, this] { message(id + ": engine started; peer authentication is still required"); });
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [=, this](int code, QProcess::ExitStatus) {
            jobs_.remove(id); process->deleteLater(); message(id + ": engine stopped (exit " + QString::number(code) + ")");
        });
        connect(process, &QProcess::errorOccurred, this, [=, this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) { jobs_.remove(id); process->deleteLater(); message(id + ": engine could not start on this system"); }
        });
        process->start(executable, arguments);
    }
};
} // namespace pqvpn::console
