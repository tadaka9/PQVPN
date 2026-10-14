#pragma once

#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QSysInfo>
#include <QUrl>
#include <QVector>
#include <functional>
#include <memory>
#include <utility>

namespace pqvpn::console {
class ReleaseUpdater final : public QObject {
public:
    std::function<void(const QString&)> report;
    std::function<void(bool)> downloadable;

    explicit ReleaseUpdater(QString currentVersion, QObject* parent)
        : QObject(parent), currentVersion_(std::move(currentVersion)), network_(this) {}

    void check() {
        if (busy_) return;
        busy_ = true; selectedAsset_ = {}; selectedSums_ = {};
        setDownloadable(false); message("Checking GitHub releases…");
        fetch(QUrl("https://api.github.com/repos/tadaka9/PQVPN/releases?per_page=20"), 2 * 1024 * 1024,
              [this](const QByteArray& bytes, const QString& error) {
            busy_ = false;
            if (!error.isEmpty()) { message("Update check failed: " + error); return; }
            const auto document = QJsonDocument::fromJson(bytes);
            if (!document.isArray()) { message("Update check failed: invalid release response"); return; }
            const auto current = versionKey(currentVersion_);
            if (current.isEmpty()) { message("Update check blocked: installed version is not comparable"); return; }
            QVector<qulonglong> best = current;
            QString bestTag;
            for (const auto& value : document.array()) {
                const auto release = value.toObject();
                if (release.value("draft").toBool()) continue;
                const auto tag = release.value("tag_name").toString();
                auto candidate = tag; if (candidate.startsWith('v')) candidate.remove(0, 1);
                const auto key = versionKey(candidate);
                if (key.isEmpty() || compare(key, best) <= 0) continue;
                const auto assets = release.value("assets").toArray();
                const auto package = selectAsset(assets);
                const auto sums = namedAsset(assets, "SHA256SUMS");
                if (package.isEmpty() || sums.isEmpty()) continue;
                best = key; bestTag = tag; selectedAsset_ = package; selectedSums_ = sums;
            }
            if (selectedAsset_.isEmpty()) { message("PQVPN " + currentVersion_ + " is current; no newer verified release is available"); return; }
            selectedTag_ = bestTag; setDownloadable(true);
            message("Update available: " + bestTag + " · " + selectedAsset_.value("name").toString());
        });
    }

    void download() {
        if (busy_ || selectedAsset_.isEmpty() || selectedSums_.isEmpty()) return;
        const QUrl sumsUrl(selectedSums_.value("browser_download_url").toString());
        if (!trustedReleaseUrl(sumsUrl)) { message("Update blocked: unexpected checksum URL"); return; }
        busy_ = true; setDownloadable(false); message("Downloading release checksums…");
        fetch(sumsUrl, 1024 * 1024, [this](const QByteArray& sums, const QString& error) {
            if (!error.isEmpty()) { busy_ = false; setDownloadable(true); message("Checksum download failed: " + error); return; }
            const QString name = selectedAsset_.value("name").toString();
            const QRegularExpression line("^([0-9A-Fa-f]{64})\\s+\\*?" + QRegularExpression::escape(name) + "$", QRegularExpression::MultilineOption);
            auto matches = line.globalMatch(QString::fromUtf8(sums)); QRegularExpressionMatch match; int count = 0;
            while (matches.hasNext()) { match = matches.next(); ++count; }
            if (count != 1) { busy_ = false; setDownloadable(true); message("Update blocked: asset needs one unique checksum"); return; }
            downloadAsset(QByteArray::fromHex(match.captured(1).toLatin1()));
        });
    }

private:
    QString currentVersion_;
    QNetworkAccessManager network_;
    QJsonObject selectedAsset_;
    QJsonObject selectedSums_;
    QString selectedTag_;
    bool busy_ = false;

    void message(const QString& value) { if (report) report(value); }
    void setDownloadable(bool value) { if (downloadable) downloadable(value); }

    static QVector<qulonglong> versionKey(QString version) {
        QRegularExpressionMatch match;
        const QRegularExpression publicLabel("^alpha-(\\d+)\\.(\\d+)-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression semverPrerelease("^(\\d+)\\.(\\d+)\\.(\\d+)-alpha-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression semver("^(\\d+)\\.(\\d+)\\.(\\d+)$");
        if ((match = publicLabel.match(version)).hasMatch()) return {match.captured(1).toULongLong(), match.captured(2).toULongLong(), 0, 0, match.captured(3).toULongLong()};
        if ((match = semverPrerelease.match(version)).hasMatch()) return {match.captured(1).toULongLong(), match.captured(2).toULongLong(), match.captured(3).toULongLong(), 0, match.captured(4).toULongLong()};
        if ((match = semver.match(version)).hasMatch()) return {match.captured(1).toULongLong(), match.captured(2).toULongLong(), match.captured(3).toULongLong(), 1, 0};
        return {};
    }
    static int compare(const QVector<qulonglong>& left, const QVector<qulonglong>& right) {
        for (int index = 0; index < qMin(left.size(), right.size()); ++index) {
            if (left[index] < right[index]) return -1;
            if (left[index] > right[index]) return 1;
        }
        return left.size() < right.size() ? -1 : left.size() > right.size() ? 1 : 0;
    }
    static QJsonObject namedAsset(const QJsonArray& assets, const QString& name) {
        for (const auto& value : assets) if (value.toObject().value("name").toString() == name) return value.toObject();
        return {};
    }
    static QJsonObject selectAsset(const QJsonArray& assets) {
        QString architecture = QSysInfo::currentCpuArchitecture();
        if (architecture == "aarch64") architecture = "arm64";
        if (architecture == "amd64") architecture = "x86_64";
        QStringList suffixes;
#if defined(Q_OS_WIN)
        if (architecture == "x86_64") architecture = "x64";
        suffixes = {"-windows-" + architecture + ".msi"};
#elif defined(Q_OS_MACOS)
        suffixes = {"-macos-" + architecture + ".pkg", "-macos-" + architecture + ".dmg", "-macos-" + architecture + ".tar.gz"};
#elif defined(Q_OS_LINUX)
        suffixes = architecture == "x86_64" ? QStringList{"_amd64.deb", "-linux-x86_64.tar.gz"} : QStringList{"_arm64.deb", "-linux-arm64.tar.gz"};
#endif
        for (const auto& suffix : suffixes) for (const auto& value : assets) {
            const auto object = value.toObject(); if (object.value("name").toString().endsWith(suffix)) return object;
        }
        return {};
    }
    static bool trustedReleaseUrl(const QUrl& url) {
        return url.scheme() == "https" && url.host() == "github.com" && url.path().startsWith("/tadaka9/PQVPN/releases/download/");
    }
    void fetch(const QUrl& url, qint64 maximum, std::function<void(const QByteArray&, const QString&)> complete) {
        QNetworkRequest request(url); request.setHeader(QNetworkRequest::UserAgentHeader, "PQVPN-Privacy-Console/" + currentVersion_); request.setTransferTimeout(30000);
        request.setRawHeader("Accept", "application/vnd.github+json");
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* reply = network_.get(request); auto body = std::make_shared<QByteArray>(); auto oversized = std::make_shared<bool>(false);
        connect(reply, &QNetworkReply::readyRead, this, [reply, body, oversized, maximum] {
            body->append(reply->readAll()); if (body->size() > maximum) { *oversized = true; reply->abort(); }
        });
        connect(reply, &QNetworkReply::finished, this, [reply, body, oversized, complete = std::move(complete)] {
            body->append(reply->readAll());
            const QString error = *oversized ? "response exceeded size limit" : reply->error() == QNetworkReply::NoError ? QString{} : reply->errorString();
            reply->deleteLater(); complete(*body, error);
        });
    }
    void downloadAsset(const QByteArray& expected) {
        const QUrl url(selectedAsset_.value("browser_download_url").toString());
        if (!trustedReleaseUrl(url)) { busy_ = false; setDownloadable(true); message("Update blocked: unexpected asset URL"); return; }
        const QString directory = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation) + "/PQVPN-updates";
        if (!QDir().mkpath(directory)) { busy_ = false; setDownloadable(true); message("Update download directory cannot be created"); return; }
        const QString destination = directory + "/" + QFileInfo(selectedAsset_.value("name").toString()).fileName();
        auto output = std::make_shared<QSaveFile>(destination); auto hash = std::make_shared<QCryptographicHash>(QCryptographicHash::Sha256); auto bytes = std::make_shared<qint64>(0); auto failed = std::make_shared<bool>(false);
        if (!output->open(QIODevice::WriteOnly) || !output->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) { busy_ = false; setDownloadable(true); message("Update file cannot be created"); return; }
        QNetworkRequest request(url); request.setHeader(QNetworkRequest::UserAgentHeader, "PQVPN-Privacy-Console/" + currentVersion_); request.setTransferTimeout(300000); request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* reply = network_.get(request); message("Downloading " + selectedAsset_.value("name").toString() + "…");
        const auto drain = [=] { const auto chunk = reply->readAll(); *bytes += chunk.size(); if (*bytes > 1024LL * 1024 * 1024 || output->write(chunk) != chunk.size()) { *failed = true; reply->abort(); } else hash->addData(chunk); };
        connect(reply, &QNetworkReply::readyRead, this, drain);
        connect(reply, &QNetworkReply::finished, this, [=, this] {
            drain(); const bool valid = !*failed && reply->error() == QNetworkReply::NoError && *bytes > 0 && hash->result() == expected && output->commit();
            reply->deleteLater(); busy_ = false;
            if (!valid) { output->cancelWriting(); setDownloadable(true); message("Update download failed or SHA-256 did not match; file was discarded"); return; }
            message("Verified " + selectedTag_ + " downloaded to " + destination + ". Install it when ready."); QDesktopServices::openUrl(QUrl::fromLocalFile(directory));
        });
    }
};
} // namespace pqvpn::console
