#pragma once

#include <QCryptographicHash>
#include <QDate>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
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
#include <QSet>
#include <QStandardPaths>
#include <QStringList>
#include <QSysInfo>
#include <QUrl>
#include <QVector>
#include <QtEndian>
#include <functional>
#include <memory>
#include <utility>

namespace pqvpn::console {
class ReleaseUpdater final : public QObject {
public:
    std::function<void(const QString&)> report;
    std::function<void(bool)> downloadable;
    std::function<void(const QString&, const QString&)> prepared;

    explicit ReleaseUpdater(QString currentVersion, QObject* parent)
        : QObject(parent), currentVersion_(std::move(currentVersion)), network_(this) {}

    static bool selfTest() {
        const auto legacyAlpha = versionKey("alpha-0.6-10142026-cybergun");
        const auto alpha = versionKey("0.6-alpha-10142026-test");
        const auto beta = versionKey("0.6-beta-10142026-David0-OTA");
        const auto stable = versionKey("0.6.0");
        const auto newBeta = versionKey("0.0.9-10152026-David0-beta-OTA");
        const auto priorBeta = versionKey("0.0.8-10142026-David0-beta-OTA");
        const auto yearEnd = versionKey("0.6-beta-12312026-test");
        const auto nextYear = versionKey("0.6-beta-01012027-test");
        const auto leapDay = versionKey("0.6-beta-02292028-test");
        return !legacyAlpha.isEmpty() && !alpha.isEmpty() && !beta.isEmpty() && !stable.isEmpty() &&
               !yearEnd.isEmpty() && !nextYear.isEmpty() && !leapDay.isEmpty() &&
               compare(legacyAlpha, alpha) == 0 && compare(alpha, beta) < 0 &&
               compare(beta, stable) < 0 && !newBeta.isEmpty() && !priorBeta.isEmpty() &&
               compare(priorBeta, newBeta) < 0 && compare(newBeta, stable) < 0 &&
               compare(yearEnd, nextYear) < 0 &&
               compare(nextYear, leapDay) < 0 &&
               versionKey("0.6-beta-02302028-invalid").isEmpty() &&
               versionKey("0.6-beta-1231202-invalid").isEmpty();
    }

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

    // Public release labels use MMDDYYYY. Normalize to YYYYMMDD so
    // December of one year compares below January of the following year.
    static QVector<qulonglong> datedVersion(const QRegularExpressionMatch& match,
                                            bool includesPatch, qulonglong stage) {
        const QString date = match.captured(includesPatch ? 4 : 3);
        if (date.size() != 8) return {};
        const int month = date.left(2).toInt();
        const int day = date.mid(2, 2).toInt();
        const int year = date.mid(4, 4).toInt();
        if (!QDate::isValid(year, month, day)) return {};
        const qulonglong calendarKey = static_cast<qulonglong>(year) * 10000ULL +
                                       static_cast<qulonglong>(month) * 100ULL +
                                       static_cast<qulonglong>(day);
        return {match.captured(1).toULongLong(), match.captured(2).toULongLong(),
                includesPatch ? match.captured(3).toULongLong() : 0ULL,
                stage, calendarKey};
    }

    static QVector<qulonglong> versionKey(QString version) {
        QRegularExpressionMatch match;
        const QRegularExpression publicLabel("^alpha-(\\d+)\\.(\\d+)-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression publicAlpha("^(\\d+)\\.(\\d+)-alpha-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression publicBeta("^(\\d+)\\.(\\d+)-beta-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression semverAlpha("^(\\d+)\\.(\\d+)\\.(\\d+)-alpha-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression semverBeta("^(\\d+)\\.(\\d+)\\.(\\d+)-beta-(\\d+)-[0-9A-Za-z.-]+$");
        const QRegularExpression datedPublicBeta("^(\\d+)\\.(\\d+)\\.(\\d+)-(\\d{8})-[0-9A-Za-z.]+-beta(?:-[0-9A-Za-z.-]+)?$");
        const QRegularExpression semver("^(\\d+)\\.(\\d+)\\.(\\d+)$");
        if ((match = publicLabel.match(version)).hasMatch()) return datedVersion(match, false, 0);
        if ((match = publicAlpha.match(version)).hasMatch()) return datedVersion(match, false, 0);
        if ((match = publicBeta.match(version)).hasMatch()) return datedVersion(match, false, 1);
        if ((match = semverAlpha.match(version)).hasMatch()) return datedVersion(match, true, 0);
        if ((match = semverBeta.match(version)).hasMatch()) return datedVersion(match, true, 1);
        if ((match = datedPublicBeta.match(version)).hasMatch()) return datedVersion(match, true, 1);
        if ((match = semver.match(version)).hasMatch()) return {match.captured(1).toULongLong(), match.captured(2).toULongLong(), match.captured(3).toULongLong(), 2, 0};
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
        if (architecture != "x86_64" && architecture != "arm64") return {};
        QStringList suffixes;
#if defined(Q_OS_WIN)
        suffixes = {"-windows-" + architecture + ".pqvpnpkg"};
        if (architecture == "x86_64") architecture = "x64";
        suffixes.append("-windows-" + architecture + ".msi");
#elif defined(Q_OS_MACOS)
        suffixes = {"-macos-" + architecture + ".pqvpnpkg", "-macos-" + architecture + ".pkg", "-macos-" + architecture + ".dmg", "-macos-" + architecture + ".tar.gz"};
#elif defined(Q_OS_LINUX)
        suffixes = architecture == "x86_64" ? QStringList{"-deb-x86_64.pqvpnpkg", "-linux-x86_64.pqvpnpkg", "_amd64.deb", "-linux-x86_64.tar.gz"} : QStringList{"-deb-arm64.pqvpnpkg", "-linux-arm64.pqvpnpkg", "_arm64.deb", "-linux-arm64.tar.gz"};
#endif
        for (const auto& suffix : suffixes) for (const auto& value : assets) {
            const auto object = value.toObject(); if (object.value("name").toString().endsWith(suffix)) return object;
        }
        return {};
    }
    static bool trustedReleaseUrl(const QUrl& url) {
        return url.scheme() == "https" && url.host() == "github.com" && url.path().startsWith("/tadaka9/PQVPN/releases/download/");
    }
    static QStringList platformTargets() {
        QString architecture = QSysInfo::currentCpuArchitecture();
        if (architecture == "aarch64") architecture = "arm64";
        if (architecture == "amd64") architecture = "x86_64";
        if (architecture != "x86_64" && architecture != "arm64") return {};
#if defined(Q_OS_WIN)
        return {"windows-" + architecture};
#elif defined(Q_OS_MACOS)
        return {"macos-" + architecture};
#elif defined(Q_OS_LINUX)
        return {"deb-" + architecture, "linux-" + architecture};
#else
        return {};
#endif
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
            QString installable = destination;
            if (destination.endsWith(".pqvpnpkg")) {
                QString error; installable = extractCustomPackage(destination, error);
                if (installable.isEmpty()) { setDownloadable(true); message("Custom update package rejected: " + error); return; }
            }
            message("Verified " + selectedTag_ + " downloaded to " + installable + ". Install it when ready.");
            if (prepared) prepared(installable, selectedTag_);
            QDesktopServices::openUrl(QUrl::fromLocalFile(directory));
        });
    }
    QString extractCustomPackage(const QString& package, QString& error) const {
        QFile source(package); if (!source.open(QIODevice::ReadOnly)) { error = "cannot open container"; return {}; }
        if (source.read(10) != QByteArray("PQVPNPKG1\n", 10)) { error = "invalid container magic"; return {}; }
        const QByteArray lengthBytes = source.read(4); if (lengthBytes.size() != 4) { error = "truncated container header"; return {}; }
        const quint32 length = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(lengthBytes.constData()));
        if (length == 0 || length > 64 * 1024) { error = "invalid manifest length"; return {}; }
        const auto document = QJsonDocument::fromJson(source.read(length)); if (!document.isObject()) { error = "invalid manifest JSON"; return {}; }
        const auto manifest = document.object();
        const QSet<QString> expectedFields{"schema","product","version","target","payload_name","payload_size","payload_sha256","install_mode"}; const QStringList manifestKeys=manifest.keys(); const QSet<QString> actualFields(manifestKeys.begin(),manifestKeys.end());
        if (actualFields != expectedFields || manifest.value("schema").toInt() != 1 || manifest.value("product").toString() != "PQVPN") { error = "unsupported manifest"; return {}; }
        QString releaseVersion = selectedTag_; if (releaseVersion.startsWith('v')) releaseVersion.remove(0,1);
        const QString target = manifest.value("target").toString();
        if (manifest.value("version").toString() != releaseVersion || !platformTargets().contains(target) || !selectedAsset_.value("name").toString().endsWith("-" + target + ".pqvpnpkg")) { error = "version or target mismatch"; return {}; }
        const QString name = manifest.value("payload_name").toString();
        const QRegularExpression safeName("^[0-9A-Za-z][0-9A-Za-z._+~-]*$");
        if (!safeName.match(name).hasMatch() || QFileInfo(name).fileName() != name) { error = "unsafe payload name"; return {}; }
        const qint64 size = manifest.value("payload_size").toInteger();
        const QString hashText=manifest.value("payload_sha256").toString();const QByteArray expectedHash = QByteArray::fromHex(hashText.toLatin1());const QString mode=manifest.value("install_mode").toString();
        const bool modeMatches=(mode=="msi"&&name.endsWith(".msi",Qt::CaseInsensitive))||(mode=="deb"&&name.endsWith(".deb",Qt::CaseInsensitive))||(mode=="package"&&(name.endsWith(".pkg",Qt::CaseInsensitive)||name.endsWith(".dmg",Qt::CaseInsensitive)||name.endsWith(".AppImage",Qt::CaseInsensitive)||name.endsWith(".rpm",Qt::CaseInsensitive)||name.contains(".pkg.tar.")))||(mode=="archive"&&(name.endsWith(".tar.gz",Qt::CaseInsensitive)||name.endsWith(".zip",Qt::CaseInsensitive)));
        if (size <= 0 || size > 1024LL * 1024 * 1024 || !QRegularExpression("^[0-9a-f]{64}$").match(hashText).hasMatch() || expectedHash.size() != 32 || !modeMatches || source.size() - source.pos() != size) { error = "invalid payload metadata"; return {}; }
        const QString destination = QFileInfo(package).dir().absoluteFilePath(name); QSaveFile output(destination);
        if (!output.open(QIODevice::WriteOnly) || !output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) { error = "cannot create native package"; return {}; }
        QCryptographicHash hash(QCryptographicHash::Sha256); qint64 copied = 0;
        while (!source.atEnd()) { const QByteArray chunk = source.read(qMin<qint64>(1024 * 1024, size - copied)); if (chunk.isEmpty()) break; copied += chunk.size(); hash.addData(chunk); if (output.write(chunk) != chunk.size()) { error = "native package write failed"; output.cancelWriting(); return {}; } }
        if (copied != size || hash.result() != expectedHash || !output.commit()) { error = "native package checksum mismatch"; output.cancelWriting(); return {}; }
        return destination;
    }
};
} // namespace pqvpn::console
