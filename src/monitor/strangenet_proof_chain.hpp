#pragma once

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QVector>

namespace pqvpn::console {

// An opt-in, memory-only commitment chain for StrangeNet events. It provides
// a compact root that can be submitted to an external blockchain timestamping
// or notarization service without disclosing chat contents or peer metadata.
// It does not send a transaction and it never writes messages to disk.
class StrangeNetProofChain final {
public:
    static constexpr qsizetype kMaximumBlocks = 4096;

    StrangeNetProofChain() { reset(); }

    void reset() {
        salt_.resize(32);
        for (qsizetype offset = 0; offset < salt_.size(); offset += 4) {
            const auto value = QRandomGenerator::system()->generate();
            const auto count = qMin<qsizetype>(4, salt_.size() - offset);
            for (qsizetype byte = 0; byte < count; ++byte)
                salt_[offset + byte] = static_cast<char>(value >> (byte * 8));
        }
        blocks_.clear();
        root_ = QByteArray(32, '\0');
    }

    bool append(const QByteArray& canonicalEvent) {
        if (canonicalEvent.isEmpty() || canonicalEvent.size() > 16 * 1024 ||
            blocks_.size() >= kMaximumBlocks) return false;
        const QByteArray commitment = digest(QByteArrayLiteral("PQVPN StrangeNet private commitment v1\0") +
                                             salt_ + canonicalEvent);
        const quint64 index = static_cast<quint64>(blocks_.size() + 1);
        QByteArray encodedIndex(8, '\0');
        for (int byte = 0; byte < 8; ++byte)
            encodedIndex[byte] = static_cast<char>(index >> (56 - byte * 8));
        const QByteArray blockHash = digest(QByteArrayLiteral("PQVPN StrangeNet proof block v1\0") +
                                            encodedIndex + root_ + commitment);
        blocks_.push_back({index, root_, commitment, blockHash});
        root_ = blockHash;
        return true;
    }

    qsizetype size() const { return blocks_.size(); }
    QByteArray rootHex() const { return blocks_.isEmpty() ? QByteArray{} : root_.toHex(); }

    bool valid() const {
        QByteArray previous(32, '\0');
        for (qsizetype position = 0; position < blocks_.size(); ++position) {
            const auto& block = blocks_[position];
            if (block.index != static_cast<quint64>(position + 1) || block.previous != previous ||
                block.commitment.size() != 32 || block.hash.size() != 32) return false;
            QByteArray encodedIndex(8, '\0');
            for (int byte = 0; byte < 8; ++byte)
                encodedIndex[byte] = static_cast<char>(block.index >> (56 - byte * 8));
            if (digest(QByteArrayLiteral("PQVPN StrangeNet proof block v1\0") + encodedIndex +
                       block.previous + block.commitment) != block.hash) return false;
            previous = block.hash;
        }
        return previous == root_;
    }

    QJsonObject anchor() const {
        if (blocks_.isEmpty() || !valid()) return {};
        return {{"schema", "pqvpn-strangenet-anchor-v1"},
                {"algorithm", "SHA-256 salted commitment chain"},
                {"blocks", static_cast<qint64>(blocks_.size())},
                {"root", QString::fromLatin1(root_.toHex())},
                {"contents_included", false}};
    }

    static bool selfTest() {
        StrangeNetProofChain chain;
        return chain.append("received\0room\0peer\0hello") &&
               chain.append("sent\0room\0peer\0reply") && chain.size() == 2 &&
               chain.rootHex().size() == 64 && chain.valid() && !chain.anchor().isEmpty();
    }

private:
    struct Block {
        quint64 index;
        QByteArray previous;
        QByteArray commitment;
        QByteArray hash;
    };

    static QByteArray digest(const QByteArray& value) {
        return QCryptographicHash::hash(value, QCryptographicHash::Sha256);
    }

    QByteArray salt_;
    QByteArray root_;
    QVector<Block> blocks_;
};

} // namespace pqvpn::console
