#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace pqvpn::shield {

class LocalDnsFilter {
public:
    static constexpr std::size_t max_files = 8;
    static constexpr std::size_t max_rules = 500000;
    static constexpr std::size_t max_total_bytes = 16 * 1024 * 1024;

    void load(const std::vector<std::string>& files, const std::vector<std::string>& rules) {
        if (files.size() > max_files) throw std::invalid_argument("too many custom blocklist files");
        domains_.clear();
        std::size_t bytes = 0;
        for (const auto& file : files) {
            std::error_code error;
            const std::filesystem::path path(file);
            if (!path.is_absolute() || !std::filesystem::is_regular_file(path, error))
                throw std::invalid_argument("custom blocklist must be an absolute regular file: " + file);
            const auto file_size = std::filesystem::file_size(path, error);
            if (error || file_size > max_total_bytes || bytes + file_size > max_total_bytes)
                throw std::invalid_argument("custom blocklists exceed 16 MiB");
            std::ifstream input(file);
            if (!input) throw std::invalid_argument("cannot read custom blocklist: " + file);
            std::string line;
            while (std::getline(input, line)) {
                bytes += line.size() + 1;
                if (bytes > max_total_bytes) throw std::invalid_argument("custom blocklists exceed 16 MiB");
                add_line(line);
            }
        }
        for (const auto& rule : rules) add_line(rule);
        if (domains_.size() > max_rules) throw std::invalid_argument("custom blocklists exceed 500000 domains");
    }

    [[nodiscard]] bool blocks(std::string domain) const {
        domain = normalize(std::move(domain));
        if (domain.empty()) return false;
        for (;;) {
            if (domains_.contains(domain)) return true;
            const auto dot = domain.find('.');
            if (dot == std::string::npos) return false;
            domain.erase(0, dot + 1);
        }
    }

    // Returns a local NXDOMAIN response when an IPv4/UDP DNS question is
    // blocked. Empty means the packet must continue through the tunnel.
    [[nodiscard]] std::vector<std::uint8_t> filter_packet(const std::vector<std::uint8_t>& packet) const {
        if (packet.size() < 40 || (packet[0] >> 4) != 4) return {};
        const std::size_t ihl = (packet[0] & 0x0f) * 4u;
        if (ihl < 20 || packet.size() < ihl + 20 || packet[9] != 17) return {};
        const std::size_t udp = ihl;
        if (read16(packet, udp + 2) != 53) return {};
        const std::size_t dns = udp + 8;
        if ((packet[dns + 2] & 0x80) || read16(packet, dns + 4) != 1) return {};
        std::size_t cursor = dns + 12;
        std::string name;
        while (cursor < packet.size()) {
            const auto length = packet[cursor++];
            if (length == 0) break;
            if (length > 63 || cursor + length > packet.size()) return {};
            if (!name.empty()) name.push_back('.');
            name.append(reinterpret_cast<const char*>(packet.data() + cursor), length);
            cursor += length;
        }
        if (cursor + 4 > packet.size() || !blocks(name)) return {};
        auto reply = packet;
        reply.resize(cursor + 4); // retain only the question; discard EDNS/options
        write16(reply, 2, static_cast<std::uint16_t>(reply.size()));
        write16(reply, udp + 4, static_cast<std::uint16_t>(reply.size() - udp));
        for (std::size_t i = 0; i < 4; ++i) std::swap(reply[12 + i], reply[16 + i]);
        std::swap(reply[udp], reply[udp + 2]);
        std::swap(reply[udp + 1], reply[udp + 3]);
        reply[dns + 2] = static_cast<std::uint8_t>((reply[dns + 2] & 0x79) | 0x80);
        reply[dns + 3] = static_cast<std::uint8_t>((reply[dns + 3] & 0xf0) | 0x03);
        std::fill(reply.begin() + static_cast<std::ptrdiff_t>(dns + 6),
                  reply.begin() + static_cast<std::ptrdiff_t>(dns + 12), 0);
        reply[udp + 6] = reply[udp + 7] = 0; // legal for IPv4 UDP
        reply[10] = reply[11] = 0;
        const auto sum = checksum(reply.data(), ihl);
        reply[10] = static_cast<std::uint8_t>(sum >> 8);
        reply[11] = static_cast<std::uint8_t>(sum);
        return reply;
    }

    [[nodiscard]] std::size_t size() const noexcept { return domains_.size(); }

private:
    std::unordered_set<std::string> domains_;

    static std::uint16_t read16(const std::vector<std::uint8_t>& data, std::size_t offset) {
        return static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
    }
    static void write16(std::vector<std::uint8_t>& data, std::size_t offset, std::uint16_t value) {
        data[offset] = static_cast<std::uint8_t>(value >> 8);
        data[offset + 1] = static_cast<std::uint8_t>(value);
    }
    static std::uint16_t checksum(const std::uint8_t* data, std::size_t size) {
        std::uint32_t sum = 0;
        for (std::size_t i = 0; i + 1 < size; i += 2) sum += (data[i] << 8) | data[i + 1];
        if (size & 1u) sum += data[size - 1] << 8;
        while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
        return static_cast<std::uint16_t>(~sum);
    }
    static std::string normalize(std::string value) {
        while (!value.empty() && (value.back() == '.' || std::isspace(static_cast<unsigned char>(value.back())))) value.pop_back();
        std::size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) ++start;
        value.erase(0, start);
        if (value.size() > 253) return {};
        for (auto& c : value) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.')) return {};
        }
        return value;
    }
    void add_line(std::string line) {
        if (const auto comment = line.find('#'); comment != std::string::npos) line.resize(comment);
        const auto first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos) return;
        line.erase(0, first);
        if (line.rfind("||", 0) == 0) {
            line.erase(0, 2);
            if (const auto end = line.find('^'); end != std::string::npos) line.resize(end);
        } else if (const auto split = line.find_first_of(" \t"); split != std::string::npos) {
            const auto domain_start = line.find_first_not_of(" \t", split);
            if (domain_start == std::string::npos) return;
            line.erase(0, domain_start);
            if (const auto end = line.find_first_of(" \t"); end != std::string::npos) line.resize(end);
        }
        if (line.rfind("*.", 0) == 0) line.erase(0, 2);
        auto domain = normalize(std::move(line));
        if (!domain.empty() && domain.find('.') != std::string::npos) domains_.insert(std::move(domain));
        if (domains_.size() > max_rules) throw std::invalid_argument("custom blocklists exceed 500000 domains");
    }
};

} // namespace pqvpn::shield
