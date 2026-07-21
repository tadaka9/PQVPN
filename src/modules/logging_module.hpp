#ifndef PQVPN_LOGGING_MODULE_HPP
#define PQVPN_LOGGING_MODULE_HPP

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>

namespace pqvpn::logging {

enum class LogLevel { trace, debug, info, warn, error, critical, off };

inline std::string_view to_string(LogLevel level) {
    switch (level) {
        case LogLevel::trace: return "trace";
        case LogLevel::debug: return "debug";
        case LogLevel::info: return "info";
        case LogLevel::warn: return "warn";
        case LogLevel::error: return "error";
        case LogLevel::critical: return "critical";
        default: return "off";
    }
}

inline spdlog::level::level_enum to_spdlog(LogLevel level) {
    switch (level) {
        case LogLevel::trace: return spdlog::level::trace;
        case LogLevel::debug: return spdlog::level::debug;
        case LogLevel::info: return spdlog::level::info;
        case LogLevel::warn: return spdlog::level::warn;
        case LogLevel::error: return spdlog::level::err;
        case LogLevel::critical: return spdlog::level::critical;
        default: return spdlog::level::off;
    }
}

class ColoredFormatter {
public:
    static std::string format(std::string_view level, std::string message) {
        if (redaction_enabled()) message = LoggerRedaction(message);
        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        std::tm local{};
#ifdef _WIN32
        localtime_s(&local, &time);
#else
        localtime_r(&time, &local);
#endif
        const std::string color = level == "WARNING" ? "\033[33m" :
            level == "ERROR" || level == "CRITICAL" ? "\033[31m" :
            level == "DEBUG" ? "\033[36m" : "\033[32m";
        std::ostringstream out;
        out << color << std::put_time(&local, "%H:%M:%S") << '.'
            << std::setfill('0') << std::setw(3) << ms.count() << ' '
            << std::left << std::setw(8) << std::setfill(' ') << level << ' '
            << message << "\033[0m";
        return out.str();
    }

private:
    static bool redaction_enabled() {
        const char* value = std::getenv("PQVPN_REDACT");
        return value && std::string_view(value) != "0";
    }
    static std::string LoggerRedaction(const std::string& value) {
        static const std::regex ipv4(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
        return std::regex_replace(value, ipv4, "***.***.***.***");
    }
};

class Logger {
public:
    static std::shared_ptr<spdlog::logger> setup_logger(
        const std::string& name, LogLevel level = LogLevel::info,
        const std::string& file = "pqvpn.log") {
        spdlog::drop(name);
        std::vector<spdlog::sink_ptr> sinks;
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        try {
            sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(file, true));
        } catch (const spdlog::spdlog_ex&) {}
        auto logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
        logger->set_level(to_spdlog(level));
        spdlog::register_logger(logger);
        return logger;
    }

    static std::string redact_ipv4(const std::string& value) {
        const char* enabled = std::getenv("PQVPN_REDACT");
        if (!enabled || std::string_view(enabled) == "0") return value;
        static const std::regex ipv4(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
        return std::regex_replace(value, ipv4, "***.***.***.***");
    }

    template <typename... Args> static void trace(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::trace(f, std::forward<Args>(a)...); }
    static void trace(const std::string& value) { spdlog::trace("{}", value); }
    template <typename... Args> static void debug(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::debug(f, std::forward<Args>(a)...); }
    static void debug(const std::string& value) { spdlog::debug("{}", value); }
    template <typename... Args> static void info(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::info(f, std::forward<Args>(a)...); }
    static void info(const std::string& value) { spdlog::info("{}", value); }
    template <typename... Args> static void warn(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::warn(f, std::forward<Args>(a)...); }
    static void warn(const std::string& value) { spdlog::warn("{}", value); }
    template <typename... Args> static void warning(spdlog::format_string_t<Args...> f, Args&&... a) { warn(f, std::forward<Args>(a)...); }
    static void warning(const std::string& value) { warn(value); }
    template <typename... Args> static void error(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::error(f, std::forward<Args>(a)...); }
    static void error(const std::string& value) { spdlog::error("{}", value); }
    template <typename... Args> static void critical(spdlog::format_string_t<Args...> f, Args&&... a) { spdlog::critical(f, std::forward<Args>(a)...); }
    static void critical(const std::string& value) { spdlog::critical("{}", value); }
    template <typename... Args> static void exception(spdlog::format_string_t<Args...> f, Args&&... a) { error(f, std::forward<Args>(a)...); }
    static void exception(const std::string& value) { error(value); }
};

}  // namespace pqvpn::logging

namespace logging = pqvpn::logging;

#endif
