#pragma once
#include <filesystem>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace pqvpn::identity {
// Create with private permissions before writing, refusing existing temporary files.
inline void write_private_file(const std::string& path, const std::string& contents) {
    const auto temporary = path + ".tmp";
#ifdef _WIN32
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;OW)", SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("cannot create private identity security descriptor");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    HANDLE file = CreateFileW(std::filesystem::path(temporary).c_str(), GENERIC_WRITE,
                             0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create private identity file");
    DWORD written = 0;
    const bool complete = contents.size() <= MAXDWORD &&
        WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) &&
        written == contents.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!complete || !MoveFileExW(std::filesystem::path(temporary).c_str(),
            std::filesystem::path(path).c_str(), MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(std::filesystem::path(temporary).c_str());
        throw std::runtime_error("cannot persist private identity file");
    }
#else
    const int file = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file < 0) throw std::runtime_error("cannot create private identity file");
    size_t offset = 0;
    bool complete = true;
    while (offset < contents.size()) {
        const auto written = ::write(file, contents.data() + offset, contents.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { complete = false; break; }
        offset += static_cast<size_t>(written);
    }
    if (::fsync(file) != 0) complete = false;
    if (::close(file) != 0) complete = false;
    if (!complete || ::link(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        throw std::runtime_error("cannot persist private identity file");
    }
    ::unlink(temporary.c_str());
#endif
}
} // namespace pqvpn::identity
