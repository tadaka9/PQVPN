#pragma once
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

namespace pqvpn::console {
inline std::filesystem::path user_profile_directory() {
    auto value=[](const char* name){const char* raw=std::getenv(name);return raw?std::filesystem::path(raw):std::filesystem::path{};};
#ifdef _WIN32
    auto root=value("LOCALAPPDATA");if(root.empty())root=value("APPDATA");
#elif defined(__APPLE__)
    auto root=value("HOME");if(!root.empty())root/="Library/Application Support";
#else
    auto root=value("XDG_CONFIG_HOME");if(!root.is_absolute()){root=value("HOME");if(!root.empty())root/=".config";}
#endif
    return root.empty()?root:root/"PQVPN";
}
inline std::filesystem::path materialize_profile(const std::filesystem::path& example,const std::filesystem::path& directory) {
    if(directory.empty())return example;
    const auto destination=directory/"config.json";
    if(std::filesystem::exists(destination))return destination;
    std::ifstream source(example);if(!source)return example;
    auto root=nlohmann::json::parse(source,nullptr,false);if(!root.is_object())return example;
    if(root.contains("security")&&!root["security"].is_object())return example;
    root["security"]["known_peers_file"]=(directory/"known_peers.json").generic_string();
    if(std::filesystem::create_directories(directory))std::filesystem::permissions(directory,std::filesystem::perms::owner_all);
    const auto temporary=directory/"config.json.new";
    // Never overwrite a user's existing file, including another launch's
    // partially prepared profile. Exclusive hard-link publication exposes a complete JSON file.
    if(std::filesystem::exists(temporary))return example;
    {std::ofstream output(temporary,std::ios::out|std::ios::noreplace);if(!output)return example;output<<root.dump(2)<<'\n';if(!output){output.close();std::filesystem::remove(temporary);return example;}}
    std::filesystem::permissions(temporary,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write);
    if(std::filesystem::exists(destination)){std::filesystem::remove(temporary);return destination;}
    std::error_code error;std::filesystem::create_hard_link(temporary,destination,error);std::filesystem::remove(temporary);
    if(error&&!std::filesystem::exists(destination))return example;
    return destination;
}
inline std::filesystem::path default_profile(const std::filesystem::path& binary_directory) {
    if(std::filesystem::is_regular_file("config.json"))return std::filesystem::absolute("config.json");
    const auto portable=binary_directory/"config.json";if(std::filesystem::is_regular_file(portable))return portable;
    for(const auto& example:{binary_directory/"../share/pqvpn/examples/config.json",binary_directory/"../Resources/pqvpn/examples/config.json"}){
        if(!std::filesystem::is_regular_file(example))continue;
        try{return materialize_profile(example,user_profile_directory());}catch(const std::filesystem::filesystem_error&){return example;}
    }
    return std::filesystem::absolute("config.json");
}
}
