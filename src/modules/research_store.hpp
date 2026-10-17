#pragma once
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include "research_ledger.hpp"

namespace pqvpn::research {
inline bool save_checkpoint_atomic(const Ledger& ledger,const std::filesystem::path& path){
    std::error_code ec;std::filesystem::create_directories(path.parent_path(),ec);if(ec)return false;
    const auto temporary=path.string()+".tmp";{std::ofstream out(temporary,std::ios::binary|std::ios::trunc);if(!out)return false;out<<ledger.checkpoint().dump()<<'\n';out.flush();if(!out)return false;}
    std::filesystem::permissions(temporary,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write,std::filesystem::perm_options::replace,ec);if(ec){std::filesystem::remove(temporary);return false;}
    std::filesystem::rename(temporary,path,ec);if(ec){std::filesystem::remove(temporary);return false;}return true;
}
inline std::optional<Ledger> recover_checkpoint(const SubnetPolicy& policy,const std::filesystem::path& path){
    std::ifstream input(path,std::ios::binary);if(!input)return std::nullopt;std::string data((std::istreambuf_iterator<char>(input)),{});if(data.size()>16*1024*1024)return std::nullopt;
    try{return Ledger::recover(policy,nlohmann::ordered_json::parse(data));}catch(...){return std::nullopt;}
}
inline void prune_evidence(const std::filesystem::path& directory,std::size_t keep){
    std::vector<std::filesystem::directory_entry> files;std::error_code ec;if(!std::filesystem::exists(directory))return;
    for(const auto& item:std::filesystem::directory_iterator(directory,ec))if(item.is_regular_file()&&item.path().extension()==".json")files.push_back(item);
    std::sort(files.begin(),files.end(),[](const auto&a,const auto&b){return a.last_write_time()<b.last_write_time();});
    while(files.size()>keep){std::filesystem::remove(files.front().path(),ec);files.erase(files.begin());}
}
}
