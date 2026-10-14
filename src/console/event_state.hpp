#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <unordered_set>
#include <nlohmann/json.hpp>

namespace pqvpn::console {
class EventState {
public:
    bool authenticated() const { return !peers_.empty(); }
    bool tunnel_ready() const { return tunnel_ready_; }
    void reset() { peers_.clear(); tunnel_ready_=false; }
    void accept_line(std::string_view line) {
        constexpr std::string_view prefix="PQVPN_EVENT ";
        if (!line.starts_with(prefix) || line.size()>16384) return;
        const auto event=nlohmann::json::parse(line.substr(prefix.size()),nullptr,false);
        if (!event.is_object()) return;
        const auto name=event.find("event");
        if(name==event.end()||!name->is_string())return;
        const auto type=name->get<std::string>();
        if(type=="peer.connected"||type=="peer.disconnected"){
            const auto value=event.find("peer");if(value==event.end()||!value->is_string())return;
            auto peer=value->get<std::string>();
            if(peer.size()!=64||!std::all_of(peer.begin(),peer.end(),[](unsigned char c){return std::isxdigit(c)!=0;}))return;
            std::transform(peer.begin(),peer.end(),peer.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
            if(type=="peer.disconnected")peers_.erase(peer);
            else if(peers_.size()<1024)peers_.insert(peer);
        }else if(type=="tunnel.ready"){
            const auto closed=event.find("fail_closed"),ipv4=event.find("ipv4");
            tunnel_ready_=closed!=event.end()&&closed->is_boolean()&&closed->get<bool>()&&ipv4!=event.end()&&ipv4->is_string()&&*ipv4=="full";
        }else if(type=="tunnel.closed"||type=="tunnel.failed")tunnel_ready_=false;
    }
private:
    std::unordered_set<std::string> peers_;
    bool tunnel_ready_=false;
};
}
