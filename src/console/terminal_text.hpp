#pragma once
#include <string>
#include <string_view>

namespace pqvpn::console {
// Escape terminal control bytes from logs, paths and other external text.
inline std::string terminal_safe(std::string_view input) {
    std::string output;
    for(unsigned char c:input){if(c>=32&&c!=127)output+=static_cast<char>(c);else if(c=='\t'||c=='\r'||c=='\n')output+=' ';}
    return output;
}
// Preserve complete UTF-8 codepoints and our SGR decorations while clipping.
inline std::string clip_ansi(std::string_view input,int columns) {
    std::string output;int used=0;
    for(std::size_t i=0;i<input.size();){
        if(input[i]=='\033'&&i+1<input.size()&&input[i+1]=='['){
            const auto end=input.find('m',i+2);if(end==std::string_view::npos)break;
            output.append(input.substr(i,end-i+1));i=end+1;continue;
        }
        const auto first=static_cast<unsigned char>(input[i]);
        std::size_t length=first<0x80?1:(first&0xe0)==0xc0?2:(first&0xf0)==0xe0?3:(first&0xf8)==0xf0?4:1;
        if(i+length>input.size())break;
        unsigned int point=first& (length==1?0x7f:length==2?0x1f:length==3?0x0f:0x07);
        bool valid=true;
        for(std::size_t j=1;j<length;++j){const auto c=static_cast<unsigned char>(input[i+j]);if((c&0xc0)!=0x80){valid=false;break;}point=(point<<6)|(c&0x3f);}
        if(!valid){length=1;point='?';}
        const bool combining=point>=0x300&&point<=0x36f;
        const bool wide=(point>=0x1100&&point<=0x115f)||(point>=0x2e80&&point<=0xa4cf)||(point>=0xac00&&point<=0xd7a3)||(point>=0xf900&&point<=0xfaff)||(point>=0xff01&&point<=0xff60)||(point>=0x1f300&&point<=0x1faff);
        const int width=combining?0:wide?2:1;if(used+width>columns)break;
        output.append(input.substr(i,length));used+=width;i+=length;
    }
    return output;
}
}
