#include "rtnetlink.hpp"

#include "netlink.hpp"

#include <linux/rtnetlink.h>

namespace phosphor::network::netlink
{

template <typename Addr>
static std::optional<std::tuple<unsigned, InAddrAny>>
    parse(std::string_view msg)
{
    std::optional<unsigned> ifIdx;
    std::optional<InAddrAny> gw;
    while (!msg.empty())
    {
        auto [hdr, data] = extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case RTA_OIF:
                ifIdx.emplace(stdplus::raw::copyFrom<int>(data));
                break;
            case RTA_GATEWAY:
                gw.emplace(stdplus::raw::copyFrom<Addr>(data));
                break;
        }
    }
    if (ifIdx && gw)
    {
        return std::make_tuple(*ifIdx, *gw);
    }
    return std::nullopt;
}

std::optional<std::tuple<unsigned, InAddrAny>>
    gatewayFromRtm(std::string_view msg)
{
    const auto& rtm = extractRtData<rtmsg>(msg);
    if (rtm.rtm_table != RT_TABLE_MAIN || rtm.rtm_dst_len != 0)
    {
        return std::nullopt;
    }
    switch (rtm.rtm_family)
    {
        case AF_INET:
            return parse<in_addr>(msg);
        case AF_INET6:
            return parse<in6_addr>(msg);
    }
    return std::nullopt;
}

} // namespace phosphor::network::netlink
