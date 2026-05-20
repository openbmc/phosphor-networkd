#include "rtnetlink.hpp"

#include "netlink.hpp"
#include "util.hpp"

#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

#include <cstring>

namespace phosphor::network::netlink
{

using std::literals::string_view_literals::operator""sv;

static void parseVlanInfo(InterfaceInfo& info, std::string_view msg)
{
    if (msg.data() == nullptr)
    {
        throw std::runtime_error("Missing VLAN data");
    }
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case IFLA_VLAN_ID:
                info.vlan_id.emplace(stdplus::raw::copyFrom<uint16_t>(data));
                break;
        }
    }
}

#if ENABLE_BOND_SUPPORT
static void parseBondInfo(InterfaceInfo& info, std::string_view msg)
{
    bool activeSlaveFlag = true;

    if (msg.data() == nullptr)
    {
        throw std::runtime_error("Missing Bond data");
    }
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case IFLA_BOND_MIIMON:
                if (!info.bondInfo)
                {
                    info.bondInfo.emplace();
                }
                info.bondInfo->miiMonitor = static_cast<uint8_t>(
                    stdplus::raw::copyFrom<uint32_t>(data));
                activeSlaveFlag = false;
                break;
        }
    }

    // Read active slave from sysfs
    if (activeSlaveFlag)
    {
        char buf[16] = {0};
        int fd = open("/sys/class/net/bond0/bonding/active_slave", O_RDONLY);
        if (fd < 0)
        {
            throw std::runtime_error("Failed to open active_slave file");
        }

        ssize_t ret = read(fd, (char*)&buf, sizeof(buf));
        close(fd);

        if (ret <= 0)
        {
            if (!info.bondInfo)
            {
                info.bondInfo.emplace();
            }
            info.bondInfo->activeSlave = "";
        }
        else
        {
            if (buf[std::strlen(buf) - 1] == '\n')
                buf[std::strlen(buf) - 1] =
                    '\0'; // Remove the line-enter character

            if (!info.bondInfo)
            {
                info.bondInfo.emplace();
            }
            info.bondInfo->activeSlave = buf;
            info.bondInfo->mode = 1; // active-backup
            if (info.bondInfo->miiMonitor == 0)
            {
                info.bondInfo->miiMonitor = 100; // default
            }
        }
    }
}
#endif

static void parseLinkInfo(InterfaceInfo& info, std::string_view msg)
{
    std::string_view submsg;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case IFLA_INFO_KIND:
                data.remove_suffix(1);
                info.kind.emplace(data);
                break;
            case IFLA_INFO_DATA:
                submsg = data;
                break;
        }
    }
    if (info.kind == "vlan"sv)
    {
        parseVlanInfo(info, submsg);
    }
#if ENABLE_BOND_SUPPORT
    if (info.kind == "bond"sv)
    {
        parseBondInfo(info, submsg);
    }
#endif
}

InterfaceInfo intfFromRtm(std::string_view msg)
{
    const auto& ifinfo = netlink::extractRtData<ifinfomsg>(msg);
    InterfaceInfo ret;
    ret.type = ifinfo.ifi_type;
    ret.idx = ifinfo.ifi_index;
    ret.flags = ifinfo.ifi_flags;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case IFLA_IFNAME:
                ret.name.emplace(data.begin(), data.end() - 1);
                break;
            case IFLA_ADDRESS:
                if (data.size() == sizeof(stdplus::EtherAddr))
                {
                    ret.mac.emplace(
                        stdplus::raw::copyFrom<stdplus::EtherAddr>(data));
                }
                break;
            case IFLA_MTU:
                ret.mtu.emplace(stdplus::raw::copyFrom<unsigned>(data));
                break;
            case IFLA_LINK:
                ret.parent_idx.emplace(stdplus::raw::copyFrom<unsigned>(data));
                break;
            case IFLA_LINKINFO:
                parseLinkInfo(ret, data);
                break;
        }
    }
    return ret;
}

template <typename Addr>
static std::optional<std::tuple<unsigned, stdplus::InAnyAddr>> parse(
    std::string_view msg)
{
    std::optional<unsigned> ifIdx;
    std::optional<stdplus::InAnyAddr> gw;
    while (!msg.empty())
    {
        auto [hdr, data] = extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case RTA_OIF:
                ifIdx.emplace(stdplus::raw::copyFromStrict<int>(data));
                break;
            case RTA_GATEWAY:
                gw.emplace(stdplus::raw::copyFromStrict<Addr>(data));
                break;
        }
    }
    if (ifIdx && gw)
    {
        return std::make_tuple(*ifIdx, *gw);
    }
    return std::nullopt;
}

std::optional<std::tuple<unsigned, stdplus::InAnyAddr>> gatewayFromRtm(
    std::string_view msg)
{
    const auto& rtm = extractRtData<rtmsg>(msg);
    if (rtm.rtm_table != RT_TABLE_MAIN || rtm.rtm_dst_len != 0)
    {
        return std::nullopt;
    }
    switch (rtm.rtm_family)
    {
        case AF_INET:
            return parse<stdplus::In4Addr>(msg);
        case AF_INET6:
            return parse<stdplus::In6Addr>(msg);
    }
    return std::nullopt;
}

AddressInfo addrFromRtm(std::string_view msg)
{
    const auto& ifa = extractRtData<ifaddrmsg>(msg);

    uint32_t flags = ifa.ifa_flags;
    std::optional<stdplus::InAnyAddr> addr;
    while (!msg.empty())
    {
        auto [hdr, data] = extractRtAttr(msg);
        if (hdr.rta_type == IFA_ADDRESS)
        {
            addr.emplace(addrFromBuf(ifa.ifa_family, data));
        }
        else if (hdr.rta_type == IFA_FLAGS)
        {
            flags = stdplus::raw::copyFromStrict<uint32_t>(data);
        }
    }
    if (!addr)
    {
        throw std::runtime_error("Missing address");
    }
    return AddressInfo{.ifidx = ifa.ifa_index,
                       .ifaddr = stdplus::SubnetAny{*addr, ifa.ifa_prefixlen},
                       .scope = ifa.ifa_scope,
                       .flags = flags};
}

NeighborInfo neighFromRtm(std::string_view msg)
{
    const auto& ndm = netlink::extractRtData<ndmsg>(msg);

    NeighborInfo ret;
    ret.ifidx = ndm.ndm_ifindex;
    ret.state = ndm.ndm_state;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        if (hdr.rta_type == NDA_LLADDR)
        {
            ret.mac = stdplus::raw::copyFrom<stdplus::EtherAddr>(data);
        }
        else if (hdr.rta_type == NDA_DST)
        {
            ret.addr = addrFromBuf(ndm.ndm_family, data);
        }
    }
    return ret;
}

} // namespace phosphor::network::netlink
