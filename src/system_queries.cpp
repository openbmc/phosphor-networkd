#include "system_queries.hpp"

#include "netlink.hpp"

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/hash/tuple.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

namespace phosphor::network::system
{

using std::literals::string_view_literals::operator""sv;

static stdplus::Fd& getIFSock()
{
    using namespace stdplus::fd;
    static auto fd =
        socket(SocketDomain::INet, SocketType::Datagram, SocketProto::IP);
    return fd;
}

static ifreq makeIFReq(std::string_view ifname)
{
    ifreq ifr = {};
    const auto copied = std::min<std::size_t>(ifname.size(), IFNAMSIZ - 1);
    std::copy_n(ifname.begin(), copied, ifr.ifr_name);
    return ifr;
}

static ifreq executeIFReq(std::string_view ifname, unsigned long cmd,
                          void* data = nullptr)
{
    ifreq ifr = makeIFReq(ifname);
    ifr.ifr_data = reinterpret_cast<char*>(data);
    getIFSock().ioctl(cmd, &ifr);
    return ifr;
}

inline auto optionalIFReq(stdplus::zstring_view ifname, unsigned long long cmd,
                          std::string_view cmdname, auto&& complete,
                          void* data = nullptr)
{
    ifreq ifr;
    std::optional<decltype(complete(ifr))> ret;
    auto ukey = std::make_tuple(std::string(ifname), cmd);
    static std::unordered_set<std::tuple<std::string, unsigned long long>>
        unsupported;
    try
    {
        ifr = executeIFReq(ifname, cmd, data);
    }
    catch (const std::system_error& e)
    {
        if (e.code() == std::errc::operation_not_supported)
        {
            if (unsupported.find(ukey) == unsupported.end())
            {
                unsupported.emplace(std::move(ukey));
                lg2::info("{NET_IFREQ} not supported on {NET_INTF}",
                          "NET_IFREQ", cmdname, "NET_INTF", ifname);
            }
            return ret;
        }
        throw;
    }
    unsupported.erase(ukey);
    ret.emplace(complete(ifr));
    return ret;
}

EthInfo getEthInfo(stdplus::zstring_view ifname)
{
    ethtool_cmd edata = {};
    edata.cmd = ETHTOOL_GSET;
    return optionalIFReq(
               ifname, SIOCETHTOOL, "ETHTOOL"sv,
               [&](const ifreq&) {
                   return EthInfo{.autoneg = edata.autoneg != 0,
                                  .speed = edata.speed,
                                  .fullDuplex = (edata.duplex == DUPLEX_FULL)};
               },
               &edata)
        .value_or(EthInfo{});
}

/**
 * @brief Check if a network interface exists
 * @param ifname Interface name to check
 * @return true if interface exists, false otherwise
 */
static bool interfaceExists(std::string_view ifname)
{
    auto ifr = makeIFReq(ifname);
    try
    {
        getIFSock().ioctl(SIOCGIFFLAGS, &ifr);
        return true;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Interface does not exist: {INTERFACE}, error: {ERROR}",
                   "INTERFACE", ifname, "ERROR", e.what());
        return false;
    }
}

/** @brief Validate IPv4 address string via stdplus.
 *  @throws std::invalid_argument on bad address */
static stdplus::In4Addr validateIPv4Address(std::string_view ipAddress)
{
    try
    {
        return stdplus::fromStr<stdplus::In4Addr>(ipAddress);
    }
    catch (const std::exception&)
    {
        throw std::invalid_argument(
            std::string("Invalid IPv4 address: ") + std::string(ipAddress));
    }
}

/** @brief Validate IPv6 address string via stdplus.
 *  @throws std::invalid_argument on bad address */
static stdplus::In6Addr validateIPv6Address(std::string_view ipAddress)
{
    try
    {
        return stdplus::fromStr<stdplus::In6Addr>(ipAddress);
    }
    catch (const std::exception&)
    {
        throw std::invalid_argument(
            std::string("Invalid IPv6 address: ") + std::string(ipAddress));
    }
}

/** @brief Validate IPv6 prefix length (range 1-128).
 *  @throws std::invalid_argument if prefix is 0 or > 128 */
static void validateIPv6Prefix(uint8_t prefixLength)
{
    if (prefixLength == 0 || prefixLength > 128)
    {
        throw std::invalid_argument(
            std::string("Invalid IPv6 prefix length: ") +
            std::to_string(prefixLength) + " -- must be 1-128");
    }
}

/** @brief Validate IPv4 prefix length (range 1-31).
 *  @throws std::invalid_argument if prefix is 0 or >= 32 */
static void validateIPv4Prefix(uint8_t prefixLength)
{
    if (prefixLength == 0 || prefixLength >= 32)
    {
        throw std::invalid_argument(
            std::string("Invalid IPv4 prefix length: ") +
            std::to_string(prefixLength) +
            " -- must be 1-31 for interface address assignment");
    }
}

/** @brief Validate interface name length.
 *  @throws std::system_error if empty or exceeds IFNAMSIZ-1 */
static void validateInterfaceName(std::string_view ifname)
{
    if (ifname.empty() || ifname.length() > IFNAMSIZ - 1)
    {
        throw std::system_error(
            std::make_error_code(std::errc::invalid_argument),
            std::format("Invalid interface name length: {}", ifname));
    }
}

/**
 * @brief Send a single RTM_NEWADDR or RTM_DELADDR message and wait for ACK.
 *        Uses netlink::detail::performRequest (sendmsg/recvmsg)
 *
 * Shared by setIPV4Address, setIPV6Address, deleteIPv4, deleteIPv6
 *
 * @param type      RTM_NEWADDR or RTM_DELADDR
 * @param nlFlags   Extra NLM_F_* flags (e.g. NLM_F_CREATE|NLM_F_REPLACE)
 * @param family    AF_INET or AF_INET6
 * @param ifidx     Interface index
 * @param prefixLen Prefix length
 * @param rtaType   IFA_LOCAL (IPv4) or IFA_ADDRESS (IPv6)
 * @param addrPtr   Pointer to in_addr or in6_addr
 * @param addrLen   sizeof(in_addr) or sizeof(in6_addr)
 * @param scope     RT_SCOPE_UNIVERSE for set; passed through for delete
 * @return true on success, false on failure (error already logged)
 */
static bool netlinkAddrRequest(
    uint16_t type, uint16_t nlFlags, uint8_t family, unsigned ifidx,
    uint8_t prefixLen, uint16_t rtaType, const void* addrPtr, size_t addrLen,
    uint8_t scope = RT_SCOPE_UNIVERSE)
{
    struct
    {
        nlmsghdr nlh;
        ifaddrmsg ifa;
        char buf[256];
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | nlFlags;
    req.ifa.ifa_family = family;
    req.ifa.ifa_index = ifidx;
    req.ifa.ifa_prefixlen = prefixLen;
    req.ifa.ifa_scope = scope;

    rtattr* rta = reinterpret_cast<rtattr*>(req.buf);
    rta->rta_type = rtaType;
    rta->rta_len = RTA_LENGTH(addrLen);
    memcpy(RTA_DATA(rta), addrPtr, addrLen);
    req.nlh.nlmsg_len += rta->rta_len;

    // For IPv4 RTM_NEWADDR also set IFA_ADDRESS (same value as IFA_LOCAL)
    if (type == RTM_NEWADDR && family == AF_INET)
    {
        rta = reinterpret_cast<rtattr*>(req.buf + RTA_ALIGN(rta->rta_len));
        rta->rta_type = IFA_ADDRESS;
        rta->rta_len = RTA_LENGTH(addrLen);
        memcpy(RTA_DATA(rta), addrPtr, addrLen);
        req.nlh.nlmsg_len += rta->rta_len;
    }

    try
    {
        netlink::detail::performRequest(
            NETLINK_ROUTE, &req, req.nlh.nlmsg_len,
            [&](const nlmsghdr& hdr, std::string_view data) {
                if (hdr.nlmsg_type != NLMSG_ERROR)
                    return;
                const auto& err =
                    stdplus::raw::refFrom<nlmsgerr, stdplus::raw::Aligned>(
                        data);
                // EADDRNOTAVAIL on delete = address already gone, OK
                if (err.error != 0 &&
                    !(type == RTM_DELADDR && err.error == -EADDRNOTAVAIL))
                {
                    throw std::system_error(-err.error, std::generic_category(),
                                            "netlinkAddrRequest");
                }
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("Netlink addr request failed: {ERROR}", "ERROR", e.what());
        return false;
    }
    return true;
}

/**
 * @brief Validate interface name, confirm it exists, and return its index.
 * @throws std::system_error      if name is invalid or interface not found
 */
static unsigned resolveIfIndex(std::string_view ifname)
{
    validateInterfaceName(ifname);
    if (!interfaceExists(ifname))
    {
        throw std::system_error(
            std::make_error_code(std::errc::no_such_device),
            std::format("Interface {} does not exist", ifname));
    }
    unsigned ifidx = if_nametoindex(std::string(ifname).c_str());
    if (ifidx == 0)
    {
        throw std::system_error(
            std::make_error_code(std::errc::no_such_device),
            std::format("if_nametoindex failed for {}", ifname));
    }
    return ifidx;
}

/**
 * @brief Enumerate all addresses of @p family on @p ifidx via RTM_GETADDR
 *        and delete each one via RTM_DELADDR.
 *        Uses netlink::detail::performRequest (sendmsg/recvmsg).
 *
 * @return true if all deletions succeeded (no addresses = success)
 */
static bool flushAddresses(uint8_t family, unsigned ifidx, uint16_t rtaType,
                           size_t addrLen)
{
    struct
    {
        nlmsghdr nlh;
        ifaddrmsg ifa;
    } req{};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.ifa.ifa_family = family;
    req.ifa.ifa_index = ifidx;

    struct AddrEntry
    {
        std::array<uint8_t, sizeof(in6_addr)> addr;
        uint8_t pfx;
    };
    std::vector<AddrEntry> toDelete;

    try
    {
        netlink::detail::performRequest(
            NETLINK_ROUTE, &req, req.nlh.nlmsg_len,
            [&](const nlmsghdr& hdr, std::string_view data) {
                if (hdr.nlmsg_type != RTM_NEWADDR)
                    return;
                auto view = data;
                const auto& ifa = netlink::extractRtData<ifaddrmsg>(view);
                if (ifa.ifa_family != family || ifa.ifa_index != ifidx)
                    return;
                while (!view.empty())
                {
                    auto [rta, rdata] = netlink::extractRtAttr(view);
                    if (rta.rta_type == rtaType && rdata.size() >= addrLen)
                    {
                        AddrEntry e{};
                        memcpy(e.addr.data(), rdata.data(), addrLen);
                        e.pfx = ifa.ifa_prefixlen;
                        toDelete.push_back(e);
                    }
                }
            });
    }
    catch (const std::exception& e)
    {
        lg2::error("flushAddresses: RTM_GETADDR failed: {ERROR}", "ERROR",
                   e.what());
        return false;
    }

    bool ok = true;
    for (const auto& e : toDelete)
    {
        lg2::info("Flushing address (family={FAM}) on ifidx {NET_IFIDX}", "FAM",
                  family, "NET_IFIDX", ifidx);
        if (!netlinkAddrRequest(RTM_DELADDR, 0, family, ifidx, e.pfx, rtaType,
                                e.addr.data(), addrLen))
        {
            ok = false;
        }
    }
    return ok;
}

/** @brief Flush all existing IPv4 addresses from an interface.
 *         Equivalent to "ip addr flush dev <ifname>".
 *         Call before setIPV4Address() to ensure a clean slate.
 *  @param ifidx  Interface index (from if_nametoindex)
 */
bool deleteIPv4(unsigned ifidx)
{
    if (ifidx == 0)
    {
        lg2::warning("deleteIPv4: invalid ifidx 0 -- skipping");
        return false;
    }
    return flushAddresses(AF_INET, ifidx, IFA_LOCAL, sizeof(in_addr));
}

/** @brief Flush all existing IPv6 addresses from an interface.
 *         Equivalent to "ip -6 addr flush dev <ifname>".
 *         Call before setIPV6Address() to ensure a clean slate.
 *  @param ifidx  Interface index (from if_nametoindex)
 */
bool deleteIPv6(unsigned ifidx)
{
    if (ifidx == 0)
    {
        lg2::warning("deleteIPv6: invalid ifidx 0 -- skipping");
        return false;
    }
    return flushAddresses(AF_INET6, ifidx, IFA_ADDRESS, sizeof(in6_addr));
}

/**
 * @brief Set an IPv4 address on an ignored interface via RTM_NEWADDR.
 *        Caller is responsible for flushing stale addresses first via
 *        deleteIPv4() if needed.
 *
 * @param ifname       Interface name (e.g. "eth2")
 * @param ipAddress    IPv4 address string (e.g. "9.6.1.100")
 * @param prefixLength CIDR prefix length (1-31)
 * @throws std::system_error     if interface doesn't exist
 * @throws std::invalid_argument if address or prefix is invalid
 * @throws std::runtime_error    if netlink operation fails
 */
void setIPV4Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength)
{
    try
    {
        const stdplus::In4Addr addrTyped = validateIPv4Address(ipAddress);
        struct in_addr addr = static_cast<in_addr>(addrTyped);
        validateIPv4Prefix(prefixLength);
        unsigned ifidx = resolveIfIndex(ifname);

        lg2::info("Setting IPv4 {NET_IP}/{PREFIX} on {NET_INTF} via rtnetlink",
                  "NET_IP", ipAddress, "PREFIX", prefixLength, "NET_INTF",
                  ifname);

        if (!netlinkAddrRequest(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE,
                                AF_INET, ifidx, prefixLength, IFA_LOCAL, &addr,
                                sizeof(in_addr)))
        {
            throw std::runtime_error(
                std::format("RTM_NEWADDR failed for {} {}/{}", ifname,
                            ipAddress, prefixLength));
        }

        lg2::info("Successfully set IPv4 {NET_IP}/{PREFIX} on {NET_INTF}",
                  "NET_IP", ipAddress, "PREFIX", prefixLength, "NET_INTF",
                  ifname);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Invalid IPv4 config for {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Failed to set IPv4 on {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw std::system_error(
            e.code(),
            std::format("Failed to set IPv4 on {}: {}", ifname, e.what()));
    }
    catch (const std::exception& e)
    {
        lg2::error("Unexpected error setting IPv4 on {INTF}: {ERROR}", "INTF",
                   ifname, "ERROR", e.what());
        throw;
    }
}

/**
 * @brief Set an IPv6 address on an ignored interface via RTM_NEWADDR.
 *        Caller is responsible for flushing stale addresses first via
 *        deleteIPv6() if needed.
 *
 * @param ifname      Interface name (e.g. "eth2")
 * @param ipAddress   IPv6 address string (e.g. "2001:db8::1")
 * @param prefixLength CIDR prefix length (1-128)
 * @throws std::system_error     if interface doesn't exist
 * @throws std::invalid_argument if address or prefix is invalid
 * @throws std::runtime_error    if netlink operation fails
 */
void setIPV6Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength)
{
    try
    {
        validateIPv6Prefix(prefixLength);
        const stdplus::In6Addr addrTyped = validateIPv6Address(ipAddress);
        in6_addr addr = static_cast<in6_addr>(addrTyped);
        unsigned ifidx = resolveIfIndex(ifname);

        lg2::info("Setting IPv6 {NET_IP}/{PREFIX} on {NET_INTF} via rtnetlink",
                  "NET_IP", ipAddress, "PREFIX", prefixLength, "NET_INTF",
                  ifname);

        if (!netlinkAddrRequest(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE,
                                AF_INET6, ifidx, prefixLength, IFA_ADDRESS,
                                &addr, sizeof(in6_addr)))
        {
            throw std::runtime_error(
                std::format("RTM_NEWADDR IPv6 failed for {} {}/{}", ifname,
                            ipAddress, prefixLength));
        }

        lg2::info("Successfully set IPv6 {NET_IP}/{PREFIX} on {NET_INTF}",
                  "NET_IP", ipAddress, "PREFIX", prefixLength, "NET_INTF",
                  ifname);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Invalid IPv6 config for {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Failed to set IPv6 on {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw std::system_error(
            e.code(),
            std::format("Failed to set IPv6 on {}: {}", ifname, e.what()));
    }
    catch (const std::exception& e)
    {
        lg2::error("Unexpected error setting IPv6 on {INTF}: {ERROR}", "INTF",
                   ifname, "ERROR", e.what());
        throw;
    }
}

void setMTU(std::string_view ifname, unsigned mtu)
{
    auto ifr = makeIFReq(ifname);
    ifr.ifr_mtu = mtu;
    getIFSock().ioctl(SIOCSIFMTU, &ifr);
}

void setNICUp(std::string_view ifname, bool up)
{
    ifreq ifr = executeIFReq(ifname, SIOCGIFFLAGS);
    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= up ? IFF_UP : 0;
    lg2::info("Setting NIC {UPDOWN} on {NET_INTF}", "UPDOWN",
              up ? "up"sv : "down"sv, "NET_INTF", ifname);
    getIFSock().ioctl(SIOCSIFFLAGS, &ifr);
}

void deleteIntf(unsigned idx)
{
    if (idx == 0)
    {
        return;
    }
    ifinfomsg msg = {};
    msg.ifi_family = AF_UNSPEC;
    msg.ifi_index = idx;
    netlink::performRequest(
        NETLINK_ROUTE, RTM_DELLINK, NLM_F_REPLACE, msg,
        [&](const nlmsghdr& hdr, std::string_view data) {
            int err = 0;
            if (hdr.nlmsg_type == NLMSG_ERROR)
            {
                err = netlink::extractRtData<nlmsgerr>(data).error;
            }
            throw std::runtime_error(
                std::format("Failed to delete `{}`: {}", idx, strerror(err)));
        });
}

bool deleteLinkLocalIPv4ViaNetlink(unsigned ifidx, const stdplus::SubnetAny& ip)
{
    bool success = false;

    std::visit(
        [&](const auto& wrappedAddr) {
            using T = std::decay_t<decltype(wrappedAddr)>;
            if constexpr (std::is_same_v<T, stdplus::In4Addr>)
            {
                in_addr addr = static_cast<in_addr>(wrappedAddr);

                if ((ntohl(addr.s_addr) & 0xFFFF0000) != 0xA9FE0000)
                    return;

                int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
                if (sock < 0)
                {
                    lg2::error("Failed to open the NETLINK_ROUTE socket");
                    return;
                }

                sockaddr_nl nladdr{};
                memset(&nladdr, 0, sizeof(nladdr));
                nladdr.nl_family = AF_NETLINK;
                nladdr.nl_pid = 0;
                nladdr.nl_groups = 0;

                if (bind(sock, reinterpret_cast<sockaddr*>(&nladdr),
                         sizeof(nladdr)) < 0)
                {
                    lg2::error("Failed to bind the NETLINK_ROUTE socket");
                    close(sock);
                    return;
                }

                struct
                {
                    nlmsghdr nlh;
                    ifaddrmsg ifa;
                    char buf[256];
                } req{};

                req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
                req.nlh.nlmsg_type = RTM_DELADDR;
                req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                req.ifa.ifa_family = AF_INET;
                req.ifa.ifa_index = ifidx;
                req.ifa.ifa_prefixlen = ip.getPfx();

                rtattr* rta = reinterpret_cast<rtattr*>(req.buf);
                rta->rta_type = IFA_LOCAL;
                rta->rta_len = RTA_LENGTH(sizeof(in_addr));
                memcpy(RTA_DATA(rta), &addr, sizeof(in_addr));

                req.nlh.nlmsg_len += rta->rta_len;

                const ssize_t sent = send(sock, &req, req.nlh.nlmsg_len, 0);
                if (sent != static_cast<ssize_t>(req.nlh.nlmsg_len))
                {
                    lg2::error(
                        "Failed to send netlink message for RTM_DELADDR");
                    close(sock);
                    return;
                }

                std::array<char, 4096> resp;
                ssize_t len = recv(sock, resp.data(), resp.size(), 0);
                close(sock);

                if (len < 0)
                {
                    lg2::error(
                        "recv failed on netlink socket for ifidx {NET_IFIDX}: {ERROR}",
                        "NET_IFIDX", ifidx, "ERROR", strerror(errno));
                    return;
                }

                if (len >= NLMSG_LENGTH(0))
                {
                    const nlmsghdr* hdr =
                        reinterpret_cast<nlmsghdr*>(resp.data());
                    if (hdr->nlmsg_type == NLMSG_ERROR)
                    {
                        const nlmsgerr* err =
                            reinterpret_cast<nlmsgerr*>(NLMSG_DATA(hdr));
                        if (err->error != 0)
                        {
                            lg2::error(
                                "Failed to delete link-local IP on ifidx {NET_IFIDX}: {ERROR}",
                                "NET_IFIDX", ifidx, "ERROR",
                                strerror(-err->error));
                            return;
                        }
                    }
                }
                success = true;
            }
        },
        ip.getAddr());

    return success;
}

} // namespace phosphor::network::system
