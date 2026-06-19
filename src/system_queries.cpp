#include "system_queries.hpp"

#include "netlink.hpp"

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/hash/tuple.hpp>

#include <algorithm>
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

/**
 * @brief Validate IPv4 address string.
 * @param ipAddress  IPv4 string e.g. "192.168.1.100"
 * @return stdplus::In4Addr with operator in_addr() for ioctl use
 * @throws std::invalid_argument if not a valid IPv4 address
 */
static struct in_addr validateIPv4Address(std::string_view ipAddress)
{
    try
    {
        return stdplus::fromStr<stdplus::In4Addr>(ipAddress);
    }
    catch (const std::exception& e)
    {
        throw std::invalid_argument(
            std::string("Invalid IPv4 address: ") + std::string(ipAddress));
    }
}

/**
 * @brief Validate prefix length and compute the IPv4 netmask.
 * @param addr         Validated In4Addr from validateIPv4Address()
 * @param prefixLength CIDR prefix length — valid range is 1-31 for
 *                     interface assignment (/0 and /32 are rejected)
 * @return in_addr netmask ready for SIOCSIFNETMASK
 * @throws std::invalid_argument if prefixLength is 0, >= 32, or > 32
 */
static struct in_addr calculateNetmask(stdplus::In4Addr addr,
                                       uint8_t prefixLength)
{
    // Reject /0 (default route mask) and /32 (host-only) as they are
    // not meaningful for interface address assignment. stdplus::Subnet4
    // only rejects > 32, so we enforce the tighter 1-31 range here.
    if (prefixLength == 0 || prefixLength >= 32)
    {
        throw std::invalid_argument(
            std::string("Invalid prefix length: ") +
            std::to_string(prefixLength) +
            " — must be 1-31 for interface address assignment");
    }

    try
    {
        // stdplus::Subnet4 validates prefixLength <= 32
        const stdplus::Subnet4 subnet(addr, prefixLength);

        // pfxToMask<In4Addr> converts the prefix to the correct bitmask
        return static_cast<in_addr>(
            stdplus::pfxToMask<stdplus::In4Addr>(prefixLength));
    }
    catch (const std::exception& e)
    {
        // Propagate any unexpected errors
        throw;
    }
}

/**
 * @brief Calculate broadcast address
 * @param addr IP address
 * @param netmask Network mask
 * @return in_addr structure with the broadcast address
 */
static struct in_addr calculateBroadcast(struct in_addr addr,
                                         struct in_addr netmask)
{
    struct in_addr bcast;
    bcast.s_addr = (addr.s_addr & netmask.s_addr) | ~netmask.s_addr;
    return bcast;
}

/**
 * @brief Validate interface name
 * @param ifname Interface name to validate
 * @throws std::system_error if name is empty or exceeds IFNAMSIZ-1
 */
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
 * @brief Set sockaddr_in structure with IPv4 address
 * @param sa Reference to sockaddr structure to populate
 * @param addr IPv4 address to set
 */
static void setSockAddrIn(struct sockaddr& sa, const struct in_addr& addr)
{
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&sa);
    sin->sin_family = AF_INET;
    sin->sin_addr = addr;
}

/**
 * @brief Set IPV4 address on a network interface
 * @param ifname Interface name (e.g., "eth0")
 * @param ipAddress IPv4 address in dotted-decimal notation (e.g.,
 * "192.168.1.100")
 * @param prefixLength CIDR prefix length (1-31, rejects 0, 32, and >32)
 * @throws std::system_error if interface doesn't exist or ioctl fails
 * @throws std::invalid_argument if IP address format is invalid or prefix
 * length is invalid
 */
void setIPV4Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength)
{
    try
    {
        // Validate interface name
        validateInterfaceName(ifname);

        if (!interfaceExists(ifname))
        {
            throw std::system_error(
                std::make_error_code(std::errc::no_such_device),
                std::format("Interface {} does not exist", ifname));
        }

        // Validate IP address and calculate network parameters
        const stdplus::In4Addr addrTyped = validateIPv4Address(ipAddress);
        struct in_addr addr = static_cast<in_addr>(addrTyped);
        struct in_addr netmask = calculateNetmask(addrTyped, prefixLength);
        struct in_addr bcast = calculateBroadcast(addr, netmask);

        // Prepare ifreq structure
        auto ifr = makeIFReq(ifname);

        // Set IP address
        setSockAddrIn(ifr.ifr_addr, addr);
        lg2::info("Setting IP {NET_IP} on {NET_INTF}", "NET_IP", ipAddress,
                  "NET_INTF", ifname);
        getIFSock().ioctl(SIOCSIFADDR, &ifr);

        // Set netmask
        setSockAddrIn(ifr.ifr_netmask, netmask);
        lg2::info("Setting netmask /{PREFIX} on {NET_INTF}", "PREFIX",
                  prefixLength, "NET_INTF", ifname);
        getIFSock().ioctl(SIOCSIFNETMASK, &ifr);

        // Set broadcast address (non-critical)
        setSockAddrIn(ifr.ifr_broadaddr, bcast);
        try
        {
            getIFSock().ioctl(SIOCSIFBRDADDR, &ifr);
        }
        catch (const std::system_error& e)
        {
            lg2::warning("Failed to set broadcast on {INTF}: {ERROR}", "INTF",
                         ifname, "ERROR", e.what());
        }

        lg2::info("Successfully configured IP address on {NET_INTF}",
                  "NET_INTF", ifname);
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error("Invalid IP configuration for {INTF}: {ERROR}", "INTF",
                   ifname, "ERROR", e.what());
        throw;
    }
    catch (const std::system_error& e)
    {
        lg2::error("Failed to configure IP on {INTF}: {ERROR}", "INTF", ifname,
                   "ERROR", e.what());
        throw std::system_error(
            e.code(),
            std::format("Failed to configure IP on {}: {}", ifname, e.what()));
    }
    catch (const std::exception& e)
    {
        lg2::error("Unexpected error configuring IP on {INTF}: {ERROR}", "INTF",
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
                std::memcpy(RTA_DATA(rta), &addr, sizeof(in_addr));

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
