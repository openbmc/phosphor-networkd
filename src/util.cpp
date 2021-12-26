#include "util.hpp"

#include "config_parser.hpp"
#include "types.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/wait.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <list>
#ifdef SYNC_MAC_FROM_INVENTORY
#include <nlohmann/json.hpp>
#endif
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <stdexcept>
#include <stdplus/raw.hpp>
#include <string>
#include <variant>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::filesystem;

namespace internal
{

void executeCommandinChildProcess(const char* path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();
    int status{};

    if (pid == 0)
    {
        execv(path, args);
        auto error = errno;
        // create the command from var args.
        std::string command = path + " "s;

        for (int i = 0; args[i]; i++)
        {
            command += args[i] + " "s;
        }

        log<level::ERR>("Couldn't exceute the command",
                        entry("ERRNO=%d", error),
                        entry("CMD=%s", command.c_str()));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork", entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            { // Error other than EINTR
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            std::string command = path + " "s;
            for (int i = 0; args[i]; i++)
            {
                command += args[i] + " "s;
            }

            log<level::ERR>("Unable to execute the command",
                            entry("CMD=%s", command.c_str()),
                            entry("STATUS=%d", status));
            elog<InternalFailure>();
        }
    }
}

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv()
{
    auto r = std::getenv("IGNORED_INTERFACES");
    if (r == nullptr)
    {
        return "";
    }
    return r;
}

/** @brief Parse the comma separated interface names */
std::set<std::string_view> parseInterfaces(std::string_view interfaces)
{
    std::set<std::string_view> result;
    while (true)
    {
        auto sep = interfaces.find(',');
        auto interface = interfaces.substr(0, sep);
        while (!interface.empty() && std::isspace(interface.front()))
        {
            interface.remove_prefix(1);
        }
        while (!interface.empty() && std::isspace(interface.back()))
        {
            interface.remove_suffix(1);
        }
        if (!interface.empty())
        {
            result.insert(interface);
        }
        if (sep == interfaces.npos)
        {
            break;
        }
        interfaces = interfaces.substr(sep + 1);
    }
    return result;
}

/** @brief Get the ignored interfaces */
const std::set<std::string_view>& getIgnoredInterfaces()
{
    static auto ignoredInterfaces = parseInterfaces(getIgnoredInterfacesEnv());
    return ignoredInterfaces;
}

} // namespace internal

uint8_t toCidr(int addressFamily, const std::string& subnetMask)
{
    uint32_t subnet[sizeof(in6_addr) / sizeof(uint32_t)];
    if (inet_pton(addressFamily, subnetMask.c_str(), &subnet) != 1)
    {
        log<level::ERR>("inet_pton failed:",
                        entry("SUBNETMASK=%s", subnetMask.c_str()));
        return 0;
    }

    static_assert(sizeof(in6_addr) % sizeof(uint32_t) == 0);
    static_assert(sizeof(in_addr) % sizeof(uint32_t) == 0);
    auto i = (addressFamily == AF_INET ? sizeof(in_addr) : sizeof(in6_addr)) /
             sizeof(uint32_t);
    while (i > 0)
    {
        if (subnet[--i] != 0)
        {
            auto v = be32toh(subnet[i]);
            static_assert(sizeof(unsigned) == sizeof(uint32_t));
            auto trailing = __builtin_ctz(v);
            auto ret = (i + 1) * 32 - trailing;
            bool valid = ~v == 0 || 32 == trailing + __builtin_clz(~v);
            while (i > 0 && (valid = (~subnet[--i] == 0) && valid))
                ;
            if (!valid)
            {
                log<level::ERR>("Invalid netmask",
                                entry("SUBNETMASK=%s", subnetMask.c_str()));
                return 0;
            }
            return ret;
        }
    }
    return 0;
}

std::string toMask(int addressFamily, uint8_t prefix)
{
    if (addressFamily == AF_INET6)
    {
        // TODO:- conversion for v6
        return "";
    }

    if (prefix < 1 || prefix > 30)
    {
        log<level::ERR>("Invalid Prefix", entry("PREFIX=%d", prefix));
        return "";
    }
    /* Create the netmask from the number of bits */
    unsigned long mask = 0;
    for (auto i = 0; i < prefix; i++)
    {
        mask |= 1 << (31 - i);
    }
    struct in_addr netmask;
    netmask.s_addr = htonl(mask);
    return inet_ntoa(netmask);
}

InAddrAny addrFromBuf(int addressFamily, std::string_view buf)
{
    if (addressFamily == AF_INET)
    {
        struct in_addr ret;
        if (buf.size() != sizeof(ret))
        {
            throw std::runtime_error("Buf not in_addr sized");
        }
        memcpy(&ret, buf.data(), sizeof(ret));
        return ret;
    }
    else if (addressFamily == AF_INET6)
    {
        struct in6_addr ret;
        if (buf.size() != sizeof(ret))
        {
            throw std::runtime_error("Buf not in6_addr sized");
        }
        memcpy(&ret, buf.data(), sizeof(ret));
        return ret;
    }

    throw std::runtime_error("Unsupported address family");
}

std::string toString(const struct in_addr& addr)
{
    std::string ip(INET_ADDRSTRLEN, '\0');
    if (inet_ntop(AF_INET, &addr, ip.data(), ip.size()) == nullptr)
    {
        throw std::runtime_error("Failed to convert IP4 to string");
    }

    ip.resize(strlen(ip.c_str()));
    return ip;
}

std::string toString(const struct in6_addr& addr)
{
    std::string ip(INET6_ADDRSTRLEN, '\0');
    if (inet_ntop(AF_INET6, &addr, ip.data(), ip.size()) == nullptr)
    {
        throw std::runtime_error("Failed to convert IP6 to string");
    }

    ip.resize(strlen(ip.c_str()));
    return ip;
}

std::string toString(const InAddrAny& addr)
{
    if (std::holds_alternative<struct in_addr>(addr))
    {
        const auto& v = std::get<struct in_addr>(addr);
        return toString(v);
    }
    else if (std::holds_alternative<struct in6_addr>(addr))
    {
        const auto& v = std::get<struct in6_addr>(addr);
        return toString(v);
    }

    throw std::runtime_error("Invalid addr type");
}

bool isLinkLocalIP(const std::string& address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

bool isValidIP(int addressFamily, const std::string& address)
{
    unsigned char buf[sizeof(struct in6_addr)];

    return inet_pton(addressFamily, address.c_str(), buf) > 0;
}

bool isValidPrefix(int addressFamily, uint8_t prefixLength)
{
    if (addressFamily == AF_INET)
    {
        if (prefixLength < IPV4_MIN_PREFIX_LENGTH ||
            prefixLength > IPV4_MAX_PREFIX_LENGTH)
        {
            return false;
        }
    }

    if (addressFamily == AF_INET6)
    {
        if (prefixLength < IPV4_MIN_PREFIX_LENGTH ||
            prefixLength > IPV6_MAX_PREFIX_LENGTH)
        {
            return false;
        }
    }

    return true;
}

IntfAddrMap getInterfaceAddrs()
{
    IntfAddrMap intfMap{};
    struct ifaddrs* ifaddr = nullptr;

    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the getifaddrs call",
                        entry("ERRNO=%s", strerror(error)));
        elog<InternalFailure>();
    }

    AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;

    std::string intfName{};

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        // walk interfaces
        if (ifa->ifa_addr == nullptr)
        {
            continue;
        }

        // get only INET interfaces not ipv6
        if (ifa->ifa_addr->sa_family == AF_INET ||
            ifa->ifa_addr->sa_family == AF_INET6)
        {
            // if loopback, or not running ignore
            if ((ifa->ifa_flags & IFF_LOOPBACK) ||
                !(ifa->ifa_flags & IFF_RUNNING))
            {
                continue;
            }
            intfName = ifa->ifa_name;
            AddrInfo info{};
            char ip[INET6_ADDRSTRLEN] = {0};
            char subnetMask[INET6_ADDRSTRLEN] = {0};

            if (ifa->ifa_addr->sa_family == AF_INET)
            {

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr),
                          ip, sizeof(ip));

                inet_ntop(
                    ifa->ifa_addr->sa_family,
                    &(((struct sockaddr_in*)(ifa->ifa_netmask))->sin_addr),
                    subnetMask, sizeof(subnetMask));
            }
            else
            {
                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr),
                          ip, sizeof(ip));

                inet_ntop(
                    ifa->ifa_addr->sa_family,
                    &(((struct sockaddr_in6*)(ifa->ifa_netmask))->sin6_addr),
                    subnetMask, sizeof(subnetMask));
            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = ip;
            info.prefix = toCidr(info.addrType, std::string(subnetMask));
            intfMap[intfName].push_back(info);
        }
    }
    return intfMap;
}

InterfaceList getInterfaces()
{
    InterfaceList interfaces{};
    struct ifaddrs* ifaddr = nullptr;

    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the getifaddrs call",
                        entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }

    AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;
    const auto& ignoredInterfaces = internal::getIgnoredInterfaces();

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        // walk interfaces
        // if loopback ignore
        if (ifa->ifa_flags & IFF_LOOPBACK ||
            ignoredInterfaces.find(ifa->ifa_name) != ignoredInterfaces.end())
        {
            continue;
        }
        interfaces.emplace(ifa->ifa_name);
    }
    return interfaces;
}

void deleteInterface(const std::string& intf)
{
    pid_t pid = fork();
    int status{};

    if (pid == 0)
    {

        execl("/sbin/ip", "ip", "link", "delete", "dev", intf.c_str(), nullptr);
        auto error = errno;
        log<level::ERR>("Couldn't delete the device", entry("ERRNO=%d", error),
                        entry("INTF=%s", intf.c_str()));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork", entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            { /* Error other than EINTR */
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            log<level::ERR>("Unable to delete the interface",
                            entry("INTF=%s", intf.c_str()),
                            entry("STATUS=%d", status));
            elog<InternalFailure>();
        }
    }
}

std::optional<std::string> interfaceToUbootEthAddr(const char* intf)
{
    constexpr char ethPrefix[] = "eth";
    constexpr size_t ethPrefixLen = sizeof(ethPrefix) - 1;
    if (strncmp(ethPrefix, intf, ethPrefixLen) != 0)
    {
        return std::nullopt;
    }
    const auto intfSuffix = intf + ethPrefixLen;
    if (intfSuffix[0] == '\0')
    {
        return std::nullopt;
    }
    char* end;
    unsigned long idx = strtoul(intfSuffix, &end, 10);
    if (end[0] != '\0')
    {
        return std::nullopt;
    }
    if (idx == 0)
    {
        return "ethaddr";
    }
    return "eth" + std::to_string(idx) + "addr";
}

EthernetInterfaceIntf::DHCPConf getDHCPValue(const std::string& confDir,
                                             const std::string& intf)
{
    EthernetInterfaceIntf::DHCPConf dhcp =
        EthernetInterfaceIntf::DHCPConf::none;
    // Get the interface mode value from systemd conf
    // using namespace std::string_literals;
    fs::path confPath = confDir;
    std::string fileName = systemd::config::networkFilePrefix + intf +
                           systemd::config::networkFileSuffix;
    confPath /= fileName;

    auto rc = config::ReturnCode::SUCCESS;
    config::ValueList values;
    config::Parser parser(confPath.string());

    std::tie(rc, values) = parser.getValues("Network", "DHCP");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for Network[DHCP]",
                          entry("RC=%d", rc));
        return dhcp;
    }
    // There will be only single value for DHCP key.
    if (values[0] == "true")
    {
        dhcp = EthernetInterfaceIntf::DHCPConf::both;
    }
    else if (values[0] == "ipv4")
    {
        dhcp = EthernetInterfaceIntf::DHCPConf::v4;
    }
    else if (values[0] == "ipv6")
    {
        dhcp = EthernetInterfaceIntf::DHCPConf::v6;
    }
    return dhcp;
}

namespace mac_address
{

constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperObj = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";
constexpr auto propIntf = "org.freedesktop.DBus.Properties";
constexpr auto methodGet = "Get";
constexpr auto configFile = "/usr/share/network/config.json";

using DbusObjectPath = std::string;
using DbusService = std::string;
using DbusInterface = std::string;
using ObjectTree =
    std::map<DbusObjectPath, std::map<DbusService, std::vector<DbusInterface>>>;

constexpr auto invBus = "xyz.openbmc_project.Inventory.Manager";
constexpr auto invNetworkIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";
constexpr auto invRoot = "/xyz/openbmc_project/inventory";

ether_addr getfromInventory(sdbusplus::bus::bus& bus,
                            const std::string& intfName)
{

    std::string interfaceName = intfName;

#ifdef SYNC_MAC_FROM_INVENTORY
    // load the config JSON from the Read Only Path
    std::ifstream in(configFile);
    nlohmann::json configJson;
    in >> configJson;
    interfaceName = configJson[intfName];
#endif

    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(invNetworkIntf);

    auto depth = 0;

    auto mapperCall =
        bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

    mapperCall.append(invRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the interface",
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    DbusObjectPath objPath;
    DbusService service;

    if (1 == objectTree.size())
    {
        objPath = objectTree.begin()->first;
        service = objectTree.begin()->second.begin()->first;
    }
    else
    {
        // If there are more than 2 objects, object path must contain the
        // interface name
        for (auto const& object : objectTree)
        {
            log<level::INFO>("interface",
                             entry("INT=%s", interfaceName.c_str()));
            log<level::INFO>("object", entry("OBJ=%s", object.first.c_str()));

            if (std::string::npos != object.first.find(interfaceName.c_str()))
            {
                objPath = object.first;
                service = object.second.begin()->first;
                break;
            }
        }

        if (objPath.empty())
        {
            log<level::ERR>("Can't find the object for the interface",
                            entry("intfName=%s", interfaceName.c_str()));
            elog<InternalFailure>();
        }
    }

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      propIntf, methodGet);

    method.append(invNetworkIntf, "MACAddress");

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to get MACAddress",
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    std::variant<std::string> value;
    reply.read(value);
    return fromString(std::get<std::string>(value));
}

ether_addr fromString(const char* str)
{
    struct ether_addr mac;

    if (ether_aton_r(str, &mac) != nullptr)
    {
        return mac;
    }

    // MAC address from hex string
    if (strlen(str) == 12 &&
        std::regex_match(str, std::regex("^[a-fA-F0-9]{12}")))
    {
        unsigned int mac_addr_uint[6];
        if (sscanf(str, "%02x%02x%02x%02x%02x%02x", &mac_addr_uint[0],
                   &mac_addr_uint[1], &mac_addr_uint[2], &mac_addr_uint[3],
                   &mac_addr_uint[4], &mac_addr_uint[5]) == 6)
        {
            mac.ether_addr_octet[0] = mac_addr_uint[0];
            mac.ether_addr_octet[1] = mac_addr_uint[1];
            mac.ether_addr_octet[2] = mac_addr_uint[2];
            mac.ether_addr_octet[3] = mac_addr_uint[3];
            mac.ether_addr_octet[4] = mac_addr_uint[4];
            mac.ether_addr_octet[5] = mac_addr_uint[5];
            return mac;
        }
    }

    throw std::invalid_argument("Invalid MAC Address");
}

std::string toString(const ether_addr& mac)
{
    char buf[18] = {0};
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac.ether_addr_octet[0],
             mac.ether_addr_octet[1], mac.ether_addr_octet[2],
             mac.ether_addr_octet[3], mac.ether_addr_octet[4],
             mac.ether_addr_octet[5]);
    return buf;
}

bool isEmpty(const ether_addr& mac)
{
    return stdplus::raw::equal(mac, ether_addr{});
}

bool isMulticast(const ether_addr& mac)
{
    return mac.ether_addr_octet[0] & 0b1;
}

bool isUnicast(const ether_addr& mac)
{
    return !isEmpty(mac) && !isMulticast(mac);
}

} // namespace mac_address
} // namespace network
} // namespace phosphor
