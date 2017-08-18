#include "config_parser.hpp"
#include "util.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/wait.h>

#include <iostream>
#include <list>
#include <string>
#include <algorithm>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

namespace
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

uint8_t toV6Cidr(const std::string& subnetMask)
{
    uint8_t pos = 0;
    uint8_t prevPos = 0;
    uint8_t cidr = 0;
    uint16_t buff {};
    do
    {
        //subnet mask look like ffff:ffff::
        // or ffff:c000::
        pos =  subnetMask.find(":", prevPos);
        if (pos == std::string::npos)
        {
            break;
        }

        auto str = subnetMask.substr(prevPos, (pos - prevPos));
        prevPos = pos + 1;

        // String length is 0
        if (!str.length())
        {
            return cidr;
        }
        //converts it into number.
        if (sscanf(str.c_str(), "%hx", &buff) <= 0)
        {
            log<level::ERR>("Invalid Mask",
                            entry("SUBNETMASK=%s", subnetMask));

            return 0;
        }

        // convert the number into bitset
        // and check for how many ones are there.
        // if we don't have all the ones then make
        // sure that all the ones should be left justify.

        if (__builtin_popcount(buff) != 16)
        {
            if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) != __builtin_popcount(buff))
            {
                log<level::ERR>("Invalid Mask",
                                entry("SUBNETMASK=%s", subnetMask));

                return 0;
            }
            cidr += __builtin_popcount(buff);
            return cidr;
        }

        cidr += 16;
    }
    while (1);

    return cidr;
}
}// anonymous namespace

uint8_t toCidr(int addressFamily, const std::string& subnetMask)
{
    if (addressFamily == AF_INET6)
    {
        return toV6Cidr(subnetMask);
    }

    uint32_t buff;

    auto rc = inet_pton(addressFamily, subnetMask.c_str(), &buff);
    if (rc <= 0)
    {
        log<level::ERR>("inet_pton failed:",
                        entry("SUBNETMASK=%s", subnetMask));
        return 0;
    }

    buff = be32toh(buff);
    // total no of bits - total no of leading zero == total no of ones
    if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) == __builtin_popcount(buff))
    {
        return __builtin_popcount(buff);
    }
    else
    {
        log<level::ERR>("Invalid Mask",
                        entry("SUBNETMASK=%s", subnetMask));
        return 0;
    }
}

std::string toMask(int addressFamily, uint8_t prefix)
{
    if (addressFamily == AF_INET6)
    {
        //TODO:- conversion for v6
        return "";
    }

    if (prefix < 1 || prefix > 30)
    {
        log<level::ERR>("Invalid Prefix",
                        entry("PREFIX=%d", prefix));
        return "";
    }
    /* Create the netmask from the number of bits */
    unsigned long mask = 0;
    for (auto i = 0 ; i < prefix ; i++)
    {
        mask |= 1 << (31 - i);
    }
    struct in_addr netmask;
    netmask.s_addr = htonl(mask);
    return inet_ntoa(netmask);
}

std::string getNetworkID(int addressFamily, const std::string& ipaddress,
                         uint8_t prefix)
{
    unsigned char* pntMask = nullptr;
    unsigned char* pntNetwork = nullptr;
    int bit {};
    int offset {};
    struct in6_addr netmask {};
    const u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
                              0xf8, 0xfc, 0xfe, 0xff
                             };

    pntMask = reinterpret_cast<unsigned char*>(&netmask);

    offset = prefix / 8;
    bit = prefix % 8;

    while (offset--)
    {
        *pntMask++ = 0xff;
    }

    if (bit)
    {
        *pntMask = maskbit[bit];
    }

    // convert ipaddres string into network address
    struct in6_addr ipaddressNetwork;
    if (inet_pton(addressFamily, ipaddress.c_str(), &ipaddressNetwork) <= 0)
    {
        log<level::ERR>("inet_pton failure",
                        entry("IPADDRESS=%s", ipaddress.c_str()));
        report<InternalFailure>();

        return "";
    }

    // Now bit wise and gets you the network address
    pntMask = reinterpret_cast<unsigned char*>(&netmask);
    pntNetwork = reinterpret_cast<unsigned char*>(&ipaddressNetwork);

    for (int i = 0; i < 16 ; i++)
    {
        pntNetwork[i] = pntNetwork[i] & pntMask[i];
    }

    //convert the network address into string fomat.
    char networkString[INET6_ADDRSTRLEN] = { 0 };
    if (inet_ntop(addressFamily, &ipaddressNetwork, networkString,
                  INET6_ADDRSTRLEN) == NULL)
    {
        log<level::ERR>("inet_ntop failure");
        report<InternalFailure>();
    }
    return networkString;
}

bool isLinkLocal(const std::string& address)
{
    std::string linklocal = "fe80";
    return std::mismatch(linklocal.begin(), linklocal.end(),
                         address.begin()).first == linklocal.end() ?
           true : false;
}

IntfAddrMap getInterfaceAddrs()
{
    IntfAddrMap intfMap {};
    AddrList addrList {};
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

    std::string intfName {};

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
            // if the interface name is  not same as the  previous
            // iteration then add the addr list into
            // the map.
            if (intfName != "" && intfName != std::string(ifa->ifa_name))
            {
                intfMap.emplace(intfName, addrList);
                addrList.clear();
            }
            intfName = ifa->ifa_name;
            AddrInfo info {};
            char ip[INET6_ADDRSTRLEN] = { 0 };
            char subnetMask[INET6_ADDRSTRLEN] = { 0 };

            if (ifa->ifa_addr->sa_family == AF_INET)
            {

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr),
                          ip,
                          sizeof(ip));

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_netmask))->sin_addr),
                          subnetMask,
                          sizeof(subnetMask));

            }
            else
            {
                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr),
                          ip,
                          sizeof(ip));

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_netmask))->sin6_addr),
                          subnetMask,
                          sizeof(subnetMask));

            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = ip;
            info.prefix = toCidr(info.addrType, std::string(subnetMask));
            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}

void deleteInterface(const std::string& intf)
{
    pid_t pid = fork();
    int status {};

    if (pid == 0)
    {

        execl("/sbin/ip", "ip", "link", "delete", "dev", intf.c_str(), nullptr);
        auto error = errno;
        log<level::ERR>("Couldn't delete the device",
                        entry("ERRNO=%d", error),
                        entry("INTF=%s", intf.c_str()));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork",
                        entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            {   /* Error other than EINTR */
                status = -1;
                break;
            }
        }

        if(status < 0)
        {
            log<level::ERR>("Unable to delete the interface",
                             entry("INTF=%s", intf.c_str(),
                             entry("STATUS=%d", status)));
            elog<InternalFailure>();
        }
    }
}

bool getDHCPValue(const std::string& confDir, const std::string& intf)
{
    bool dhcp = false;
    // Get the interface mode value from systemd conf
    //using namespace std::string_literals;
    fs::path confPath = confDir;
    std::string fileName = systemd::config::networkFilePrefix + intf +
                           systemd::config::networkFileSuffix;
    confPath /= fileName;

    try
    {
        config::Parser parser(confPath.string());
        auto values = parser.getValues("Network", "DHCP");
        // There will be only single value for DHCP key.
        if (values[0] == "true")
        {
            dhcp = true;
        }
    }
    catch (InternalFailure& e)
    {
        log<level::INFO>("Exception occured during getting of DHCP value");
    }
    return dhcp;
}

namespace internal
{

void executeCommandinChildProcess(char* path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();
    int status {};

    if (pid == 0)
    {
        execv(path, args);
        auto error = errno;
        // create the command from var args.
        std::string command;

        for(int i = 0; args[i]; i++)
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
        log<level::ERR>("Error occurred during fork",
                entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            {   //Error other than EINTR
                status = -1;
                break;
            }
        }

        if(status < 0)
        {
            std::string command;
            for(int i = 0; args[i]; i++)
            {
                command += args[i] + " "s;
            }

            log<level::ERR>("Unable to execute the command",
                    entry("CMD=%s", command.c_str(),
                          entry("STATUS=%d", status)));
            elog<InternalFailure>();
        }
    }

}
} //namespace internal

}//namespace network
}//namespace phosphor
