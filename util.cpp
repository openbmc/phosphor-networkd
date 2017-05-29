#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <bitset>
#include <iostream>
#include <list>
#include <string>
#include <algorithm>
#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
namespace
{
using namespace phosphor::logging;
uint8_t toV6Cidr(const std::string& subnetMask)
{
    uint8_t pos = 0;
    uint8_t prevPos = 0;
    uint8_t cidr = 0;
    int buff;
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
        if (sscanf(str.c_str(), "%x", &buff) <= 0)
        {
            log<level::ERR>("Invalid Mask",
                            entry("Mask=%s", subnetMask));

            return 0;
        }
        // convert the number into bitset
        // and check for how many ones are there.
        // if we don't have all the ones then make
        // sure that all the ones should be left justify.

        std::bitset<16>set(buff);
        if (!set.all())
        {
            for (uint8_t i = 0 ; i < (16 - set.count()) ; i--)
            {
                if (set[i])
                {
                    log<level::ERR>("Invalid Mask",
                                    entry("Mask=%s", subnetMask));
                    return 0;
                }

            }
            cidr += set.count();
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
        fprintf(stderr, "Invalid net mask bits (1-30): %d\n", prefix);
        exit(1);
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

std::string getNetwork(int addressFamily, const std::string& ipaddress,
                       uint8_t prefix)
{
    unsigned char* pntMask;
    unsigned char* pntNetwork;
    int bit;
    int offset;
    struct in6_addr netmask;
    const u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
                              0xf8, 0xfc, 0xfe, 0xff
                             };
    std::cout << "IPADDRESS=" << ipaddress << "\n";

    // Convert prefix into netmask network address
    memset(&netmask, 0, sizeof(struct in6_addr));
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

    // convert ipaddres string  into network address
    struct in6_addr ipaddressNetwork;
    if (inet_pton(addressFamily, ipaddress.c_str(), &ipaddressNetwork) <= 0)
    {
        std::cout << "inet_pton failure\n";
        log<level::ERR>("inet_pton failure");
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
    char networkString[INET6_ADDRSTRLEN];
    if (inet_ntop(addressFamily, &ipaddressNetwork , networkString,
                  INET6_ADDRSTRLEN) == NULL)
    {
        log<level::ERR>("inet_ntop failure");
        std::cout << "inet_ntop failure\n";

    }
    std::cout << "NetworkAddress=" << networkString << "\n";
    return networkString;
}

bool isLinkLocal(const std::string& address)
{
    std::string linklocal = "fe80";
    return  std::mismatch(linklocal.begin(), linklocal.end(),
                          address.begin()).first == linklocal.end() ? true :
            false;
}

}//namespace network
}//namespace phosphor
