#pragma once

#include "hyp_ethernet_interface.hpp"
#include "hyp_ip_interface.hpp"

namespace phosphor
{
namespace network
{

class MockHypEthernetInterface : public HypEthInterface
{
  public:
    MockHypEthernetInterface(sdbusplus::bus::bus& bus, const char* path,
                             const std::string& intfName,
                             HypNetworkMgr& parent) :
        HypEthInterface(bus, path, intfName, parent)
    {
    }

    void createIPAddrObj()
    {
        addrs.emplace(
            "eth0",
            std::make_unique<HypIPAddress>(
                bus, "/xyz/openbmc_test/network/hypervisor/eth0/ipv4/addr0",
                *this, HypIP::Protocol::IPv4, "9.9.9.9",
                HypIP::AddressOrigin::Static, 0, "9.9.9.1", "if0"));
        addrs.emplace(
            "eth1",
            std::make_unique<HypIPAddress>(
                bus, "/xyz/openbmc_test/network/hypervisor/eth1/ipv4/addr0",
                *this, HypIP::Protocol::IPv4, "8.8.8.8",
                HypIP::AddressOrigin::Static, 0, "8.8.8.1", "if1"));
    }

    bool createIP(MockHypEthernetInterface& interface, std::string intfLabel,
                  HypIP::Protocol protType, const std::string& ipaddress,
                  uint8_t prefixLength, const std::string& gateway)
    {
        if (interface.dhcpIsEnabled(protType))
        {
            switch (protType)
            {
                case HypIP::Protocol::IPv4:
                    interface.dhcp4(false);
                    break;
                case HypIP::Protocol::IPv6:
                    interface.dhcp6(false);
                    break;
            }
        }

        HypIP::AddressOrigin origin = HypIP::AddressOrigin::Static;

        if (!isValidIP(AF_INET, ipaddress) && !isValidIP(AF_INET6, ipaddress))
        {
            // Not a valid IP address
            return false;
        }

        if (!isValidIP(AF_INET, gateway) && !isValidIP(AF_INET6, gateway))
        {
            // Not a valid gateway
            return false;
        }

        if (!isValidPrefix(AF_INET, prefixLength) &&
            !isValidPrefix(AF_INET6, prefixLength))
        {
            // PrefixLength is not correct
            return false;
        }

        const std::string ipObjId = "addr0";
        std::string protocol;
        if (protType == HypIP::Protocol::IPv4)
        {
            protocol = "ipv4";
        }
        else if (protType == HypIP::Protocol::IPv6)
        {
            protocol = "ipv6";
        }

        std::string objPath = objectPath + "/" + protocol + "/" + ipObjId;

        addrs.erase(intfLabel);

        addrs[intfLabel] = std::make_unique<HypIPAddress>(
            bus, (objPath).c_str(), *this, protType, ipaddress, origin,
            prefixLength, gateway, "if0");
        return true;
    }

    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
