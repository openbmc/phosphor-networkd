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
    {}

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

        InAddrAny addr;
        try
        {
            switch (protType)
            {
                case HypIP::Protocol::IPv4:
                    addr = ToAddr<in_addr>{}(ipaddress);
                    break;
                case HypIP::Protocol::IPv6:
                    addr = ToAddr<in6_addr>{}(ipaddress);
                    break;
                default:
                    return false;
            }
        }
        catch (const std::exception& e)
        {
            // Invalid ip address
        }

        IfAddr ifaddr;
        try
        {
            ifaddr = {addr, prefixLength};
        }
        catch (const std::exception& e)
        {
            // Invalid prefix length
            return false;
        }

        std::string gw;
        try
        {
            if (!gateway.empty())
            {
                gw = std::to_string(ToAddr<in_addr>{}(gateway));
            }
        }
        catch (const std::exception& e)
        {
            // Invalid gateway
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
            prefixLength, gw, "if0");
        return true;
    }

    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
