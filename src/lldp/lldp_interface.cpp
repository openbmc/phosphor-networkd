#include "lldp_interface.hpp"

#include "lldp_manager.hpp"

#include <arpa/inet.h>
#include <lldpctl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>

namespace phosphor
{
namespace network
{
namespace lldp
{

using namespace phosphor::logging;

constexpr auto lldpFilePath = "/etc/lldpd.conf";

Interface::Interface(sdbusplus::bus_t& bus, LLDPManager& manager,
                     const std::string& objPath, const std::string& ifname) :
    SettingsIface(bus, objPath.c_str(), SettingsIface::action::defer_emit),
    manager(manager), bus(bus), objPath(objPath), ifname(ifname)
{
    bool enabled = manager.isLLDPEnabledForInterface(ifname);
    SettingsIface::enableLLDP(enabled);
    if (enabled)
    {
        // create transmit dbus object once
        transmit = std::make_unique<TLVs>(bus, objPath + "/transmit");
        transmit->setExchangeType(TLVsIface::LLDPExchangeType::Transmit);
        refreshInterface();
    }
    this->emit_object_added();
}

bool Interface::enableLLDP(bool value)
{
    bool curr = SettingsIface::enableLLDP();
    if (curr == value)
    {
        return value;
    }

    SettingsIface::enableLLDP(value);

    lg2::info("EnableLLDP changed on {IF}: {VAL}", "IF", ifname, "VAL",
              value ? "true" : "false");

    manager.handleLLDPEnableChange(ifname, value);
    if (value)
    {
        refreshInterface();
    }
    else
    {
        // Delete the transmit & receive objects, as LLDP is disabled
        if (transmit)
        {
            lg2::info("Removing \"transmit\" object on {IF}", "IF", ifname);
            transmit.reset();
        }

        if (receive)
        {
            lg2::info("Removing \"receive\" object on {IF}", "IF", ifname);
            receive.reset();
        }
    }

    return value;
}

void Interface::updateTransmitObjProperties()
{
    // TODO: Read the transmit properties using lldpctl APIs
    // and set it to the transmit obj properties
}

void Interface::refreshInterface()
{
    auto* conn = lldpctl_new_name(lldpctl_get_default_transport(), nullptr,
                                  nullptr, nullptr);
    if (!conn)
    {
        lg2::error("Could not connect to lldpd daemon");
        return;
    }

    lldpctl_atom_t* ports = lldpctl_get_interfaces(conn);
    if (!ports)
    {
        lg2::info("lldpctl: no ports");
        lldpctl_release(conn);
        return;
    }

    // Get the interface index from /sys/class/net/<ifname>/ifindex
    int localIfIndex = -1;
    {
        std::string path = "/sys/class/net/" + ifname + "/ifindex";
        std::ifstream ifs(path);
        if (ifs)
        {
            ifs >> localIfIndex;
            lg2::debug("Interface {IF} has index {IDX}", "IF", ifname, "IDX",
                       localIfIndex);
        }
        else
        {
            lg2::warning("Unable to read ifindex for interface {IF}", "IF",
                         ifname);
        }
    }

    lldpctl_atom_t* port = nullptr;
    lldpctl_atom_foreach(ports, port)
    {
        lldpctl_atom_t* p = lldpctl_get_port(port);
        if (!p)
            continue;

        const char* pname = lldpctl_atom_get_str(p, lldpctl_k_port_name);
        if (!pname || ifname != pname)
        {
            lldpctl_atom_dec_ref(p);
            continue;
        }

        lldpctl_atom_t* neighbors =
            lldpctl_atom_get(p, lldpctl_k_port_neighbors);
        if (!neighbors)
        {
            lldpctl_atom_dec_ref(p);
            break;
        }

        lldpctl_atom_t* neigh = nullptr;
        lldpctl_atom_foreach(neighbors, neigh)
        {
            const char* chassis =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_id);
            const char* portid = lldpctl_atom_get_str(neigh, lldpctl_k_port_id);
            const char* sysname =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_name);
            const char* sysdesc =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_descr);

            std::string mgmtMac;
            const char* portSubtypeStr =
                lldpctl_atom_get_str(neigh, lldpctl_k_port_id_subtype);
            if (portSubtypeStr && std::string_view(portSubtypeStr) == "mac")
            {
                mgmtMac = portid ? portid : "";
            }

            const char* chassisSubtypeStr =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_id_subtype);
            if (mgmtMac.empty() && chassisSubtypeStr &&
                std::string_view(chassisSubtypeStr) == "mac")
            {
                mgmtMac = chassis ? chassis : "";
            }

            std::string mgmtV4;
            std::string mgmtV6;
            lldpctl_atom_t* mgmts =
                lldpctl_atom_get(neigh, lldpctl_k_chassis_mgmt);
            if (mgmts)
            {
                lldpctl_atom_t* mgmt = nullptr;
                lldpctl_atom_foreach(mgmts, mgmt)
                {
                    const char* mip =
                        lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip);
                    int ifaceIndex =
                        lldpctl_atom_get_int(mgmt, lldpctl_k_mgmt_iface_index);

                    if (mip && *mip)
                    {
                        in_addr addr4;
                        in6_addr addr6;
                        if (localIfIndex > 0)
                        {
                            if (ifaceIndex == localIfIndex)
                            {
                                if (inet_pton(AF_INET, mip, &addr4) == 1)
                                    mgmtV4 = mip;
                                else if (inet_pton(AF_INET6, mip, &addr6) == 1)
                                    mgmtV6 = mip;
                            }
                            else
                            {
                                lg2::debug(
                                    "Skipping IP {IP} on MgmtIfac: {IND} — does not match local IfIndex {LOCALIND}",
                                    "IP", mip, "IND", ifaceIndex, "LOCALIND",
                                    localIfIndex);
                            }
                        }
                        else
                        {
                            lg2::info(
                                "Local interface index could not be fetched. Assiging the IP address from lldp packet directly");
                            if (inet_pton(AF_INET, mip, &addr4) == 1)
                                mgmtV4 = mip;
                            else if (inet_pton(AF_INET6, mip, &addr6) == 1)
                                mgmtV6 = mip;
                        }
                    }
                }
                lldpctl_atom_dec_ref(mgmts);
            }

            updateOrCreateReceiveObj(
                chassis ? std::string(chassis) : std::string(),
                portid ? std::string(portid) : std::string(),
                sysname ? std::string(sysname) : std::string(),
                sysdesc ? std::string(sysdesc) : std::string(), mgmtV4, mgmtV6,
                mgmtMac);
        }

        lldpctl_atom_dec_ref(neighbors);
        lldpctl_atom_dec_ref(p);
        break;
    }

    lldpctl_atom_dec_ref(ports);
    lldpctl_release(conn);
}

void Interface::updateOrCreateReceiveObj(
    const std::string& chassisId, const std::string& portId,
    const std::string& sysName, const std::string& sysDesc,
    const std::string& mgmtIPv4, const std::string& mgmtIPv6,
    const std::string& mgmtMac)
{
    bool neighborChanged = false;
    if (receive)
    {
        TLVs& tlv = *receive;

        // Check if any TLV value from the current lldp packet
        // is different from what is on dbus
        neighborChanged = (tlv.TLVsIface::chassisId() != chassisId) ||
                          (tlv.TLVsIface::portId() != portId) ||
                          (tlv.TLVsIface::managementAddressIPv4() != mgmtIPv4) ||
                          (tlv.TLVsIface::managementAddressIPv6() != mgmtIPv6) ||
                          (tlv.TLVsIface::managementAddressMAC() != mgmtMac);

        if (neighborChanged)
        {
            // If TLV values are changed, remove existing receive object before
            // recreating
            lg2::info(
                "Neighbor TLV changed on {IF}. Removing existing \"receive\" object.",
                "IF", ifname);
            receive.reset();
        }
        else
        {
            // Check if there are any changes in other property values
            // If yes, update the current receive object
            bool otherPropChanged =
                (tlv.TLVsIface::systemName() != sysName) ||
                (tlv.TLVsIface::systemDescription() != sysDesc);
            if (otherPropChanged)
            {
                tlv.setSystemName(sysName);
                tlv.setSystemDescription(sysDesc);
            }
            return;
        }
    }

    std::string path = objPath + "/receive";

    lg2::info("Creating \"receive\" dbus object on {IF} at {PATH}", "IF",
              ifname, "PATH", path);

    try
    {
        auto tlvObj = std::make_unique<TLVs>(
            bus, path, chassisId.empty() ? "" : chassisId,
            TLVsIface::IEEE802IdSubtype::NotTransmitted,
            portId.empty() ? "" : portId,
            TLVsIface::IEEE802IdSubtype::NotTransmitted,
            sysName.empty() ? "" : sysName, sysDesc.empty() ? "" : sysDesc,
            std::vector<TLVsIface::SystemCapabilities>(),
            mgmtIPv4.empty() ? "" : mgmtIPv4, mgmtIPv6.empty() ? "" : mgmtIPv6,
            mgmtMac.empty() ? "" : mgmtMac, 0,
            TLVsIface::LLDPExchangeType::Receive);
        receive = std::move(tlvObj);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to create \"receive\" dbus object. Error: {ERR}",
                   "ERR", e.what());
    }
}

} // namespace lldp
} // namespace network
} // namespace phosphor
