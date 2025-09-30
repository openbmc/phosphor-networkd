#include "lldp_interface.hpp"

#include "lldp_manager.hpp"

#include <lldpctl.h>

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
    if (!value)
    {
        // Delete the transmit object, as LLDP is disabled
        if (transmit)
        {
            lg2::info("Removing \"transmit\" object on {IF}", "IF", ifname);
            transmit.reset();
        }
    }
    return value;
}

void Interface::updateTransmitObjProperties()
{
    // TODO: Read the transmit properties using lldpctl APIs
    // and set it to the transmit obj properties
}

} // namespace lldp
} // namespace network
} // namespace phosphor
