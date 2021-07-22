#include "hyp_sys_config.hpp"

#include "hyp_network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using InvalidArgumentMetadata = xyz::openbmc_project::Common::InvalidArgument;

using SysConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

HypSysConfig::HypSysConfig(sdbusplus::bus::bus& bus, const std::string& objPath,
                           HypNetworkMgr& parent) :
    Iface(bus, objPath.c_str(), true),
    bus(bus), manager(parent)
{
    auto name = getHostNameFromBios();

    SysConfigIntf::hostName(name);
}

std::string HypSysConfig::hostName(std::string name)
{
    if (SysConfigIntf::hostName() == name)
    {
        return name;
    }

    name = SysConfigIntf::hostName(name);
    setHostNameInBios(name);
    return name;
}

std::string HypSysConfig::getHostNameFromBios() const
{
    try
    {
        using getAttrRetType =
            std::tuple<std::string, std::variant<std::string, int64_t>,
                       std::variant<std::string, int64_t>>;
        getAttrRetType name;
        auto method = bus.new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                          BIOS_MGR_INTF, "GetAttribute");

        method.append("vmi_hostname");

        auto reply = bus.call(method);

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return std::get<std::string>(currValue);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to get the hostname from bios table",
                        entry("ERR=%s", ex.what()));
    }
    return "";
}

void HypSysConfig::setHostNameInBios(std::string name)
{
    auto properties = bus.new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                          BIOS_MGR_INTF, "SetAttribute");
    properties.append("vmi_hostname");
    properties.append(std::variant<std::string>(name));
    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("Set attribute api failed");
    }
}

} // namespace network
} // namespace phosphor
