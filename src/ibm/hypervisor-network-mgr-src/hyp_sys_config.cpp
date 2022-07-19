#include "hyp_sys_config.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using InvalidArgumentMetadata = xyz::openbmc_project::Common::InvalidArgument;

using SysConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

void HypSysConfig::setHostName()
{
    auto name = getHostNameFromBios();

    SysConfigIntf::hostName(std::move(name));
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
        auto req = bus.get().new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                             BIOS_MGR_INTF, "GetAttribute");

        req.append("vmi_hostname");

        auto reply = req.call();

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return std::get<std::string>(currValue);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        lg2::error("Failed to get the hostname from bios table: {ERROR}",
                   "ERROR", ex);
    }
    return std::string();
}

void HypSysConfig::setHostNameInBios(const std::string& name)
{
    auto req = bus.get().new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                         BIOS_MGR_INTF, "SetAttribute");
    req.append("vmi_hostname");
    req.append(std::variant<std::string>(name));
    auto result = req.call();

    if (result.is_method_error())
    {
        throw std::runtime_error("Set attribute api failed");
    }
}

} // namespace network
} // namespace phosphor
