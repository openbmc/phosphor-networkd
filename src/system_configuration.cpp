#include "system_configuration.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

static constexpr char HOSTNAMED_SVC[] = "org.freedesktop.hostname1";
static constexpr char HOSTNAMED_OBJ[] = "/org/freedesktop/hostname1";
static constexpr char HOSTNAMED_INTF[] = "org.freedesktop.hostname1";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

static constexpr char propMatch[] =
    "type='signal',sender='org.freedesktop.hostname1',"
    "path='/org/freedesktop/hostname1',"
    "interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',"
    "arg0='org.freedesktop.hostname1'";

SystemConfiguration::SystemConfiguration(
    stdplus::PinnedRef<sdbusplus::bus_t> bus, stdplus::const_zstring objPath) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit),
    bus(bus),
    hostnamePropMatch(
        bus, propMatch,
        [sc = stdplus::PinnedRef(*this)](sdbusplus::message_t& m) {
            std::string intf;
            std::unordered_map<std::string, std::variant<std::string>> values;
            try
            {
                m.read(intf, values);
                auto it = values.find("Hostname");
                if (it == values.end())
                {
                    return;
                }
                sc.get().Iface::hostName(std::get<std::string>(it->second));
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(
                    fmt::format("Hostname match parsing failed: {}", e.what())
                        .c_str(),
                    entry("ERROR=%s", e.what()));
            }
        })
{
    try
    {
        std::variant<std::string> name;
        auto req =
            bus.get().new_method_call(HOSTNAMED_SVC, HOSTNAMED_OBJ,
                                      "org.freedesktop.DBus.Properties", "Get");

        req.append(HOSTNAMED_INTF, "Hostname");
        auto reply = req.call();
        reply.read(name);
        SystemConfigIntf::hostName(std::get<std::string>(name), true);
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Failed to get hostname: {}", e.what());
        log<level::ERR>(msg.c_str(), entry("ERROR=%s", e.what()));
    }

    emit_object_added();
}

std::string SystemConfiguration::hostName(std::string name)
{
    if (SystemConfigIntf::hostName() == name)
    {
        return name;
    }
    try
    {
        auto method = bus.get().new_method_call(
            HOSTNAMED_SVC, HOSTNAMED_OBJ, HOSTNAMED_INTF, "SetStaticHostname");
        method.append(name, /*interactive=*/false);
        bus.get().call_noreply(method);
        return SystemConfigIntf::hostName(std::move(name));
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Failed to set hostname: {}", e.what());
        log<level::ERR>(msg.c_str(), entry("ERROR=%s", e.what()));
    }
    return SystemConfigIntf::hostName();
}

} // namespace network
} // namespace phosphor
