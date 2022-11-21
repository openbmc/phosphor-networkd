#include "config.h"

#include "util.hpp"

#include "config_parser.hpp"
#include "types.hpp"

#include <fmt/compile.h>
#include <fmt/format.h>
#include <sys/wait.h>

#include <cctype>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using std::literals::string_view_literals::operator""sv;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace internal
{

void executeCommandinChildProcess(stdplus::const_zstring path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();

    if (pid == 0)
    {
        execv(path.c_str(), args);
        exit(255);
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork", entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        int status;
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            {
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            fmt::memory_buffer buf;
            fmt::format_to(fmt::appender(buf), "`{}`", path);
            for (size_t i = 0; args[i] != nullptr; ++i)
            {
                fmt::format_to(fmt::appender(buf), " `{}`", args[i]);
            }
            buf.push_back('\0');
            log<level::ERR>("Unable to execute the command",
                            entry("CMD=%s", buf.data()),
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
std::unordered_set<std::string_view>
    parseInterfaces(std::string_view interfaces)
{
    std::unordered_set<std::string_view> result;
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
const std::unordered_set<std::string_view>& getIgnoredInterfaces()
{
    static auto ignoredInterfaces = parseInterfaces(getIgnoredInterfacesEnv());
    return ignoredInterfaces;
}

} // namespace internal

std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf)
{
    constexpr auto pfx = "eth"sv;
    if (!intf.starts_with(pfx))
    {
        return std::nullopt;
    }
    intf.remove_prefix(pfx.size());
    unsigned idx;
    try
    {
        idx = DecodeInt<unsigned, 10>{}(intf);
    }
    catch (...)
    {
        return std::nullopt;
    }
    if (idx == 0)
    {
        return "ethaddr";
    }
    return fmt::format(FMT_COMPILE("eth{}addr"), idx);
}

static std::optional<DHCPVal> systemdParseDHCP(std::string_view str)
{
    if (config::icaseeq(str, "ipv4"))
    {
        return DHCPVal{.v4 = true, .v6 = false};
    }
    if (config::icaseeq(str, "ipv6"))
    {
        return DHCPVal{.v4 = false, .v6 = true};
    }
    if (auto b = config::parseBool(str); b)
    {
        return DHCPVal{.v4 = *b, .v6 = *b};
    }
    return std::nullopt;
}

inline auto systemdParseLast(const config::Parser& config,
                             std::string_view section, std::string_view key,
                             auto&& fun)
{
    if (!config.getFileExists())
    {
    }
    else if (auto str = config.map.getLastValueString(section, key);
             str == nullptr)
    {
        auto err = fmt::format("Unable to get the value of {}[{}] from {}",
                               section, key, config.getFilename().native());
        log<level::NOTICE>(err.c_str(),
                           entry("FILE=%s", config.getFilename().c_str()));
    }
    else if (auto val = fun(*str); !val)
    {
        auto err = fmt::format("Invalid value of {}[{}] from {}: {}", section,
                               key, config.getFilename().native(), *str);
        log<level::NOTICE>(err.c_str(), entry("VALUE=%s", str->c_str()),
                           entry("FILE=%s", config.getFilename().c_str()));
    }
    else
    {
        return val;
    }
    return decltype(fun(std::string_view{}))(std::nullopt);
}

bool getIPv6AcceptRA(const config::Parser& config)
{
#ifdef ENABLE_IPV6_ACCEPT_RA
    constexpr bool def = true;
#else
    constexpr bool def = false;
#endif
    return systemdParseLast(config, "Network", "IPv6AcceptRA",
                            config::parseBool)
        .value_or(def);
}

DHCPVal getDHCPValue(const config::Parser& config)
{
    return systemdParseLast(config, "Network", "DHCP", systemdParseDHCP)
        .value_or(DHCPVal{.v4 = true, .v6 = true});
}

bool getDHCPProp(const config::Parser& config, std::string_view key)
{
    return systemdParseLast(config, "DHCP", key, config::parseBool)
        .value_or(true);
}

namespace mac_address
{

bool isEmpty(const ether_addr& mac)
{
    return mac == ether_addr{};
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
