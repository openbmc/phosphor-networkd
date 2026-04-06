#include "config.h"

#include "firewall_configuration.hpp"

#include "config_parser.hpp"
#include "ethernet_interface.hpp"
#include "network_manager.hpp"
#include "types.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <fmt/compile.h>
#include <fmt/format.h>
#include <sys/stat.h>
#include <unistd.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstdlib>
#include <fstream>
#include <iostream>

namespace phosphor
{
namespace network
{
using namespace phosphor::network;
using namespace phosphor::logging;
namespace firewall
{

Configuration::Configuration(sdbusplus::bus_t& bus, stdplus::const_zstring path,
                             Manager& parent) :
    Iface(bus, path.c_str(), Iface::action::defer_emit), bus(bus),
    manager(parent)
{
    // Ensure custom rules directory exists
    fs::create_directories(CUSTOM_IPTABLES_DIR);

    // Initial Rules File Path
    execute("/usr/sbin/iptables", "iptables", "-F");
    execute("/usr/sbin/ip6tables", "ip6tables", "-F");
    rulesLists.push_back(
        fmt::format("{}/{}", CUSTOM_IPTABLES_DIR, IPTABLES_RULES));
    rulesLists.push_back(
        fmt::format("{}/{}", CUSTOM_IPTABLES_DIR, IP6TABLES_RULES));

    // Restore Custom Rules
    restoreConfigurationFile<in_addr>();
    restoreConfigurationFile<in6_addr>();
    emit_object_added();
}

/** @brief Implementation for AddRule
 *  Add the rule with incoming parameters
 */
int16_t Configuration::addRule(
    FirewallIface::Target target, uint8_t control,
    FirewallIface::Protocol protocol, std::string startIPAddress,
    std::string endIPAddress, uint16_t startPort, uint16_t endPort,
    std::string macAddress, std::string startTime, std::string stopTime,
    FirewallIface::IP IPver)
{
    int16_t ret = addRuleDetailSteps(target, control, protocol, startIPAddress,
                                     endIPAddress, startPort, endPort,
                                     macAddress, startTime, stopTime, IPver);

    if (ret < 0)
    {
        log<level::ERR>("Failed to add rule\n");
        return ret;
    }

    writeConfigurationFile<in_addr>(false);
    writeConfigurationFile<in6_addr>(false);

    return ret;
}

/** @brief Implementation for DelRule
 *  Delete the rule with incoming parameters
 */
int16_t Configuration::delRule(
    FirewallIface::Target target, uint8_t control,
    FirewallIface::Protocol protocol, std::string startIPAddress,
    std::string endIPAddress, uint16_t startPort, uint16_t endPort,
    std::string macAddress, std::string startTime, std::string stopTime,
    FirewallIface::IP IPver)
{
    int16_t ret;
    if (control > (uint8_t)ControlBit::TIMEOUT &&
        (control & (uint8_t)ControlBit::IP) == 0 &&
        (control & (uint8_t)ControlBit::MAC) == 0 &&
        (control & (uint8_t)ControlBit::PORT) == 0 &&
        (control & (uint8_t)ControlBit::PROTOCOL) == 0)
    {
        return -1;
    } // if

    if (!endIPAddress.empty() &&
        !((startIPAddress.find(":") == std::string::npos &&
           endIPAddress.find(":") == std::string::npos) ||
          (startIPAddress.find(".") == std::string::npos &&
           endIPAddress.find(".") == std::string::npos)))
    {
        log<level::ERR>(
            fmt::format(
                "Type of IP Range are different. Start IP Address: {} End IP Address: {}\n",
                startIPAddress, endIPAddress)
                .c_str());
        return -1;
    } // if

    if (IPver != FirewallIface::IP::IPV4 && IPver != FirewallIface::IP::IPV6 &&
        IPver != FirewallIface::IP::BOTH)
    {
        IPver = FirewallIface::IP::BOTH;
    } // if

    std::string params = fmt::format(
        "-D INPUT -j {}",
        target == FirewallIface::Target::ACCEPT ? "ACCEPT" : "DROP");

    if (startIPAddress.find(":") == std::string::npos)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) ==
            (uint8_t)ControlBit::PROTOCOL)
        {
            params = params + " -p " +
                     (protocol == FirewallIface::Protocol::TCP    ? "tcp"
                      : protocol == FirewallIface::Protocol::UDP  ? "udp"
                      : protocol == FirewallIface::Protocol::ICMP ? "icmp"
                                                                  : "all");
        }
    } // if
    else if (startIPAddress.find(":") != std::string::npos)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) ==
            (uint8_t)ControlBit::PROTOCOL)
        {
            params = params + " -p " +
                     (protocol == FirewallIface::Protocol::TCP    ? "tcp"
                      : protocol == FirewallIface::Protocol::UDP  ? "udp"
                      : protocol == FirewallIface::Protocol::ICMP ? "icmpv6"
                                                                  : "all");
        } // if
    }

    if ((control & (uint8_t)ControlBit::IP) == (uint8_t)ControlBit::IP)
    {
        std::variant<in_addr, in6_addr> addr1, addr2;
        if (startIPAddress.find(":") != std::string::npos &&
            endIPAddress.find(":") != std::string::npos)
        {
            in6_addr tmp1, tmp2;
            inet_pton(AF_INET6, startIPAddress.c_str(), &tmp1);
            if (!endIPAddress.empty())
            {
                inet_pton(AF_INET6, endIPAddress.c_str(), &tmp2);
                for (int i = 0; i < 4; i++)
                {
                    try
                    {
                        if (ntohl(tmp1.s6_addr32[i]) > ntohl(tmp2.s6_addr32[i]))
                        {
                            log<level::ERR>(
                                fmt::format(
                                    "Incorrect IP Range. Start IP Address: {} End IP Address: {}\n",
                                    startIPAddress, endIPAddress)
                                    .c_str());
                            return -1;
                        }
                    }
                    catch (std::exception& e)
                    {
                        log<level::ERR>(
                            fmt::format("error = {}\n", e.what()).c_str());
                    }
                }
            }

            addr1 = tmp1;
            addr2 = tmp2;
        } // if
        else if (startIPAddress.find(".") != std::string::npos &&
                 endIPAddress.find(".") != std::string::npos)
        {
            in_addr tmp1, tmp2;
            inet_pton(AF_INET, startIPAddress.c_str(), &tmp1);
            if (!endIPAddress.empty())
            {
                inet_pton(AF_INET, endIPAddress.c_str(), &tmp2);
                if (ntohl(tmp1.s_addr) > ntohl(tmp2.s_addr))
                {
                    log<level::ERR>(
                        fmt::format(
                            "Incorrect IP Range. Start IP Address: {} End IP Address: {}\n",
                            startIPAddress, endIPAddress)
                            .c_str());
                    return -1;
                }
            }
            addr1 = tmp1;
            addr2 = tmp2;
        }

        if (endIPAddress.empty() ||
            memcmp(&addr1, &addr2, sizeof(std::variant<in_addr, in6_addr>)) ==
                0)
        {
            params += " -s " + startIPAddress;
        } // if
        else
        {
            params += fmt::format(" -m iprange --src-range {}-{} ",
                                  startIPAddress, endIPAddress);
            ;
        }
    } // if

    if ((control & (uint8_t)ControlBit::PORT) == (uint8_t)ControlBit::PORT)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) !=
                (uint8_t)ControlBit::PROTOCOL ||
            protocol == FirewallIface::Protocol::ICMP)
        {
            return -1;
        }
        params += fmt::format(" --dport {}:{} ", startPort,
                              endPort != 0 ? endPort : MAX_PORT_NUM);
    } // if

    if ((control & (uint8_t)ControlBit::MAC) == (uint8_t)ControlBit::MAC)
    {
        params += " -m mac --mac-source " + macAddress;
    } // if

    if ((control & (uint8_t)ControlBit::TIMEOUT) ==
        (uint8_t)ControlBit::TIMEOUT)
    {
        if (!startTime.empty())
            params += " -m time --datestart " + startTime;
        if (!stopTime.empty())
            params += " -m time --datestop " + stopTime;
    } // if

    if ((control & (uint8_t)ControlBit::IP) != (uint8_t)ControlBit::IP &&
        IPver == FirewallIface::IP::BOTH)
    {
        ret = runSystemCommand("iptables", params);
        ret |= runSystemCommand("ip6tables", params);
    }
    else if ((((control & (uint8_t)ControlBit::IP) !=
               (uint8_t)ControlBit::IP) &&
              IPver == FirewallIface::IP::IPV4) ||
             (startIPAddress.find(":") == std::string::npos &&
              IPver == FirewallIface::IP::BOTH) ||
             (startIPAddress.find(":") == std::string::npos &&
              IPver == FirewallIface::IP::IPV4))
    {
        ret = runSystemCommand("iptables", params);
    }
    else if ((((control & (uint8_t)ControlBit::IP) !=
               (uint8_t)ControlBit::IP) &&
              IPver == FirewallIface::IP::IPV6) ||
             (startIPAddress.find(":") != std::string::npos &&
              IPver == FirewallIface::IP::BOTH) ||
             (startIPAddress.find(":") != std::string::npos &&
              IPver == FirewallIface::IP::IPV6))
    {
        ret = runSystemCommand("ip6tables", params);
    }
    else
    {
        log<level::ERR>("Illegal parameter\n");
        return -1;
    }

    writeConfigurationFile<in_addr>(false);
    writeConfigurationFile<in6_addr>(false);
    return ret;
}

/** @brief Implementation for FlushAll
 *  Delete all the rules
 */
int16_t Configuration::flushAll(FirewallIface::IP ip)
{
    switch (ip)
    {
        case FirewallIface::IP::IPV4:
            execute("/usr/sbin/iptables", "iptables", "-F");
            writeConfigurationFile<in_addr>(false);
            break;
        case FirewallIface::IP::IPV6:
            execute("/usr/sbin/ip6tables", "ip6tables", "-F");
            writeConfigurationFile<in6_addr>(false);
            break;
        case FirewallIface::IP::BOTH:
            execute("/usr/sbin/iptables", "iptables", "-F");
            execute("/usr/sbin/ip6tables", "ip6tables", "-F");
            writeConfigurationFile<in_addr>(false);
            writeConfigurationFile<in6_addr>(false);
            break;
        default:
            log<level::INFO>("Error input.");
            return -1;
    }

    return 0;
}

/** @brief Implementation for GetRules
 *  Get all the rules
 */
std::vector<IPTableElementTuple> Configuration::getRules(FirewallIface::IP ip)
{
    std::ifstream ruleFile;
    std::vector<IPTableElementTuple> returnVec;
#if 1
    if (ip == FirewallIface::IP::IPV4)
        writeConfigurationFile<in_addr>(false);
    else if (ip == FirewallIface::IP::IPV6)
        writeConfigurationFile<in6_addr>(false);

    for (auto elememt : rulesLists)
    {
        if (ip == FirewallIface::IP::IPV4 &&
            elememt.find(IP6TABLES_RULES) != std::string::npos)
            continue;
        if (ip == FirewallIface::IP::IPV6 &&
            elememt.find(IPTABLES_RULES) != std::string::npos)
            continue;
        ruleFile.open(elememt, std::fstream::in);
        if (ruleFile.is_open())
        {
            for (std::string line; std::getline(ruleFile, line);)
            {
                if (!line.starts_with("-A"))
                    continue;
                if (line == "COMMIT")
                    break;
                std::vector<std::string> vec = splitStr(line, " ");
                IPTableElementTuple element;
                std::get<3>(element) = FirewallIface::Protocol::ALL;
                for (size_t i = 0; i < vec.size(); i++)
                {
                    if (vec.at(i) == "-j")
                    {
                        i++;
                        std::get<1>(element) =
                            vec.at(i) == "ACCEPT"
                                ? FirewallIface::Target::ACCEPT
                                : FirewallIface::Target::DROP;
                    } // else if
                    else if (vec.at(i) == "-p")
                    {
                        i++;
                        std::get<3>(element) =
                            vec.at(i) == "tcp"   ? FirewallIface::Protocol::TCP
                            : vec.at(i) == "udp" ? FirewallIface::Protocol::UDP
                            : (vec.at(i) == "icmp" || vec.at(i) == "ipv6-icmp")
                                ? FirewallIface::Protocol::ICMP
                                : FirewallIface::Protocol::ALL;
                        std::get<2>(element) |= (uint8_t)ControlBit::PROTOCOL;
                    } // else if
                    else if (vec.at(i) == "-s")
                    {
                        i++;
                        std::get<4>(element) = vec.at(i);
                        std::get<2>(element) |= (uint8_t)ControlBit::IP;
                    } // else if
                    else if (vec.at(i) == "--src-range")
                    {
                        i++;
                        auto ips = splitStr(vec.at(i), "-");
                        std::get<4>(element) = ips.at(0);
                        std::get<5>(element) = ips.at(1);
                        std::get<2>(element) |= (uint8_t)ControlBit::IP;
                    } // else if
                    else if (vec.at(i) == "--dport")
                    {
                        i++;
                        if (vec.at(i).find(":") != std::string::npos)
                        {
                            auto ports = splitStr(vec.at(i), ":");
                            std::get<6>(element) = std::stoi(ports.at(0));
                            std::get<7>(element) = std::stoi(ports.at(1));
                        } // if
                        else
                        {
                            std::get<6>(element) = std::stoi(vec.at(i));
                            std::get<7>(element) = std::stoi(vec.at(i));
                        } // else
                        std::get<2>(element) |= (uint8_t)ControlBit::PORT;
                    } // else if
                    else if (vec.at(i) == "--mac-source")
                    {
                        i++;
                        std::get<8>(element) = vec.at(i);
                        std::get<2>(element) |= (uint8_t)ControlBit::MAC;
                    } // else if
                    else if (vec.at(i) == "--datestart")
                    {
                        i++;
                        std::get<9>(element) = vec.at(i);
                        std::get<2>(element) |= (uint8_t)ControlBit::TIMEOUT;
                    } // else if
                    else if (vec.at(i) == "--datestop")
                    {
                        i++;
                        std::get<10>(element) = vec.at(i);
                        std::get<2>(element) |= (uint8_t)ControlBit::TIMEOUT;
                    } // else if
                } // for
                returnVec.push_back(element);
            }
            ruleFile.close();
        }
    }

#endif
    return returnVec;
}

/** @brief Implementation for ReorderRules
 *  Reorder the rules
 */
int16_t Configuration::reorderRules(FirewallIface::IP ip,
                                    std::vector<IPTableElementTuple> rules)
{
    const char* command;
    const char* logFilePath;
    std::string logFilePathStr;

    // BackUp iptables/ip6tables
    if (ip == FirewallIface::IP::IPV4)
    {
        command = "iptables-save";
        logFilePathStr =
            std::string(TEMP_DIR) + "/" + std::string(IPTABLES_RULES);
        logFilePath = logFilePathStr.c_str();
        executeCommandAndLog(command, logFilePath);
    }
    else
    {
        command = "ip6tables-save";
        logFilePathStr =
            std::string(TEMP_DIR) + "/" + std::string(IP6TABLES_RULES);
        logFilePath = logFilePathStr.c_str();
        executeCommandAndLog(command, logFilePath);
    }

    // Flush all the rules
    int16_t result = flushAll(ip);
    if (result < 0)
    {
        log<level::ERR>("Failed to flush rules\n");
        return result;
    }

    // Add new order rules
    for (const auto& rule : rules)
    {
        result = addRuleDetailSteps(
            std::get<1>(rule),  // FirewallIface::Target target
            std::get<2>(rule),  // uint8_t control
            std::get<3>(rule),  // FirewallIface::Protocol protocol
            std::get<4>(rule),  // std::string startIPAddress
            std::get<5>(rule),  // std::string endIPAddress
            std::get<6>(rule),  // uint16_t startPort
            std::get<7>(rule),  // uint16_t endPort
            std::get<8>(rule),  // std::string macAddress
            std::get<9>(rule),  // std::string startTime
            std::get<10>(rule), // std::string stopTime
            ip);                // FirewallIface::IP IPver

        if (result != 0)
        {
            log<level::ERR>("Failed to add rule\n");

            int16_t result_ = flushAll(ip);
            if (result_ < 0)
            {
                log<level::ERR>("Failed to flush rules\n");
                return result_;
            }

            if (ip == FirewallIface::IP::IPV4)
            {
                if (fs::exists(
                        fmt::format("{}/{}", TEMP_DIR, IPTABLES_RULES).c_str()))
                    (void)runSystemCommand(
                        "iptables-restore",
                        fmt::format("--noflush {}/{}", TEMP_DIR, IPTABLES_RULES)
                            .c_str());
            }
            else
            {
                if (fs::exists(fmt::format("{}/{}", TEMP_DIR, IP6TABLES_RULES)
                                   .c_str()))
                    (void)runSystemCommand(
                        "ip6tables-restore",
                        fmt::format("--noflush {}/{}", TEMP_DIR,
                                    IP6TABLES_RULES)
                            .c_str());
            }

            return result;
        }
    }

    writeConfigurationFile<in_addr>(false);
    writeConfigurationFile<in6_addr>(false);

    return result;
}

int16_t Configuration::addRuleDetailSteps(
    FirewallIface::Target target, uint8_t control,
    FirewallIface::Protocol protocol, std::string startIPAddress,
    std::string endIPAddress, uint16_t startPort, uint16_t endPort,
    std::string macAddress, std::string startTime, std::string stopTime,
    FirewallIface::IP IPver)
{
    int16_t ret = 0;
    auto customIPv4rules = 0, customIPv6rules = 0;
    if (control > (uint8_t)ControlBit::TIMEOUT &&
        (control & (uint8_t)ControlBit::IP) == 0 &&
        (control & (uint8_t)ControlBit::MAC) == 0 &&
        (control & (uint8_t)ControlBit::PORT) == 0 &&
        (control & (uint8_t)ControlBit::PROTOCOL) == 0)
    {
        return -1;
    } // if

    for (const auto& elementTuple : getRules(FirewallIface::IP::IPV4))
    {
        if (!std::get<0>(elementTuple))
            customIPv4rules++;
    }
    for (const auto& elementTuple : getRules(FirewallIface::IP::IPV6))
    {
        if (!std::get<0>(elementTuple))
            customIPv6rules++;
    }

    if (!startIPAddress.empty())
    {
        if (startIPAddress.find(".") != std::string::npos &&
            customIPv4rules >= MAX_RULE_NUM)
        {
            return -1;
        } // if
        else if (startIPAddress.find(":") != std::string::npos &&
                 customIPv6rules >= MAX_RULE_NUM)
        {
            return -1;
        } // else if
    }
    else if (customIPv4rules >= MAX_RULE_NUM || customIPv6rules >= MAX_RULE_NUM)
    {
        return -1;
    }

    if (!endIPAddress.empty() &&
        !((startIPAddress.find(":") == std::string::npos &&
           endIPAddress.find(":") == std::string::npos) ||
          (startIPAddress.find(".") == std::string::npos &&
           endIPAddress.find(".") == std::string::npos)))
    {
        log<level::ERR>(
            fmt::format(
                "Type of IP Range are different. Start IP Address: {} End IP Address: {}\n",
                startIPAddress, endIPAddress)
                .c_str());
        return -1;
    } // if

    if (IPver != FirewallIface::IP::IPV4 && IPver != FirewallIface::IP::IPV6 &&
        IPver != FirewallIface::IP::BOTH)
    {
        IPver = FirewallIface::IP::BOTH;
    } // if

    std::string params = fmt::format(
        "-A INPUT -j {}",
        target == FirewallIface::Target::ACCEPT ? "ACCEPT" : "DROP");

    if (startIPAddress.find(":") == std::string::npos)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) ==
            (uint8_t)ControlBit::PROTOCOL)
        {
            params = params + " -p " +
                     (protocol == FirewallIface::Protocol::TCP    ? "tcp"
                      : protocol == FirewallIface::Protocol::UDP  ? "udp"
                      : protocol == FirewallIface::Protocol::ICMP ? "icmp"
                                                                  : "all");
        } // if
    } // if
    else if (startIPAddress.find(":") != std::string::npos)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) ==
            (uint8_t)ControlBit::PROTOCOL)
        {
            params = params + " -p " +
                     (protocol == FirewallIface::Protocol::TCP    ? "tcp"
                      : protocol == FirewallIface::Protocol::UDP  ? "udp"
                      : protocol == FirewallIface::Protocol::ICMP ? "icmpv6"
                                                                  : "all");
        } // if
    }

    if ((control & (uint8_t)ControlBit::IP) == (uint8_t)ControlBit::IP)
    {
        std::variant<in_addr, in6_addr> addr1, addr2;
        if (startIPAddress.find(":") != std::string::npos &&
            endIPAddress.find(":") != std::string::npos)
        {
            in6_addr tmp1, tmp2;
            inet_pton(AF_INET6, startIPAddress.c_str(), &tmp1);
            if (!endIPAddress.empty())
            {
                inet_pton(AF_INET6, endIPAddress.c_str(), &tmp2);
                for (int i = 0; i < 4; i++)
                {
                    try
                    {
                        if (ntohl(tmp1.s6_addr32[i]) > ntohl(tmp2.s6_addr32[i]))
                        {
                            log<level::ERR>(
                                fmt::format(
                                    "Incorrect IP Range. Start IP Address: {} End IP Address: {}\n",
                                    startIPAddress, endIPAddress)
                                    .c_str());
                            return -1;
                        }
                    }
                    catch (std::exception& e)
                    {
                        log<level::ERR>(
                            fmt::format("error = {}\n", e.what()).c_str());
                    }
                }
            }

            addr1 = tmp1;
            addr2 = tmp2;
        } // if
        else if (startIPAddress.find(".") != std::string::npos &&
                 endIPAddress.find(".") != std::string::npos)
        {
            in_addr tmp1, tmp2;
            inet_pton(AF_INET, startIPAddress.c_str(), &tmp1);
            if (!endIPAddress.empty())
            {
                inet_pton(AF_INET, endIPAddress.c_str(), &tmp2);
                if (ntohl(tmp1.s_addr) > ntohl(tmp2.s_addr))
                {
                    log<level::ERR>(
                        fmt::format(
                            "Incorrect IP Range. Start IP Address: {} End IP Address: {}\n",
                            startIPAddress, endIPAddress)
                            .c_str());
                    return -1;
                }
            }
            addr1 = tmp1;
            addr2 = tmp2;
        }

        if (endIPAddress.empty() ||
            memcmp(&addr1, &addr2, sizeof(std::variant<in_addr, in6_addr>)) ==
                0)
        {
            params += " -s " + startIPAddress;
        } // if
        else
        {
            params += fmt::format(" -m iprange --src-range {}-{} ",
                                  startIPAddress, endIPAddress);
            ;
        }
    } // if

    if ((control & (uint8_t)ControlBit::PORT) == (uint8_t)ControlBit::PORT)
    {
        if ((control & (uint8_t)ControlBit::PROTOCOL) !=
                (uint8_t)ControlBit::PROTOCOL ||
            protocol == FirewallIface::Protocol::ICMP || startPort == 0)
        {
            return -1;
        }

        params += fmt::format(" --dport {}:{} ", startPort,
                              endPort != 0 ? endPort : MAX_PORT_NUM);
    } // if

    if ((control & (uint8_t)ControlBit::MAC) == (uint8_t)ControlBit::MAC)
    {
        params += " -m mac --mac-source " + macAddress;
    } // if

    if ((control & (uint8_t)ControlBit::TIMEOUT) ==
        (uint8_t)ControlBit::TIMEOUT)
    {
        if (startTime.empty() || stopTime.empty())
        {
            return -1;
        }
        if (!startTime.empty())
            params += " -m time --datestart " + startTime;
        if (!stopTime.empty())
            params += " -m time --datestop " + stopTime;
    } // if

    if ((control & (uint8_t)ControlBit::IP) != (uint8_t)ControlBit::IP &&
        IPver == FirewallIface::IP::BOTH)
    {
        ret = runSystemCommand("iptables", params);
        if (auto index = params.find("icmp"); index != std::string::npos)
            params.replace(index, 4, "icmpv6");
        ret |= runSystemCommand("ip6tables", params);
    } // if
    else if ((((control & (uint8_t)ControlBit::IP) !=
               (uint8_t)ControlBit::IP) &&
              IPver == FirewallIface::IP::IPV4) ||
             (startIPAddress.find(":") == std::string::npos &&
              IPver == FirewallIface::IP::BOTH) ||
             (startIPAddress.find(":") == std::string::npos &&
              IPver == FirewallIface::IP::IPV4))
    {
        ret = runSystemCommand("iptables", params);
    }
    else if ((((control & (uint8_t)ControlBit::IP) !=
               (uint8_t)ControlBit::IP) &&
              IPver == FirewallIface::IP::IPV6) ||
             (startIPAddress.find(":") != std::string::npos &&
              IPver == FirewallIface::IP::BOTH) ||
             (startIPAddress.find(":") != std::string::npos &&
              IPver == FirewallIface::IP::IPV6))
    {
        ret = runSystemCommand("ip6tables", params);
    }
    else
    {
        log<level::ERR>("Illegal parameter\n");
        return -1;
    }

    return ret;
}

template <typename T>
void Configuration::writeConfigurationFile(bool isInit)
{
    (void)isInit;
    const char* command;
    const char* logFilePath;
    std::string logFilePathStr;

    if (typeid(T) == typeid(in6_addr))
    {
        command = "ip6tables-save";
        logFilePathStr = std::string(CUSTOM_IPTABLES_DIR) + "/" +
                         std::string(IP6TABLES_RULES);
        logFilePath = logFilePathStr.c_str();
        executeCommandAndLog(command, logFilePath);
    } // if
    else
    {
        command = "iptables-save";
        logFilePathStr = std::string(CUSTOM_IPTABLES_DIR) + "/" +
                         std::string(IPTABLES_RULES);
        logFilePath = logFilePathStr.c_str();
        executeCommandAndLog(command, logFilePath);
    } // else
}

template <typename T>
void Configuration::restoreConfigurationFile()
{
    if (typeid(T) == typeid(in6_addr))
    {
        if (fs::exists(
                fmt::format("{}/{}", CUSTOM_IPTABLES_DIR, IP6TABLES_RULES)
                    .c_str()))
            (void)runSystemCommand(
                "ip6tables-restore",
                fmt::format("--noflush {}/{}", CUSTOM_IPTABLES_DIR,
                            IP6TABLES_RULES)
                    .c_str());
    } // if
    else
    {
        if (fs::exists(fmt::format("{}/{}", CUSTOM_IPTABLES_DIR, IPTABLES_RULES)
                           .c_str()))
            (void)runSystemCommand(
                "iptables-restore",
                fmt::format("--noflush {}/{}", CUSTOM_IPTABLES_DIR,
                            IPTABLES_RULES)
                    .c_str());
    } // else
}

} // namespace firewall
} // namespace network
} // namespace phosphor
