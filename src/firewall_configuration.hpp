#pragma once

#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Network/FirewallConfiguration/server.hpp>

#include <filesystem>

namespace phosphor
{
namespace network
{
class Manager; // forward declaration of network manager

namespace firewall
{

namespace fs = std::filesystem;
using FirewallIface =
    sdbusplus::xyz::openbmc_project::Network::server::FirewallConfiguration;
using Iface = sdbusplus::server::object_t<FirewallIface>;
using IPTableElementTuple =
    std::tuple<bool, FirewallIface::Target, uint8_t, FirewallIface::Protocol,
               std::string, std::string, uint16_t, uint16_t, std::string,
               std::string, std::string>;

constexpr auto CUSTOM_IPTABLES_DIR = "/etc/interface/iptables";
constexpr auto TEMP_DIR = "/tmp";
constexpr auto IPTABLES_RULES = "iptables.rules";
constexpr auto IP6TABLES_RULES = "ip6tables.rules";

constexpr auto MAX_PORT_NUM = 65535;
constexpr auto MAX_RULE_NUM = 64;

enum class ControlBit
{
    PROTOCOL = 0x01,
    IP = 0x02,
    PORT = 0x04,
    MAC = 0x08,
    TIMEOUT = 0x10,
};

class Configuration : Iface
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor to avoid nullptrs.
     *         - Copy operations due to internal unique_ptr.
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - Destructor.
     */
    Configuration() = delete;
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;
    ~Configuration() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Configuration(sdbusplus::bus_t& bus, stdplus::const_zstring path,
                  Manager& parent);

    /** @brief Implementation for AddRule
     *  Add the rule with incoming parameters
     *
     *  @param[in] target -
     *  @param[in] control -
     *  @param[in] protocol -
     *  @param[in] startIPAddress -
     *  @param[in] endIPAddress -
     *  @param[in] startPort -
     *  @param[in] endPort -
     *  @param[in] macAddress -
     *  @param[in] startTime -
     *  @param[in] stop -
     *  @param[in] IPver -
     *
     *  @return result[int16_t] -
     */
    int16_t addRule(Target target, uint8_t control, Protocol protocol,
                    std::string startIPAddress, std::string endIPAddress,
                    uint16_t startPort, uint16_t endPort,
                    std::string macAddress, std::string startTime,
                    std::string stop, IP IPver) override;
    /** @brief Implementation for DelRule
     *  Delete the rule with incoming parameters
     *
     *  @param[in] target -
     *  @param[in] control -
     *  @param[in] protocol -
     *  @param[in] startIPAddress -
     *  @param[in] endIPAddress -
     *  @param[in] startPort -
     *  @param[in] endPort -
     *  @param[in] macAddress -
     *  @param[in] startTime -
     *  @param[in] stop -
     *  @param[in] IPver -
     *
     *  @return result[int16_t] -
     */
    int16_t delRule(Target target, uint8_t control, Protocol protocol,
                    std::string startIPAddress, std::string endIPAddress,
                    uint16_t startPort, uint16_t endPort,
                    std::string macAddress, std::string startTime,
                    std::string stop, IP IPver) override;
    /** @brief Implementation for FlushAll
     *  Delete all the rules according to IPv4, IPv6 or both
     *
     *  @param[in] ip -
     *
     *  @return result[int16_t] -
     */
    int16_t flushAll(IP ip) override;
    /** @brief Implementation for GetRules
     *  Get all the rules
     *
     *  @return rules[std::vector<std::tuple<bool, Target, uint8_t, Protocol,
     * std::string, std::string, uint16_t, uint16_t, std::string, std::string,
     * std::string>>] -
     */
    std::vector<IPTableElementTuple> getRules(IP ip) override;
    /** @brief Implementation for ReorderRules
     *  Reorder the rules
     *
     *  @param[in] ip -
     *  @param[in] rules -
     *
     *  @return result[int16_t] -
     */
    int16_t reorderRules(IP ip,
                         std::vector<IPTableElementTuple> rules) override;

    int16_t addRuleDetailSteps(
        FirewallIface::Target target, uint8_t control,
        FirewallIface::Protocol protocol, std::string startIPAddress,
        std::string endIPAddress, uint16_t startPort, uint16_t endPort,
        std::string macAddress, std::string startTime, std::string stopTime,
        FirewallIface::IP IPver);

    template <typename T>
    void writeConfigurationFile(bool isInit);

    template <typename T>
    void restoreConfigurationFile();

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Network Manager object. */
    stdplus::PinnedRef<Manager> manager;
    std::vector<std::string> rulesLists;
}; // class Configuration
} // namespace firewall
} // namespace network
} // namespace phosphor
