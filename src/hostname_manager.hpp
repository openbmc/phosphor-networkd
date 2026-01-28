#pragma once

#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>

#include <filesystem>
#include <string>

namespace phosphor
{
namespace network
{

class Manager;

/** @class HostnameManager
 *  @brief Generates and manages unique BMC hostname
 *  @details Sets unique hostname on first boot by appending either
 *           the BMC serial number or MAC address to the default hostname.
 */
class HostnameManager
{
  public:
    HostnameManager() = delete;
    HostnameManager(const HostnameManager&) = delete;
    HostnameManager& operator=(const HostnameManager&) = delete;
    HostnameManager(HostnameManager&&) = delete;
    HostnameManager& operator=(HostnameManager&&) = delete;

    explicit HostnameManager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                             stdplus::PinnedRef<Manager> manager);

    /** @brief Checks if this is first boot and sets unique hostname
     */
    void initialize();

  private:
    stdplus::PinnedRef<sdbusplus::bus_t> bus;
    stdplus::PinnedRef<Manager> manager;

    static constexpr const char* firstBootFile =
        "/var/lib/phosphor-networkd-hostname-set";

    /** @brief Check if this is the first boot
     *  @return true if first boot, false otherwise
     */
    bool isFirstBoot() const;

    /** @brief Mark that hostname has been set */
    void markHostnameSet();

    /** @brief Get BMC serial number from inventory
     *  @return Serial number string, or empty if not found
     */
    std::string getBmcSerialNumber();

    /** @brief Get MAC address from first network interface
     *  @return MAC address string, or empty if not found
     */
    std::string getMacAddress();

    /** @brief Set the system hostname
     *  @param[in] hostname - The hostname to set
     *  @return true if successful, false otherwise
     */
    bool setHostname(const std::string& hostname);

    /** @brief Get current hostname
     *  @return Current hostname string
     */
    std::string getCurrentHostname();

    /** @brief Generate and set unique hostname */
    void setUniqueHostname();
};

} // namespace network
} // namespace phosphor
