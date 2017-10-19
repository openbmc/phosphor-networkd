#pragma once

#include <experimental/filesystem>

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

namespace fs = std::experimental::filesystem;

constexpr auto RESOLV_CONF = "/etc/resolv.conf";

/** @brief Reads DNS entries supplied by DHCP and updates specificed file
 *
 *  @param[in] inFile  - File having DNS entries supplied by DHCP
 *  @param[in] outFile - File to write the nameserver entries to
 */
void processDNSEntries(const fs::path& inFile,
                       const fs::path& outFile);

/** @brief Reads DNS entries supplied by DHCP and calls updater
 *
 *  Needed to enable production and test code so that the right
 *  callback functions could be implemented
 *
 *  @param[in] inFile - File having DNS entries supplied by DHCP
 */
inline void processDNSEntries(const fs::path& inFile)
{
    return processDNSEntries(inFile, RESOLV_CONF);
}

} // namepsace updater
} // namepsace dns
} // namespace network
} // namespace phosphor
