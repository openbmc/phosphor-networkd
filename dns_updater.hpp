#pragma once

#include <experimental/filesystem>
#include <fstream>

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

/** @brief Reads DNS entries supplied by DHCP and updates specified file
 *
 *  @param[in] in  - A stream having DNS entries supplied by DHCP
 *  @param[in] out - A stream to which to write nameserver entries
 */
void updateDNSEntries(std::istream& in, std::ostream& out);

/** @brief User callback handler invoked by inotify watcher
 *
 *  Needed to enable production and test code so that the right
 *  callback functions could be implemented
 *
 *  @param[in] inFile - File having DNS entries supplied by DHCP
 */
inline void processDNSEntries(const fs::path& inFile)
{
    std::fstream in(inFile, std::fstream::in);
    std::fstream out(RESOLV_CONF, std::fstream::out);
    return updateDNSEntries(in, out);
}

} // namepsace updater
} // namepsace dns
} // namespace network
} // namespace phosphor
