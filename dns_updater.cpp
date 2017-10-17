#include "config.h"
#include "dns_updater.hpp"

#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>

#include <fstream>

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

void updateDNSEntries(const fs::path& inFile,
                      const fs::path& outFile)
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    std::fstream outStream(outFile, std::fstream::out);
    if (!outStream.is_open())
    {
        log<level::ERR>("Unable to open output file",
                        entry("FILE=%s", outFile.c_str()));
        elog<InternalFailure>();
    }

    std::fstream inStream(inFile, std::fstream::in);
    if (!inStream.is_open())
    {
        log<level::ERR>("Unable to open the input file",
                        entry("FILE=%s", inFile.c_str()));
        elog<InternalFailure>();
    }

    outStream << "### Generated through DHCP ###\n";

    for (std::string line; std::getline(inStream, line);)
    {
        auto index = line.find("DNS=");
        if(index != std::string::npos)
        {
           auto dns = line.substr(index + 4);
           outStream << "nameserver " << dns << "\n" ;
        }
    }
    return;
}

} // namespace updater
} // namespace dns
} // namespace network
} // namespace phosphor
