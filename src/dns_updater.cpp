#include "dns_updater.hpp"

#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

void updateDNSEntries(const fs::path& inFile, const fs::path& outFile)
{
    using namespace phosphor::logging;
    PHOSPHOR_LOG2_USING_WITH_FLAGS;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    std::fstream outStream(outFile, std::fstream::out);
    if (!outStream.is_open())
    {
        error("Unable to open output file {FILE}", "FILE", outFile);
        elog<InternalFailure>();
    }

    std::fstream inStream(inFile, std::fstream::in);
    if (!inStream.is_open())
    {
        error("Unable to open the input file {FILE}", "FILE", inFile);
        elog<InternalFailure>();
    }

    outStream << "### Generated by phosphor-networkd ###\n";

    for (std::string line; std::getline(inStream, line);)
    {
        auto index = line.find("DNS=");
        if (index != std::string::npos)
        {
            auto dns = line.substr(index + 4);
            outStream << "nameserver " << dns << "\n";
        }
    }
    return;
}

} // namespace updater
} // namespace dns
} // namespace network
} // namespace phosphor
