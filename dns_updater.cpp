#include "config.h"
#include "dns_updater.hpp"
#include "watch.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

#include <fstream>


using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

constexpr auto resolveConfFile = "/etc/resolv.conf";

void readNetIfState(const std::string& netIfFile)
{
    std::fstream inStream;
    std::fstream outStream;

    outStream.open(resolveConfFile, std::fstream::out);
    inStream.open(netIfFile, std::fstream::in);
    if (!inStream.is_open())
    {
        log<level::ERR>("Unable to open the file",
                        entry("FILE=%s", netIfFile.c_str()));
        elog<InternalFailure>();
    }
    if (!outStream.is_open())
    {
        log<level::ERR>("Unable to open the resolv conf file");
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
    inStream.close();
    outStream.close();
}

} // namespace updater
} // namespace dns
} // namespace network
} // namespace phosphor


int main(int argc, char* argv[])
{
    using namespace phosphor::logging;
    using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

    /* Sanity checking */
    if(argc != 2 || argv[1] == NULL)
    {
        log<level::ERR>("Not enough argument given,\
                         Usage: phosphor-dns-updater <path of DHCP netif file>");
        return -1;
    }

    auto bus = sdbusplus::bus::new_default();
    sd_event* event = nullptr;
    auto rc = sd_event_default(&event);
    if (rc < 0)
    {
        log<level::ERR>("Error occurred during the sd_event_default",
                        entry("RC=%d", rc));
        report<InternalFailure>();
        return -1;
    }

    phosphor::EventPtr eventP{event};
    event = nullptr;
    fs::path netifFile = argv[1];

    try
    {
        phosphor::network::inotify::Watch watch(
            eventP,
            IN_NONBLOCK,
            IN_MODIFY,
            EPOLLIN,
            netifFile.string(),
            std::bind(
                &phosphor::network::dns::updater::readNetIfState,
                std::placeholders::_1));

        auto rc = sd_event_loop(eventP.get());
        if (rc < 0)
        {
            log<level::ERR>("Error occurred during the sd_event_loop",
                            entry("RC=%d", rc));
            elog<InternalFailure>();
        }
    }

    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        return -1;
    }

    return 0;
}
