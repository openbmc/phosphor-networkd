#include <config.h>

#include <ncsi_info.hpp>

using namespace phosphor::logging;
constexpr char DEFAULT_NCSI_OBJPATH[] = "/xyz/openbmc_project/ncsi/eeprom";

namespace phosphor
{
namespace eeprom
{

std::unique_ptr<phosphor::eeprom::ncsi> ncsiPtr = nullptr;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

ncsi::ncsi(sdbusplus::bus::bus& bus, const char* objPath) :
    ncsiIface(bus, objPath), bus(bus)
{
    get_ncsi_info();
}

size_t ncsi::get_ncsi_info()
{
    size_t eepromSize;
    int ret = phosphor::network::ncsi::getInfo(indexInt, packageInt);
    if (ret == 0)
    {
        std::string chaVer = phosphor::network::ncsi::ncsiVer;
        std::string result = chaVer.substr(0, 3);
        if (result == "mlx")
        {
            eepromSize = 2;
        }
        else
        {
            eepromSize = 1;
        }
        setPropertyByName("DataSize", eepromSize, false);
        return 0;
    }
    else
    {
        std::cerr << "ncsi info not found" << std::endl;
        return 0;
    }
}

} // namespace eeprom
} // namespace phosphor

int main(int /*argc*/, char** /*argv*/)
{
    int ret = 0;
    sd_event* event = nullptr;
    ret = sd_event_default(&event);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error creating a default sd_event handler");
        return ret;
    }
    phosphor::eeprom::EventPtr eventPtr{event};
    event = nullptr;

    auto bus = sdbusplus::bus::new_default();

    sdbusplus::server::manager::manager objManager(bus, DEFAULT_NCSI_OBJPATH);
    bus.request_name(BUSNAME);

    phosphor::eeprom::ncsiPtr =
        std::make_unique<phosphor::eeprom::ncsi>(bus, DEFAULT_NCSI_OBJPATH);

    try
    {
        bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);
        ret = sd_event_loop(eventPtr.get());
        if (ret < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error occurred during the sd_event_loop",
                phosphor::logging::entry("RET=%d", ret));
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        ret = -1;
    }
    return ret;
}
