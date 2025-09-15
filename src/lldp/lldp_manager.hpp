#pragma once

#include "lldp_interface.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/utility/timer.hpp>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{
class Interface;

using TimerType = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

class LLDPManager
{
  public:
    LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event);

    static constexpr std::string_view objPath =
        "/xyz/openbmc_project/network/lldp";

    std::vector<std::string> getInterfaces();

  protected:
    void createIntfDbusObjects();

    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
    std::unique_ptr<TimerType> createIntfTimer;

    std::unordered_map<std::string, std::unique_ptr<Interface>> ifaces;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
