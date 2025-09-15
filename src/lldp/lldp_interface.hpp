#pragma once

#include <sdbusplus/server/object.hpp>

#include <string>

namespace phosphor
{
namespace network
{
namespace lldp
{

class LLDPManager;

class Interface
{
  public:
    Interface() = delete;
    Interface(const Interface&) = delete;
    Interface& operator=(const Interface&) = delete;

    Interface(sdbusplus::bus_t& bus, LLDPManager& manager,
              const std::string& objPath, const std::string& ifname);

    ~Interface() = default;

  private:
    LLDPManager& manager;
    sdbusplus::bus_t& bus;
    std::string objPath;
    std::string ifname;
};
} // namespace lldp
} // namespace network
} // namespace phosphor
