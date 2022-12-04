#pragma once
#include <memory>

namespace sdbusplus::bus
{
class bus;
}

namespace phosphor::network
{

class Manager;

namespace inventory
{

struct Runtime
{
    virtual ~Runtime() = default;
};
std::unique_ptr<Runtime> watch(sdbusplus::bus_t& bus, Manager& m);

} // namespace inventory
} // namespace phosphor::network
