#pragma once
#include <memory>
#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>

namespace phosphor::network
{

class Manager;

namespace inventory
{

struct Runtime
{
    virtual ~Runtime() = default;
};
std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                               stdplus::PinnedRef<Manager> m);

} // namespace inventory
} // namespace phosphor::network
