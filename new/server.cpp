#include <algorithm>
#include <sdbusplus/server.hpp>
#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Network/VLAN/Create/server.hpp>


namespace sdbusplus
{
namespace xyz
{
namespace openbmc_project
{
namespace Network
{
namespace VLAN
{
namespace server
{

Create::Create(bus::bus& bus, const char* path)
        : _xyz_openbmc_project_Network_VLAN_Create_interface(
                bus, path, _interface, _vtable, this)
{
}


int Create::_callback_VLAN(
        sd_bus_message* msg, void* context, sd_bus_error* error)
{
    using sdbusplus::server::binding::details::convertForMessage;

    try
    {
        auto m = message::message(msg);
#if 1
        {
            auto tbus = m.get_bus();
            sdbusplus::server::transaction::Transaction t(tbus, m);
            sdbusplus::server::transaction::set_id
                (std::hash<sdbusplus::server::transaction::Transaction>{}(t));
        }
#endif

        std::string interfaceName{};
    uint16_t id{};

        m.read(interfaceName, id);

        auto o = static_cast<Create*>(context);
        o->vLAN(interfaceName, id);

        auto reply = m.new_method_return();
        // No data to append on reply.

        reply.method_return();
    }
    catch(sdbusplus::internal_exception_t& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }

    return true;
}

namespace details
{
namespace Create
{
static const auto _param_VLAN =
        utility::tuple_to_array(message::types::type_id<
                std::string, uint16_t>());
static const auto _return_VLAN =
        utility::tuple_to_array(std::make_tuple('\0'));
}
}




const vtable::vtable_t Create::_vtable[] = {
    vtable::start(),

    vtable::method("VLAN",
                   details::Create::_param_VLAN
                        .data(),
                   details::Create::_return_VLAN
                        .data(),
                   _callback_VLAN),
    vtable::end()
};

} // namespace server
} // namespace VLAN
} // namespace Network
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

