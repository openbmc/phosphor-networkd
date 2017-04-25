#pragma once
#include <tuple>
#include <systemd/sd-bus.h>
#include <sdbusplus/server.hpp>

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

class Create
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
         *         - Destructor.
         */
        Create() = delete;
        Create(const Create&) = delete;
        Create& operator=(const Create&) = delete;
        Create(Create&&) = delete;
        Create& operator=(Create&&) = delete;
        virtual ~Create() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        Create(bus::bus& bus, const char* path);



        /** @brief Implementation for VLAN
         *  Create VLANInterface Object.
         *
         *  @param[in] interfaceName - Name of the interface.
         *  @param[in] id - VLAN Identifier.
         */
        virtual void vLAN(
            std::string interfaceName,
            uint16_t id) = 0;




    private:

        /** @brief sd-bus callback for VLAN
         */
        static int _callback_VLAN(
            sd_bus_message*, void*, sd_bus_error*);


        static constexpr auto _interface = "xyz.openbmc_project.Network.VLAN.Create";
        static const vtable::vtable_t _vtable[];
        sdbusplus::server::interface::interface
                _xyz_openbmc_project_Network_VLAN_Create_interface;


};


} // namespace server
} // namespace VLAN
} // namespace Network
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

