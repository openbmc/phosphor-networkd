#pragma once
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <stdplus/fd/managed.hpp>

namespace phosphor
{
namespace network
{
class Manager;
namespace netlink
{

/** General rtnetlink server which waits for the POLLIN event
    and calls the  call back once it gets the event.
    Usage would be create the server with the  call back
    and call the run method.
 */
class Server
{
  public:
    /** @brief Constructor
     *
     *  @details Sets up the server to handle incoming RTNETLINK events
     *
     *  @param[in] eventPtr - Unique ptr reference to sd_event.
     *  @param[in] manager  - The network manager that receives updates
     */
    Server(sdeventplus::Event& event, Manager& manager);

    /** @brief Gets the socket associated with this netlink server */
    inline stdplus::Fd& getSock()
    {
        return sock;
    }

  private:
    stdplus::ManagedFd sock;
    sdeventplus::source::IO io;
};

} // namespace netlink
} // namespace network
} // namespace phosphor
