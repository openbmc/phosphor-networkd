#pragma once

#include "types.hpp"

#include <stdplus/fd/managed.hpp>

namespace phosphor
{
namespace network
{
namespace rtnetlink
{

constexpr auto BUFSIZE = 4096;

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
     *  @param[in] socket - netlink socket.
     */
    Server(EventPtr& eventPtr);

    /** @brief Gets the socket associated with this netlink server */
    inline stdplus::Fd& getSock()
    {
        return sock;
    }

  private:
    stdplus::ManagedFd sock;
};

} // namespace rtnetlink
} // namespace network
} // namespace phosphor
