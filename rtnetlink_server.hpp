#pragma once

#include "util.hpp"

#include <sdeventplus/event.hpp>

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
     *  @param[in] event  - SdEvent loop handle.
     *  @param[in] socket - netlink socket.
     */
    Server(const sdeventplus::Event& event, const Descriptor& socket);

    Server() = delete;
    ~Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = default;
    Server& operator=(Server&&) = default;
};

} // namespace rtnetlink
} // namespace network
} // namespace phosphor
