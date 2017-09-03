#pragma once

#include <systemd/sd-event.h>

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

        Server(sd_event_io_handler_t cb):
            callback(cb) {};

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&&) = default;
        Server& operator=(Server &&) = default;

        sd_event_io_handler_t callback;

        /** @brief Initialise the event loop and add the handler for incoming
         *         RTNETLINK events.
         *
         *  @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
         */
        int run();

};

} //namespace rtnetlink
} //namespce network
} //namespace phosphor
