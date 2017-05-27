#pragma once

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <iostream>
#include <list>
#include <string>

namespace phosphor
{
namespace network
{
namespace route
{

struct Entry
{
    // destination network
    std::string destination;
    // gateway for this network.
    std::string gateway;
    // interface for this route
    std::string interface;
    Entry(std::string destnation,
          std::string gateway,
          std::string interface)
    {
        this->destination = destination;
        this->gateway = gateway;
        this->interface = interface;
    }

    bool operator==(const Entry& rhs)
    {

        return this->destination == rhs.destination &&
               this->gateway == rhs.gateway &&
               this->interface == rhs.interface ;
    }
};

using RouteMap = std::map<std::string, struct Entry>;

class Table
{
    public:
        Table();
        ~Table() = default;
        Table(const Table&) = delete;
        Table& operator=(const Table&) = delete;
        Table(Table&&) = default;
        Table& operator=(Table &&) = default;

    private:

        /**
         * @brief read the routing data from the socket and fill the buffer.
         *
         * @param[in] bufptr - unique pointer to confidentiality algorithm
         *                       instance
         */
        int readNetLinkSock(int sockFd, char* bufPtr);
        /**
         * @brief Parse the route and add it to the route list.
         *
         * @param[in] nlHdr - net link message header.
         */
        void parseRoutes(struct nlmsghdr* nlHdr);

    public:

        /**
         * @brief gets the list of routes.
         *
         * @returns list of routes.
         */
        RouteMap getRoutes();

        /**
         * @brief gets the default gateway.
         *
         * @returns the default gateway.
         */
        std::string getDefaultGateway()
        {
            return defaultGateway;
        };

        /**
         * @brief get the gateway for the network.
         * @param[in] - destination network.
         * @returns the gatway for the given network.
         */
        std::string getGateway(int addressFamily, const std::string& ipaddress,
                               uint8_t prefix);

        std::string defaultGateway; // default gateway
        RouteMap routeList; //List of routes
};
}// namespace route
}// namespace network
}// namespace phosphor
