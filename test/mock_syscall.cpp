#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <map>
#include <queue>
#define MAX_IFADDRS 5

int debugging = false;

/* Data for mocking getifaddrs */
struct ifaddr_storage
{
    struct ifaddrs ifaddr;
    struct sockaddr_storage addr;
    struct sockaddr_storage mask;
    struct sockaddr_storage bcast;
} mock_ifaddr_storage[MAX_IFADDRS];

struct ifaddrs* mock_ifaddrs = nullptr;

int ifaddr_count = 0;

/* Stub library functions */
void freeifaddrs(ifaddrs* ifp)
{
    return;
}

std::map<int, std::queue<std::string>> mock_rtnetlinks;

std::map<std::string, int> mock_if_nametoindex;
std::map<int, std::string> mock_if_indextoname;
std::map<std::string, ether_addr> mock_macs;

void mock_clear()
{
    mock_ifaddrs = nullptr;
    ifaddr_count = 0;
    mock_rtnetlinks.clear();
    mock_if_nametoindex.clear();
    mock_if_indextoname.clear();
    mock_macs.clear();
}

void mock_addIF(const std::string& name, int idx, const ether_addr& mac)
{
    if (idx == 0)
    {
        throw std::invalid_argument("Bad interface index");
    }

    mock_if_nametoindex[name] = idx;
    mock_if_indextoname[idx] = name;
    mock_macs[name] = mac;
}


void mock_addIP(const char* name, const char* addr, const char* mask,
                unsigned int flags)
{
    struct ifaddrs* ifaddr = &mock_ifaddr_storage[ifaddr_count].ifaddr;

    struct sockaddr_in* in =
        reinterpret_cast<sockaddr_in*>(&mock_ifaddr_storage[ifaddr_count].addr);
    struct sockaddr_in* mask_in =
        reinterpret_cast<sockaddr_in*>(&mock_ifaddr_storage[ifaddr_count].mask);

    in->sin_family = AF_INET;
    in->sin_port = 0;
    in->sin_addr.s_addr = inet_addr(addr);

    mask_in->sin_family = AF_INET;
    mask_in->sin_port = 0;
    mask_in->sin_addr.s_addr = inet_addr(mask);

    ifaddr->ifa_next = nullptr;
    ifaddr->ifa_name = const_cast<char*>(name);
    ifaddr->ifa_flags = flags;
    ifaddr->ifa_addr = reinterpret_cast<struct sockaddr*>(in);
    ifaddr->ifa_netmask = reinterpret_cast<struct sockaddr*>(mask_in);
    ifaddr->ifa_data = nullptr;

    if (ifaddr_count > 0)
        mock_ifaddr_storage[ifaddr_count - 1].ifaddr.ifa_next = ifaddr;
    ifaddr_count++;
    mock_ifaddrs = &mock_ifaddr_storage[0].ifaddr;
}

int getifaddrs(ifaddrs** ifap)
{
    *ifap = mock_ifaddrs;
    if (mock_ifaddrs == nullptr)
        return -1;
    return (0);
}
