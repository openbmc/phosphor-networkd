#include "types.hpp"
#include "rtnetlink_server.hpp"
#include "network_manager.hpp"
#include "mock_syscall.hpp"
#include "timer.hpp"
#include "types.hpp"


#include <gtest/gtest.h>
#include <sdbusplus/bus.hpp>

#include <net/if.h>
#include <linux/rtnetlink.h>

namespace phosphor
{

namespace network
{

std::unique_ptr<Manager> manager = nullptr;
std::unique_ptr<Timer> refreshObjectTimer = nullptr;
std::unique_ptr<Timer> restartTimer = nullptr;
EventPtr eventPtr = nullptr;

/** @brief refresh the network objects. */
void refreshObjects()
{

    if (manager)
    {
        manager->createChildObjects();
    }
}

void initializeTimers()
{
    std::function<void()> refreshFunc(
        std::bind(&refreshObjects));

    refreshObjectTimer =
        std::make_unique<Timer>(refreshFunc);

}

class TestRtNetlink : public testing::Test
{

    public:
        std::string confDir;
        phosphor::Descriptor smartSock;



        TestRtNetlink()
        {
            sdbusplus::bus::bus bus(sdbusplus::bus::new_default());
            manager =
                std::make_unique<Manager>(bus,
                        "/xyz/openbmc_test/bcd",
                        "/tmp");
            sd_event* events;
            sd_event_default(&events);
            eventPtr = (EventPtr)(events);
            events = nullptr;
            setConfDir();
            initializeTimers();
            createNetLinkSocket();
            bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);
            rtnetlink::Server svr(eventPtr, smartSock);
        }

        ~TestRtNetlink()
        {
            if (confDir.empty())
            {
                fs::remove_all(confDir);
            }
        }

        void setConfDir()
        {
            confDir = "/tmp/NetworkManager.YYYY";
            manager->setConfDir(confDir);
        }

        bool isInterfaceAdded(std::string intf)
        {
            return manager->interfaces.find(intf) != manager->interfaces.end()?
                   true :
                   false;
        }

        void createNetLinkSocket()
        {
            //RtnetLink socket
            auto fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK,
                NETLINK_ROUTE);
            smartSock.set(fd);
        }
};


TEST_F(TestRtNetlink, WithSingleInterface)
{
    bool caughtException = false;
    using namespace std::chrono;
    try
    {
        // Adds the following ip in the getifaddrs list.
        mock_addIP("igb5", "127.0.0.1", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);
        constexpr auto BUFSIZE = 4096;
        std::array<char, BUFSIZE> msgBuf = {0};

        // point the header and the msg structure pointers into the buffer.
        auto nlMsg = reinterpret_cast<nlmsghdr*>(msgBuf.data());
        // Length of message
        nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
        nlMsg->nlmsg_type = RTM_GETADDR;
        nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
        nlMsg->nlmsg_seq = 0;
        nlMsg->nlmsg_pid = getpid();

        EXPECT_EQ(false, isInterfaceAdded("igb5"));
        // Send the request
        send(smartSock(), nlMsg, nlMsg->nlmsg_len, 0);

        int i = 2;
        while (i--)
        {
            //wait for timer to expire
            std::this_thread::sleep_for(
                std::chrono::milliseconds(refreshTimeout));
            sd_event_run(eventPtr.get(), 10);
        };

        EXPECT_EQ(true, isInterfaceAdded("igb5"));
    }
    catch (std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(false, caughtException);
}

}// namespce network
}// namespace phosphor
