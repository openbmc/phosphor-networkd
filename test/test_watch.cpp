#include "watch.hpp"
#include "types.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <experimental/filesystem>

static constexpr auto TRIGGER_FILE = "/tmp/netif_state";

namespace fs = std::experimental::filesystem;

class WatchTest : public ::testing::Test
{
    public:
        // systemd event handler
        sd_event* events;

        // Need this so that events can be initialized.
        int rc;

        // Gets called as part of each TEST_F construction
        WatchTest()
            : rc(sd_event_default(&events)),
              eventPtr(events)
        {
            // Create a file containing DNS entries like in netif/state
            std::ofstream file(TRIGGER_FILE);
            file << "";

            // Check for successful creation of
            // event handler
            EXPECT_GE(rc, 0);
        }

        // Gets called as part of each TEST_F destruction
        ~WatchTest()
        {
            if (fs::exists(TRIGGER_FILE))
            {
                fs::remove(TRIGGER_FILE);
            }
        }

        // unique_ptr for sd_event
        phosphor::network::EventPtr eventPtr;

        // Count of callback invocation
        int count = 0;

        // This is supposed to get hit twice
        // Once at the beginning to see if there is anything
        // and the second time when the data is fired.
        void callBackHandler(const fs::path& file)
        {
            count++;

            // Expect that the file is what we wanted
            EXPECT_EQ(file, TRIGGER_FILE);
        }
};

/** @brief Makes sure that the inotify event is fired
 */
TEST_F(WatchTest, validateEventNotification)
{
    // Create a watch object and register the handler
    phosphor::network::inotify::Watch watch(eventPtr, TRIGGER_FILE,
            std::bind(&WatchTest::callBackHandler, this,
                std::placeholders::_1));

    // Reading the event post subscription
    callBackHandler(TRIGGER_FILE);

    // Callback function must have hit by now
    EXPECT_EQ(1, count);

    // Make a run and see that no changes
    sd_event_run(eventPtr.get(), 10);
    EXPECT_EQ(1, count);

    // Pump the data and get notification
    {
        std::ofstream file(TRIGGER_FILE);
        file <<"DNS=1.2.3.4\n";
    }

    sd_event_run(eventPtr.get(), 10);
    EXPECT_EQ(2, count);
}
