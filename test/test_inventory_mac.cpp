#include "config.h"

#include "config_parser.hpp"
#include "inventory_mac.hpp"
#include "network_manager.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/interface.hpp>
#include <sdbusplus/server/manager.hpp>
#include <xyz/openbmc_project/Inventory/Item/NetworkInterface/server.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

namespace
{

std::string testNetworkDirectory = "/dev/null";

// Redirect only inventory MAC marker I/O; other file operations stay real.
std::string redirectMarkerPath(const char* path)
{
    constexpr std::string_view directory = "/var/lib/network";
    const std::string_view value(path);
    if (value == directory || value.starts_with("/var/lib/network/firstBoot_"))
    {
        return testNetworkDirectory +
               std::string(value.substr(directory.size()));
    }
    return std::string(value);
}

} // namespace

extern "C"
{
int stat(const char* path, struct stat* buffer) noexcept
{
    return fstatat(AT_FDCWD, redirectMarkerPath(path).c_str(), buffer, 0);
}

#if !defined(__USE_FILE_OFFSET64) && !defined(__USE_TIME_BITS64)
int stat64(const char* path, struct stat64* buffer) noexcept
{
    return fstatat64(AT_FDCWD, redirectMarkerPath(path).c_str(), buffer, 0);
}
#endif

FILE* fopen(const char* path, const char* mode)
{
#if defined(__USE_FILE_OFFSET64)
    static auto realFopen =
        reinterpret_cast<decltype(&fopen)>(dlsym(RTLD_NEXT, "fopen64"));
#else
    static auto realFopen =
        reinterpret_cast<decltype(&fopen)>(dlsym(RTLD_NEXT, "fopen"));
#endif
    return realFopen(redirectMarkerPath(path).c_str(), mode);
}

#if !defined(__USE_FILE_OFFSET64)
FILE* fopen64(const char* path, const char* mode)
{
    static auto realFopen =
        reinterpret_cast<decltype(&fopen64)>(dlsym(RTLD_NEXT, "fopen64"));
    return realFopen(redirectMarkerPath(path).c_str(), mode);
}
#endif

// A 64-bit host's libstdc++ may use the unsuffixed symbols even when this
// translation unit was compiled with _FILE_OFFSET_BITS=64.
#if defined(__USE_FILE_OFFSET64) && __SIZEOF_LONG__ == 8
int nativeStat(const char* path, struct stat* buffer) noexcept asm("stat");
int nativeStat(const char* path, struct stat* buffer) noexcept
{
    return fstatat(AT_FDCWD, redirectMarkerPath(path).c_str(), buffer, 0);
}

FILE* nativeFopen(const char* path, const char* mode) asm("fopen");
FILE* nativeFopen(const char* path, const char* mode)
{
    static auto realFopen =
        reinterpret_cast<decltype(&nativeFopen)>(dlsym(RTLD_NEXT, "fopen"));
    return realFopen(redirectMarkerPath(path).c_str(), mode);
}
#endif
}

namespace phosphor::network
{

// Keep network manager construction from changing the test host's hostname or
// writing its first-boot marker. The other manager and D-Bus code is real.
HostnameManager::HostnameManager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                 stdplus::PinnedRef<Manager> manager) :
    bus(bus), manager(manager)
{}

void HostnameManager::initialize() {}

namespace inventory
{

// Reset the process-wide watcher state between independent startup scenarios.
extern std::unique_ptr<sdbusplus::match> EthInterfaceMatch;
extern std::unique_ptr<sdbusplus::match> MacAddressMatch;
extern std::set<std::string> pendingInterfaces;
extern std::map<std::string, MACConfig> interfaceConfigs;
extern Manager* manager;
std::optional<stdplus::EtherAddr> getFromInventory(sdbusplus::bus_t& bus,
                                                   const std::string& intfName);
void watchEthernetInterface(sdbusplus::bus_t& bus);

namespace
{

using namespace std::chrono_literals;
constexpr auto inventoryRoot = "/xyz/openbmc_project/inventory";
constexpr auto board1Path =
    "/xyz/openbmc_project/inventory/system/board/Test_Board_1";
constexpr auto board2Path =
    "/xyz/openbmc_project/inventory/system/board/Test_Board_2";
constexpr auto networkRoot = "/xyz/openbmc_project/network";
constexpr auto board1MAC = "02:11:22:33:44:50";
constexpr auto board2MAC = "02:11:22:33:44:51";
constexpr auto board1SecondMAC = "02:11:22:33:44:60";
constexpr auto board2SecondMAC = "02:11:22:33:44:61";

using InventoryObject = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::NetworkInterface>;

struct TestInventoryBoard
{
    TestInventoryBoard(sdbusplus::bus_t& bus, const char* path, const char* mac,
                       const char* secondMAC) :
        path(path), mac(mac), secondMAC(secondMAC),
        object(bus, path, InventoryObject::action::defer_emit)
    {
        object.macAddress(mac, true);
        object.macAddress2(secondMAC, true);
    }

    const char* path;
    const char* mac;
    const char* secondMAC;
    bool available = false;
    InventoryObject object;
};

struct TestExecutor : DelayedExecutor
{
    void schedule() override {}
    void setCallback(fu2::unique_function<void()>&&) override {}
};

struct TestInterface : EthernetInterface
{
    TestInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                  stdplus::PinnedRef<Manager> manager, std::string name,
                  unsigned index) :
        EthernetInterface(
            bus, manager,
            AllIntfInfo{InterfaceInfo{.type = ARPHRD_ETHER,
                                      .idx = index,
                                      .flags = 0,
                                      .name = std::move(name)}},
            sdbusplus::object_path(networkRoot), config::Parser(), true)
    {}

    bool rejectMAC = false;
    bool throwOnMAC = false;
    unsigned attempts = 0;
    std::vector<std::string> applied;

    std::string macAddress(std::string value) override
    {
        ++attempts;
        if (throwOnMAC)
        {
            throw std::runtime_error("Simulated MAC assignment failure");
        }
        if (rejectMAC)
        {
            return {};
        }
        applied.push_back(value);
        return value;
    }
};

class InventoryMAC : public testing::Test
{
  protected:
    stdplus::Pinned<sdbusplus::bus_t> bus{sdbusplus::bus::new_bus()};
    stdplus::Pinned<sdbusplus::bus_t> service{sdbusplus::bus::new_bus()};
    sdbusplus::server::manager_t networkObjects{bus, networkRoot};
    sdbusplus::server::manager_t inventoryObjects{service, inventoryRoot};
    TestInventoryBoard board1{service, board1Path, board1MAC, board1SecondMAC};
    TestInventoryBoard board2{service, board2Path, board2MAC, board2SecondMAC};
    stdplus::Pinned<TestExecutor> executor;
    std::unique_ptr<Manager> networkManager;
    std::filesystem::path tempDir;
    std::filesystem::path stateDir;
    std::mutex serviceMutex;
    std::jthread serviceThread;

    static int getSubTree(sd_bus_message* raw, void* context, sd_bus_error*)
    {
        auto& self = *static_cast<InventoryMAC*>(context);
        sdbusplus::message_t request(raw);
        std::map<std::string, std::map<std::string, std::vector<std::string>>>
            tree;
        for (const auto* board : {&self.board1, &self.board2})
        {
            if (board->available)
            {
                tree[board->path][self.service.get_unique_name()] = {
                    "xyz.openbmc_project.Inventory.Item.NetworkInterface"};
            }
        }
        auto reply = request.new_method_return();
        reply.append(tree);
        reply.method_return();
        return 1;
    }

    static constexpr sdbusplus::vtable_t mapperVtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("GetSubTree", "sias", "a{sa{sas}}", getSubTree,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END};
    sdbusplus::server::interface_t mapper{
        service, "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", mapperVtable, this};

    void SetUp() override
    {
        interfaceConfigs.clear();
        pendingInterfaces.clear();
        tempDir =
            std::filesystem::temp_directory_path() /
            ("inventory-mac-" + std::to_string(getpid()) + "-" +
             testing::UnitTest::GetInstance()->current_test_info()->name());
        stateDir = tempDir / "state";
        std::filesystem::create_directories(stateDir);
        testNetworkDirectory = stateDir.string();
        service.request_name("xyz.openbmc_project.ObjectMapper");
        serviceThread = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested())
            {
                {
                    std::lock_guard lock(serviceMutex);
                    service.process_discard();
                }
                std::this_thread::sleep_for(1ms);
            }
        });
        networkManager =
            std::make_unique<Manager>(bus, executor, networkRoot, tempDir);
    }

    void TearDown() override
    {
        EthInterfaceMatch = nullptr;
        MacAddressMatch = nullptr;
        pendingInterfaces.clear();
        interfaceConfigs.clear();
        manager = nullptr;
        networkManager.reset();
        if (serviceThread.joinable())
        {
            serviceThread.request_stop();
            serviceThread.join();
        }
        testNetworkDirectory = "/dev/null";
        std::error_code ec;
        std::filesystem::remove_all(tempDir, ec);
    }

    TestInterface& addInterface(const std::string& name, unsigned index)
    {
        auto interface =
            std::make_unique<TestInterface>(bus, *networkManager, name, index);
        auto& result = *interface;
        networkManager->interfaces.emplace(name, std::move(interface));
        return result;
    }

    void configure(const char* content)
    {
        interfaceConfigs.clear();
        const auto configJson = nlohmann::json::parse(content);
        for (const auto& entry : configJson.items())
        {
            auto config = parseMACConfig(entry.value());
            ASSERT_TRUE(config.has_value()) << entry.key();
            interfaceConfigs.emplace(entry.key(), std::move(*config));
        }
    }

    void startWatch()
    {
        manager = networkManager.get();
        watchEthernetInterface(bus);
    }

    void publishInventory(bool includeSecondMAC = true)
    {
        std::lock_guard lock(serviceMutex);
        // Allow repeated inventory announcements to test a failed MAC retry.
        for (auto* board : {&board1, &board2})
        {
            board->available = true;
            auto signal = service.new_signal(
                inventoryRoot, "org.freedesktop.DBus.ObjectManager",
                "InterfacesAdded");
            std::map<std::string,
                     std::map<std::string, std::variant<std::string>>>
                interfaces{
                    {"xyz.openbmc_project.Inventory.Item.NetworkInterface",
                     {{"MACAddress", board->mac}}}};
            if (includeSecondMAC)
            {
                interfaces
                    .at("xyz.openbmc_project.Inventory.Item.NetworkInterface")
                    .emplace("MACAddress2", board->secondMAC);
            }
            signal.append(sdbusplus::object_path(board->path), interfaces);
            signal.signal_send();
        }
        service.flush();
    }

    bool processUntil(const std::function<bool()>& done)
    {
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (!done() && std::chrono::steady_clock::now() < deadline)
        {
            if (!bus.process_discard())
            {
                bus.wait(10000);
            }
        }
        return done();
    }
};

/** @brief Default legacy and object configurations to MACAddress. */
TEST(InventoryMACConfig, LegacyAndObjectFormatsDefaultToFirstMAC)
{
    for (const auto& value : {nlohmann::json("Test_Board_1"),
                              nlohmann::json{{"Inventory", "Test_Board_1"}}})
    {
        const auto config = parseMACConfig(value);
        ASSERT_TRUE(config);
        EXPECT_EQ(config->inventory, "Test_Board_1");
        EXPECT_EQ(config->property, "MACAddress");
    }
}

/** @brief Parse the inventory name and an explicit MACAddress2 property. */
TEST(InventoryMACConfig, SelectsSecondMAC)
{
    const auto config = parseMACConfig(
        {{"Inventory", "Test_Board_1"}, {"Property", "MACAddress2"}});
    ASSERT_TRUE(config);
    EXPECT_EQ(config->inventory, "Test_Board_1");
    EXPECT_EQ(config->property, "MACAddress2");
}

/** @brief Accept an empty legacy inventory name with the default property. */
TEST(InventoryMACConfig, PreservesEmptyInventoryName)
{
    const auto config = parseMACConfig("");
    ASSERT_TRUE(config);
    EXPECT_TRUE(config->inventory.empty());
    EXPECT_EQ(config->property, "MACAddress");
}

/** @brief Reject unsupported entry types and missing or invalid fields. */
TEST(InventoryMACConfig, RejectsInvalidEntries)
{
    for (const auto& value :
         {nlohmann::json(), nlohmann::json(42), nlohmann::json(false),
          nlohmann::json::array(), nlohmann::json::object(),
          nlohmann::json{{"Property", "MACAddress2"}},
          nlohmann::json{{"Inventory", 42}},
          nlohmann::json{{"Inventory", "Test_Board_1"}, {"Property", 42}},
          nlohmann::json{{"Inventory", "Test_Board_1"}, {"Property", ""}}})
    {
        EXPECT_FALSE(parseMACConfig(value)) << value.dump();
    }
}

/** @brief Select distinct MAC properties on the same board at startup. */
TEST_F(InventoryMAC, DirectReadsSelectTwoMACsFromSameBoard)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": {"Inventory": "Test_Board_1", "Property": "MACAddress2"}
    })");
    startWatch();
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board1SecondMAC});
    EXPECT_TRUE(std::filesystem::exists(stateDir / "firstBoot_eth0"));
    EXPECT_TRUE(std::filesystem::exists(stateDir / "firstBoot_eth1"));
    EXPECT_TRUE(pendingInterfaces.empty());
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief One inventory signal can synchronize both MACs of the same board. */
TEST_F(InventoryMAC, InventorySignalsSelectTwoMACsFromSameBoard)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    configure(R"({
        "eth0": {"Inventory": "Test_Board_1"},
        "eth1": {"Inventory": "Test_Board_1", "Property": "MACAddress2"}
    })");
    startWatch();
    ASSERT_EQ(pendingInterfaces.size(), 2u);
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board1SecondMAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Wait for MACAddress2 without substituting the first MAC. */
TEST_F(InventoryMAC, MissingSecondMACSignalRemainsPendingUntilRetry)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": {"Inventory": "Test_Board_1", "Property": "MACAddress2"}
    })");
    startWatch();
    publishInventory(false);
    ASSERT_TRUE(processUntil([&] { return !eth0.applied.empty(); }));
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.attempts, 0u);
    EXPECT_TRUE(pendingInterfaces.contains("eth1"));
    EXPECT_TRUE(EthInterfaceMatch);
    EXPECT_TRUE(MacAddressMatch);
    EXPECT_FALSE(std::filesystem::exists(stateDir / "firstBoot_eth1"));
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth0.applied.size(), 1u);
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board1SecondMAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief A failed property read must not silently use MACAddress. */
TEST_F(InventoryMAC, MissingSelectedPropertyDoesNotFallBackToFirstMAC)
{
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({
        "eth1": {"Inventory": "Test_Board_1", "Property": "MissingMAC"}
    })");
    EXPECT_NO_THROW(startWatch());
    EXPECT_EQ(eth1.attempts, 0u);
    EXPECT_TRUE(pendingInterfaces.contains("eth1"));
    EXPECT_TRUE(EthInterfaceMatch);
    EXPECT_TRUE(MacAddressMatch);
}

/** @brief Apply MACAddress2 after inventory precedes the Ethernet interface. */
TEST_F(InventoryMAC, SecondMACWaitsForEthernetInterface)
{
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({
        "eth1": {"Inventory": "Test_Board_1", "Property": "MACAddress2"}
    })");
    startWatch();
    ASSERT_TRUE(pendingInterfaces.contains("eth1"));
    auto& eth1 = addInterface("eth1", 2);
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board1SecondMAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Synchronize all interfaces from inventory available at startup. */
TEST_F(InventoryMAC, DirectReadsSynchronizeAllInterfaces)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
        board2.available = true;
    }
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": "Test_Board_2"
    })");
    startWatch();
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_TRUE(pendingInterfaces.empty());
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Use the sole inventory object when its name matches the config. */
TEST_F(InventoryMAC, SingleInventoryMatchesConfiguredName)
{
    auto& eth0 = addInterface("eth0", 1);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({"eth0": "Test_Board_1"})");
    startWatch();
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_TRUE(pendingInterfaces.empty());
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Preserve empty-name configs by using the sole inventory object. */
TEST_F(InventoryMAC, EmptyInventoryNameUsesOnlyAvailableObject)
{
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({"eth1": ""})");
    startWatch();
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board1MAC});
    EXPECT_TRUE(pendingInterfaces.empty());
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Avoid choosing between multiple objects for an empty-name config. */
TEST_F(InventoryMAC, EmptyInventoryNameDoesNotChooseBetweenMultipleObjects)
{
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
        board2.available = true;
    }
    configure(R"({"eth1": ""})");
    EXPECT_NO_THROW({ EXPECT_FALSE(getFromInventory(bus, "eth1")); });
    startWatch();
    EXPECT_TRUE(eth1.applied.empty());
    EXPECT_TRUE(pendingInterfaces.contains("eth1"));
    EXPECT_TRUE(EthInterfaceMatch);
    EXPECT_TRUE(MacAddressMatch);
}

/** @brief Wait without throwing until the configured inventory appears. */
TEST_F(InventoryMAC, MissingConfiguredInventoryWaitsWithoutThrowing)
{
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
    }
    configure(R"({"eth1": "Test_Board_2"})");
    EXPECT_NO_THROW({ EXPECT_FALSE(getFromInventory(bus, "eth1")); });
    startWatch();
    ASSERT_TRUE(eth1.applied.empty());
    ASSERT_TRUE(pendingInterfaces.contains("eth1"));
    ASSERT_TRUE(EthInterfaceMatch);
    ASSERT_TRUE(MacAddressMatch);

    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Synchronize all interfaces through late inventory signals. */
TEST_F(InventoryMAC, InventorySignalsSynchronizeAllInterfaces)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": "Test_Board_2"
    })");
    startWatch();
    ASSERT_EQ(pendingInterfaces.size(), 2u);
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Keep monitoring inventory after only one interface succeeds. */
TEST_F(InventoryMAC, OneSuccessfulInterfaceKeepsListenerForPendingInterface)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    {
        std::lock_guard lock(serviceMutex);
        board2.available = true;
    }
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": "Test_Board_2"
    })");
    startWatch();
    ASSERT_TRUE(eth0.applied.empty());
    ASSERT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    ASSERT_EQ(pendingInterfaces.size(), 1u);
    ASSERT_TRUE(pendingInterfaces.contains("eth0"));
    ASSERT_TRUE(MacAddressMatch);
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth0.applied, std::vector<std::string>{board1MAC});
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Retain pending state after a failed MAC assignment and retry. */
TEST_F(InventoryMAC, FailedMACAssignmentStaysPendingUntilRetrySucceeds)
{
    auto& eth1 = addInterface("eth1", 2);
    eth1.rejectMAC = true;
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
        board2.available = true;
    }
    configure(R"({"eth1": "Test_Board_2"})");
    startWatch();
    ASSERT_EQ(pendingInterfaces.size(), 1u);
    ASSERT_TRUE(MacAddressMatch);
    EXPECT_FALSE(std::filesystem::exists(stateDir / "firstBoot_eth1"));
    eth1.rejectMAC = false;
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_TRUE(std::filesystem::exists(stateDir / "firstBoot_eth1"));
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Wait for the Ethernet interface when inventory appears first. */
TEST_F(InventoryMAC, InventoryBeforeEthernetInterfaceDoesNotCompleteEarly)
{
    configure(R"({"eth1": "Test_Board_2"})");
    startWatch();
    publishInventory();
    // Synchronize with the service so its inventory signal is queued first.
    auto request = bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                                       "/xyz/openbmc_project/object_mapper",
                                       "org.freedesktop.DBus.Peer", "Ping");
    bus.call(request);
    while (bus.process_discard())
    {}
    ASSERT_EQ(pendingInterfaces.size(), 1u);
    ASSERT_TRUE(EthInterfaceMatch);
    auto& eth1 = addInterface("eth1", 2);
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Catch MAC setter exceptions in the callback and allow retries. */
TEST_F(InventoryMAC, AssignmentExceptionDoesNotEscapeSignalCallback)
{
    auto& eth1 = addInterface("eth1", 2);
    eth1.throwOnMAC = true;
    configure(R"({"eth1": "Test_Board_2"})");
    startWatch();
    publishInventory();
    bool processed = false;
    EXPECT_NO_THROW(
        processed = processUntil([&] { return eth1.attempts == 1; }));
    ASSERT_TRUE(processed);
    ASSERT_EQ(pendingInterfaces.size(), 1u);
    ASSERT_TRUE(MacAddressMatch);
    EXPECT_FALSE(std::filesystem::exists(stateDir / "firstBoot_eth1"));
    eth1.throwOnMAC = false;
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief Sync eth1 normally; sync marked eth0 only when FORCE is enabled. */
TEST_F(InventoryMAC, ExistingMarkersRespectForceSyncAndDoNotBlockCompletion)
{
    auto& eth0 = addInterface("eth0", 1);
    auto& eth1 = addInterface("eth1", 2);
    std::ofstream marker(stateDir / "firstBoot_eth0");
    marker.close();
    {
        std::lock_guard lock(serviceMutex);
        board1.available = true;
        board2.available = true;
    }
    configure(R"({
        "eth0": "Test_Board_1",
        "eth1": "Test_Board_2"
    })");
    startWatch();
    EXPECT_EQ(eth0.applied.size(), FORCE_SYNC_MAC_FROM_INVENTORY ? 1u : 0u);
    EXPECT_EQ(eth1.applied, std::vector<std::string>{board2MAC});
    EXPECT_TRUE(pendingInterfaces.empty());
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

/** @brief A marker created while waiting skips MAC assignment unless forced. */
TEST_F(InventoryMAC, MarkerCreatedWhilePendingRespectsForceSync)
{
    auto& eth1 = addInterface("eth1", 2);
    configure(R"({"eth1": "Test_Board_2"})");
    startWatch();
    ASSERT_EQ(pendingInterfaces.size(), 1u);

    std::ofstream marker(stateDir / "firstBoot_eth1");
    marker.close();
    publishInventory();
    ASSERT_TRUE(processUntil([] { return pendingInterfaces.empty(); }));
    EXPECT_EQ(eth1.applied.size(), FORCE_SYNC_MAC_FROM_INVENTORY ? 1u : 0u);
    EXPECT_FALSE(EthInterfaceMatch);
    EXPECT_FALSE(MacAddressMatch);
}

} // namespace
} // namespace inventory
} // namespace phosphor::network
