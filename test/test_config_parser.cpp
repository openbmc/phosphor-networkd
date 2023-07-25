#include "config_parser.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <stdplus/fd/atomic.hpp>
#include <stdplus/fd/fmt.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <stdplus/print.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <exception>
#include <format>
#include <fstream>
#include <stdexcept>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace config
{

using testing::ElementsAre;
using std::literals::string_view_literals::operator""sv;

TEST(TestConvert, iCaseEq)
{
    EXPECT_TRUE(icaseeq("VaL", "val"));
    EXPECT_TRUE(icaseeq("[ab1", "[ab1"));
}

TEST(TestConvert, ParseBool)
{
    EXPECT_TRUE(parseBool("tRue").value());
    EXPECT_FALSE(parseBool("tru").has_value());
    EXPECT_TRUE(parseBool("t").value());
    EXPECT_TRUE(parseBool("Yes").value());
    EXPECT_FALSE(parseBool("ye").has_value());
    EXPECT_TRUE(parseBool("y").value());
    EXPECT_TRUE(parseBool("oN").value());

    EXPECT_FALSE(parseBool("fAlse").value());
    EXPECT_FALSE(parseBool("fal").has_value());
    EXPECT_FALSE(parseBool("f").value());
    EXPECT_FALSE(parseBool("No").value());
    EXPECT_FALSE(parseBool("n").value());
    EXPECT_FALSE(parseBool("oFf").value());
}

TEST(TestTypeChecking, Section)
{
    Section("");
    Section("fds#1!'\"");
    EXPECT_THROW(Section("fds]sf"), std::invalid_argument);
    EXPECT_THROW(Section("g\ng"), std::invalid_argument);
}

TEST(TestTypeChecking, Value)
{
    Value("");
    Value("=fds1!'\"#=");
    Value("fds]sf'' #");
    EXPECT_THROW(Value("g\ng"), std::invalid_argument);
}

TEST(TestTypeChecking, Key)
{
    Key("");
    Key("fds1!'\"#");
    Key("fds]sf'' #");
    EXPECT_THROW(Key("fds]sf'='"), std::invalid_argument);
    EXPECT_THROW(Key("g\ng"), std::invalid_argument);
}

class TestConfigParser : public stdplus::gtest::TestWithTmp
{
  public:
    std::string filename = std::format("{}/eth0.network", CaseTmpDir());
    Parser parser;

    void WriteSampleFile()
    {
        std::ofstream filestream(filename);
        filestream << "\n\n\n\nBad=key\n[Match]\n  # K=v \nName =eth0\n"
                   << "[Network\nDHCP=true\n[DHCP]\nClientIdentifier= mac\n"
                   << "[Network] a\nDHCP=false #hi\n\n\nDHCP  =   yes   \n"
                   << " [ SEC ] \n'DHCP#'=\"#hi\"\nDHCP#=ho\n[Network]\n"
                   << "Key=val\nAddress=::/0\n[]\n=\nKey";
        filestream.close();
    }

    void ValidateSectionMap()
    {
        EXPECT_THAT(
            parser.map,
            testing::ContainerEq(SectionMap(SectionMapInt{
                {"Match", {{{"Name", {"eth0"}}}}},
                {"Network",
                 {
                     {{"DHCP", {"true"}}},
                     {{"DHCP", {"false #hi", "yes"}}},
                     {{"Key", {"val"}}, {"Address", {"::/0"}}},
                 }},
                {"DHCP", {{{"ClientIdentifier", {"mac"}}}}},
                {" SEC ", {{{"'DHCP#'", {"\"#hi\""}}, {"DHCP#", {"ho"}}}}},
                {"", {{{"", {""}}}}},
            })));
    }
};

TEST_F(TestConfigParser, EmptyObject)
{
    EXPECT_FALSE(parser.getFileExists());
    EXPECT_TRUE(parser.getFilename().empty());
    EXPECT_EQ(0, parser.getWarnings().size());
    EXPECT_EQ(SectionMap(), parser.map);
}

TEST_F(TestConfigParser, ReadDirectory)
{
    parser.setFile("/");
    EXPECT_FALSE(parser.getFileExists());
    EXPECT_EQ("/", parser.getFilename());
    EXPECT_EQ(1, parser.getWarnings().size());
    EXPECT_EQ(SectionMap(), parser.map);
}

TEST_F(TestConfigParser, ReadConfigDataMissingFile)
{
    parser.setFile("/no-such-path");
    EXPECT_FALSE(parser.getFileExists());
    EXPECT_EQ("/no-such-path", parser.getFilename());
    EXPECT_EQ(1, parser.getWarnings().size());
    EXPECT_EQ(SectionMap(), parser.map);
}

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{
    WriteSampleFile();
    parser.setFile(filename);
    EXPECT_TRUE(parser.getFileExists());
    EXPECT_EQ(filename, parser.getFilename());
    EXPECT_EQ(4, parser.getWarnings().size());
    ValidateSectionMap();

    const auto& map = parser.map;

    EXPECT_EQ("eth0", *map.getLastValueString("Match", "Name"));
    EXPECT_EQ("yes", *map.getLastValueString("Network", "DHCP"));
    EXPECT_EQ(nullptr, map.getLastValueString("Match", "BadKey"));
    EXPECT_EQ(nullptr, map.getLastValueString("BadSec", "Name"));
    EXPECT_EQ(nullptr, map.getLastValueString("BadSec", "Name"));

    EXPECT_THAT(map.getValueStrings("Match", "Name"), ElementsAre("eth0"));
    EXPECT_THAT(map.getValueStrings("DHCP", "ClientIdentifier"),
                ElementsAre("mac"));
    EXPECT_THAT(map.getValueStrings("Network", "DHCP"),
                ElementsAre("true", "false #hi", "yes"));
    EXPECT_THAT(map.getValueStrings(" SEC ", "'DHCP#'"),
                ElementsAre("\"#hi\""));
    EXPECT_THAT(map.getValueStrings("Blah", "nil"), ElementsAre());
    EXPECT_THAT(map.getValueStrings("Network", "nil"), ElementsAre());
}

TEST_F(TestConfigParser, WriteConfigFile)
{
    WriteSampleFile();
    parser.setFile(filename);
    EXPECT_EQ(4, parser.getWarnings().size());
    ValidateSectionMap();

    parser.writeFile();

    parser.setFile(filename);
    EXPECT_EQ(0, parser.getWarnings().size());
    ValidateSectionMap();
}

TEST_F(TestConfigParser, Perf)
{
    GTEST_SKIP();
    stdplus::fd::AtomicWriter file(std::format("{}/tmp.XXXXXX", CaseTmpDir()),
                                   0600);
    stdplus::fd::FormatBuffer out(file);
    std::string obj(500, 'a');
    std::string kv(500 * 70, 'b');
    for (size_t i = 0; i < 500; ++i)
    {
        out.appends("["sv, std::string_view{obj}.substr(0, i + 1), "[\n"sv);
        for (size_t j = 0; j < 70; j++)
        {
            auto sv = std::string_view(kv).substr(0, i * 70 + j + 1);
            out.appends(sv, "="sv, sv, "\n"sv);
        }
    }
    out.flush();
    file.commit();

    auto start = std::chrono::steady_clock::now();
    parser.setFile(filename);
    stdplus::print("Duration: {}\n", std::chrono::steady_clock::now() - start);
    // Make sure this test isn't enabled
    EXPECT_FALSE(true);
}

} // namespace config
} // namespace network
} // namespace phosphor
