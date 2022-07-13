#include <testutil.hpp>
#include <fmt/format.h>
#include <filesystem>

namespace phosphor
{
namespace network
{

TestWithTmp::TestWithTmp()
{
	std::filesystem::create_directory(CaseTmpDir());
}

TestWithTmp::~TestWithTmp()
{
	std::filesystem::remove_all(CaseTmpDir());
}

void TestWithTmp::SetUpTestSuite()
{
	std::filesystem::create_directory(SuiteTmpDir());
}

void TestWithTmp::TearDownTestSuite()
{
	std::filesystem::remove_all(SuiteTmpDir());
}

std::string TestWithTmp::SuiteTmpDir()
{
	return fmt::format("{}/{}-{}", getenv("TMPDIR"), ::testing::UnitTest::GetInstance()->current_test_suite()->name(), getpid());
}

std::string TestWithTmp::CaseTmpDir() const
{
	return fmt::format("{}/{}", SuiteTmpDir(), ::testing::UnitTest::GetInstance()->current_test_info()->name());
}

}
}
