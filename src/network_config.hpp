#include <filesystem>
#include <string_view>

namespace phosphor
{
namespace network
{

namespace bmc
{
void writeDHCPDefault(const std::filesystem::path& filename,
                      std::string_view interface);
}

} // namespace network
} // namespace phosphor
