#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace phosphor
{
namespace network
{
namespace config
{

struct string_hash : public std::hash<std::string_view>
{
    using is_transparent = void;
};

using Key = std::string;
using Section = std::string;
using Value = std::string;
using ValueList = std::vector<Value>;
using KeyValuesMap =
    std::unordered_map<Key, ValueList, string_hash, std::equal_to<>>;
using SectionMap =
    std::unordered_map<Section, KeyValuesMap, string_hash, std::equal_to<>>;

namespace fs = std::filesystem;

class Parser
{
  public:
    Parser() = default;

    /** @brief Constructor
     *  @param[in] filename - Absolute path of the file which will be parsed.
     */

    Parser(const fs::path& filename);

    /** @brief Get the values of the given key and section.
     *  @param[in] section - section name.
     *  @param[in] key - key to look for.
     *  @returns   The ValueList or nullptr if no key + section exists.
     */
    const ValueList& getValues(std::string_view section,
                               std::string_view key) const noexcept;

    /** @brief Set the file name and parse it.
     *  @param[in] filename - Absolute path of the file.
     */
    void setFile(const fs::path& filename);

  private:
    SectionMap sections;
};

} // namespace config
} // namespace network
} // namespace phosphor
