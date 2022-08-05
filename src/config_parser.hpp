#pragma once

#include <filesystem>
#include <optional>
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

/** @brief Compare in (case insensitive) vs expected (sensitive) */
bool icaseeq(std::string_view in, std::string_view expected) noexcept;
/** @brief Turns a systemd bool string into a c++ bool */
std::optional<bool> parseBool(std::string_view in) noexcept;

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

    /** @brief Determine if there were warnings parsing the file
     *  @return The number of parsing issues in the file
     */
    inline const std::vector<std::string>& getWarnings() const noexcept
    {
        return warnings;
    }

    /** @brief Set the file name and parse it.
     *  @param[in] filename - Absolute path of the file.
     */
    void setFile(const fs::path& filename);

  private:
    SectionMap sections;
    std::vector<std::string> warnings;
};

} // namespace config
} // namespace network
} // namespace phosphor
