#pragma once

#include <filesystem>
#include <functional>
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

namespace fs = std::filesystem;

fs::path pathForIntfConf(const fs::path& dir, std::string_view intf);
fs::path pathForIntfDev(const fs::path& dir, std::string_view intf);

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
using KeyValuesMapList = std::vector<KeyValuesMap>;
using SectionMapInt =
    std::unordered_map<Section, KeyValuesMapList, string_hash, std::equal_to<>>;

class SectionMap : public SectionMapInt
{
  public:
    const std::string* getLastValueString(std::string_view section,
                                          std::string_view key) const noexcept;
    inline auto getValues(std::string_view section, std::string_view key,
                          auto&& conv) const
    {
        std::vector<std::invoke_result_t<decltype(conv), const Value&>> values;
        auto sit = find(section);
        if (sit == end())
        {
            return values;
        }
        for (const auto& secv : sit->second)
        {
            auto kit = secv.find(key);
            if (kit == secv.end())
            {
                continue;
            }
            for (auto v : kit->second)
            {
                values.push_back(conv(v));
            }
        }
        return values;
    }
    std::vector<std::string> getValueStrings(std::string_view section,
                                             std::string_view key) const;
};

class Parser
{
  public:
    Parser() = default;

    /** @brief Constructor
     *  @param[in] filename - Absolute path of the file which will be parsed.
     */
    Parser(const fs::path& filename);

    /** @brief Retrieve the map of all values in the file */
    inline const SectionMap& getMap() const noexcept
    {
        return sections;
    }

    /** @brief Determine if there were warnings parsing the file
     *  @return The number of parsing issues in the file
     */
    inline const std::vector<std::string>& getWarnings() const noexcept
    {
        return warnings;
    }

    /** @brief Get the filename last parsed successfully
     *  @return file path
     */
    inline const fs::path& getFilename() const noexcept
    {
        return filename;
    }

    /** @brief Set the file name and parse it.
     *  @param[in] filename - Absolute path of the file.
     */
    void setFile(const fs::path& filename);

  private:
    fs::path filename;
    SectionMap sections;
    std::vector<std::string> warnings;
};

} // namespace config
} // namespace network
} // namespace phosphor
