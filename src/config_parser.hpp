#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <ostream>
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

template <typename T, typename Check>
class Checked
{
  public:
    struct unchecked
    {
    };

    template <typename... Args>
    inline constexpr Checked(Args&&... args) :
        t(conCheck(std::forward<Args>(args)...))
    {
    }

    template <typename... Args>
    inline constexpr Checked(unchecked, Args&&... args) :
        t(std::forward<Args>(args)...)
    {
    }

    inline const T& get() const noexcept
    {
        return t;
    }

    inline constexpr operator const T&() const noexcept
    {
        return t;
    }

    inline constexpr bool operator==(const auto& rhs) const
    {
        return t == rhs;
    }

  private:
    T t;

    template <typename... Args>
    inline static constexpr T conCheck(Args&&... args)
    {
        T t(std::forward<Args>(args)...);
        Check{}(t);
        return t;
    }
};

template <typename T, typename Check>
inline constexpr bool operator==(const auto& lhs, const Checked<T, Check>& rhs)
{
    return lhs == rhs.get();
}

template <typename T, typename Check>
inline constexpr std::ostream& operator<<(std::ostream& s,
                                          const Checked<T, Check>& rhs)
{
    return s << rhs.get();
}

struct KeyCheck
{
    void operator()(const std::string& s);
};
struct SectionCheck
{
    void operator()(const std::string& s);
};
struct ValueCheck
{
    void operator()(const std::string& s);
};

struct string_hash : public std::hash<std::string_view>
{
    using is_transparent = void;

    template <typename T>
    inline size_t operator()(const Checked<std::string, T>& t) const
    {
        return static_cast<const std::hash<std::string_view>&>(*this)(t.get());
    }
    template <typename T>
    inline size_t operator()(const T& t) const
    {
        return static_cast<const std::hash<std::string_view>&>(*this)(t);
    }
};

using Key = Checked<std::string, KeyCheck>;
using Section = Checked<std::string, SectionCheck>;
using Value = Checked<std::string, ValueCheck>;
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
    SectionMap map;

    Parser() = default;

    /** @brief Constructor
     *  @param[in] filename - Absolute path of the file which will be parsed.
     */
    Parser(const fs::path& filename);

    /** @brief Determine if there were warnings parsing the file
     *  @return The number of parsing issues in the file
     */
    inline size_t getWarnings() const noexcept
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

    /** @brief Write the current config to a file */
    void writeFile() const;
    void writeFile(const fs::path& filename);

  private:
    fs::path filename;
    size_t warnings = 0;
};

} // namespace config
} // namespace network
} // namespace phosphor
