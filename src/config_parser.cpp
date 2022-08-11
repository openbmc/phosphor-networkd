#include "config_parser.hpp"

#include <fmt/format.h>

#include <stdexcept>
#include <stdplus/exception.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/fmt.hpp>
#include <stdplus/fd/line.hpp>
#include <string>
#include <utility>

namespace phosphor
{
namespace network
{
namespace config
{

using std::literals::string_view_literals::operator""sv;

bool icaseeq(std::string_view in, std::string_view expected) noexcept
{
    return std::equal(in.begin(), in.end(), expected.begin(), expected.end(),
                      [](auto a, auto b) { return tolower(a) == b; });
}

std::optional<bool> parseBool(std::string_view in) noexcept
{
    if (in == "1"sv || icaseeq(in, "yes"sv) || icaseeq(in, "y"sv) ||
        icaseeq(in, "true"sv) || icaseeq(in, "t"sv) || icaseeq(in, "on"sv))
    {
        return true;
    }
    if (in == "0"sv || icaseeq(in, "no"sv) || icaseeq(in, "n"sv) ||
        icaseeq(in, "false"sv) || icaseeq(in, "f"sv) || icaseeq(in, "off"sv))
    {
        return false;
    }
    return std::nullopt;
}

fs::path pathForIntfConf(const fs::path& dir, std::string_view intf)
{
    return dir / fmt::format("00-bmc-{}.network", intf);
}

fs::path pathForIntfDev(const fs::path& dir, std::string_view intf)
{
    return dir / fmt::format("{}.netdev", intf);
}

const std::string*
    SectionMap::getLastValueString(std::string_view section,
                                   std::string_view key) const noexcept
{
    auto sit = find(section);
    if (sit == end())
    {
        return nullptr;
    }
    for (auto it = sit->second.rbegin(); it != sit->second.rend(); ++it)
    {
        auto kit = it->find(key);
        if (kit == it->end() || kit->second.empty())
        {
            continue;
        }
        return &kit->second.back().get();
    }
    return nullptr;
}

std::vector<std::string> SectionMap::getValueStrings(std::string_view section,
                                                     std::string_view key) const
{
    return getValues(section, key,
                     [](const Value& v) { return std::string(v); });
}

void KeyCheck::operator()(const std::string& s)
{
    for (auto c : s)
    {
        if (c == '\n' || c == '=')
        {
            throw std::invalid_argument(
                fmt::format("Invalid Config Key: {}", s));
        }
    }
}

void SectionCheck::operator()(const std::string& s)
{
    for (auto c : s)
    {
        if (c == '\n' || c == ']')
        {
            throw std::invalid_argument(
                fmt::format("Invalid Config Section: {}", s));
        }
    }
}

void ValueCheck::operator()(const std::string& s, const char* msg)
{
    for (auto c : s)
    {
        if (c == '\n')
        {
            throw std::invalid_argument(
                fmt::format("Invalid Config Value {}: {}", msg, s));
        }
    }
}

Parser::Parser(const fs::path& filename)
{
    setFile(filename);
}

inline bool isspace(char c) noexcept
{
    return c == ' ' || c == '\t';
}

inline bool iscomment(char c) noexcept
{
    return c == '#' || c == ';';
}

static void removePadding(std::string_view& str) noexcept
{
    size_t idx = str.size();
    for (; idx > 0 && isspace(str[idx - 1]); idx--)
        ;
    str.remove_suffix(str.size() - idx);

    idx = 0;
    for (; idx < str.size() && isspace(str[idx]); idx++)
        ;
    str.remove_prefix(idx);
}

struct Parse
{
    SectionMap map;
    KeyValuesMap* section = nullptr;
    size_t warnings = 0;

    void pumpSection(std::string_view line)
    {
        auto cpos = line.find(']');
        if (cpos == line.npos)
        {
            warnings++;
        }
        else
        {
            for (auto c : line.substr(cpos + 1))
            {
                if (!isspace(c))
                {
                    warnings++;
                    break;
                }
            }
        }
        auto s = line.substr(0, cpos);
        auto it = map.find(s);
        if (it == map.end())
        {
            std::tie(it, std::ignore) = map.emplace(
                Section(Section::unchecked(), s), KeyValuesMapList{});
        }
        section = &it->second.emplace_back();
    }

    void pumpKV(std::string_view line)
    {
        auto epos = line.find('=');
        size_t old_warnings = warnings;
        if (epos == line.npos)
        {
            warnings++;
        }
        if (section == nullptr)
        {
            warnings++;
        }
        if (old_warnings != warnings)
        {
            return;
        }
        auto k = line.substr(0, epos);
        removePadding(k);
        auto v = line.substr(epos + 1);
        removePadding(v);

        auto it = section->find(k);
        if (it == section->end())
        {
            std::tie(it, std::ignore) =
                section->emplace(Key(Key::unchecked(), k), ValueList{});
        }
        it->second.emplace_back(Value::unchecked(), v);
    }

    void pump(std::string_view line)
    {
        for (size_t i = 0; i < line.size(); ++i)
        {
            auto c = line[i];
            if (iscomment(c))
            {
                return;
            }
            else if (c == '[')
            {
                return pumpSection(line.substr(i + 1));
            }
            else if (!isspace(c))
            {
                return pumpKV(line.substr(i));
            }
        }
    }
};

void Parser::setFile(const fs::path& filename)
{
    Parse parse;

    try
    {
        auto fd = stdplus::fd::open(filename.c_str(),
                                    stdplus::fd::OpenAccess::ReadOnly);
        stdplus::fd::LineReader reader(fd);
        while (true)
        {
            parse.pump(*reader.readLine());
        }
    }
    catch (const stdplus::exception::Eof&)
    {
    }
    catch (...)
    {
        // TODO: Pass exceptions once callers can handle them
        parse.warnings++;
    }

    this->map = std::move(parse.map);
    this->filename = filename;
    this->warnings = parse.warnings;
}

static void writeFileInt(const SectionMap& map, const fs::path& filename)
{
    stdplus::fd::FormatToFile out;
    for (const auto& [section, maps] : map)
    {
        for (const auto& map : maps)
        {
            out.append("[{}]\n", section.get());
            for (const auto& [key, vals] : map)
            {
                for (const auto& val : vals)
                {
                    out.append("{}={}\n", key.get(), val.get());
                }
            }
        }
    }
    out.commit(filename);
}

void Parser::writeFile() const
{
    writeFileInt(map, filename);
}

void Parser::writeFile(const fs::path& filename)
{
    writeFileInt(map, filename);
    this->filename = filename;
}

} // namespace config
} // namespace network
} // namespace phosphor
