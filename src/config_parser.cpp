#include "config_parser.hpp"

#include <stdplus/exception.hpp>
#include <stdplus/fd/atomic.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/fmt.hpp>
#include <stdplus/fd/line.hpp>
#include <stdplus/str/cat.hpp>

#include <format>
#include <functional>
#include <iterator>
#include <stdexcept>
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
    return dir / stdplus::strCat("00-bmc-"sv, intf, ".network"sv);
}

fs::path pathForIntfDev(const fs::path& dir, std::string_view intf)
{
    return dir / stdplus::strCat(intf, ".netdev"sv);
}

const std::string* SectionMap::getLastValueString(
    std::string_view section, std::string_view key) const noexcept
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

void KeyCheck::operator()(std::string_view s)
{
    for (auto c : s)
    {
        if (c == '\n' || c == '=')
        {
            throw std::invalid_argument(
                stdplus::strCat("Invalid Config Key: "sv, s));
        }
    }
}

void SectionCheck::operator()(std::string_view s)
{
    for (auto c : s)
    {
        if (c == '\n' || c == ']')
        {
            throw std::invalid_argument(
                stdplus::strCat("Invalid Config Section: "sv, s));
        }
    }
}

void ValueCheck::operator()(std::string_view s)
{
    for (auto c : s)
    {
        if (c == '\n')
        {
            throw std::invalid_argument(
                stdplus::strCat("Invalid Config Value: "sv, s));
        }
    }
}

Parser::Parser(const fs::path& filename)
{
    setFile(filename);
}

constexpr bool isspace(char c) noexcept
{
    return c == ' ' || c == '\t';
}

constexpr bool iscomment(char c) noexcept
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
    std::reference_wrapper<const fs::path> filename;
    SectionMap map;
    KeyValuesMap* section;
    std::vector<std::string> warnings;
    size_t lineno;

    inline Parse(const fs::path& filename) :
        filename(filename), section(nullptr), lineno(0)
    {}

    void pumpSection(std::string_view line)
    {
        auto cpos = line.find(']');
        if (cpos == line.npos)
        {
            warnings.emplace_back(std::format("{}:{}: Section missing ]",
                                              filename.get().native(), lineno));
        }
        else
        {
            for (auto c : line.substr(cpos + 1))
            {
                if (!isspace(c))
                {
                    warnings.emplace_back(
                        std::format("{}:{}: Characters outside section name",
                                    filename.get().native(), lineno));
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
        std::vector<std::string> new_warnings;
        if (epos == line.npos)
        {
            new_warnings.emplace_back(std::format(
                "{}:{}: KV missing `=`", filename.get().native(), lineno));
        }
        auto k = line.substr(0, epos);
        removePadding(k);
        if (section == nullptr)
        {
            new_warnings.emplace_back(
                std::format("{}:{}: Key `{}` missing section",
                            filename.get().native(), lineno, k));
        }
        if (!new_warnings.empty())
        {
            warnings.insert(warnings.end(),
                            std::make_move_iterator(new_warnings.begin()),
                            std::make_move_iterator(new_warnings.end()));
            return;
        }
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
        lineno++;
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
    Parse parse(filename);

    bool fileExists = true;
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
    {}
    catch (const std::system_error& e)
    {
        fileExists = false;
        // TODO: Pass exceptions once callers can handle them
        parse.warnings.emplace_back(
            std::format("{}: Open error: {}", filename.native(), e.what()));
    }

    this->map = std::move(parse.map);
    this->fileExists = fileExists;
    this->filename = filename;
    this->warnings = std::move(parse.warnings);
}

static void writeFileInt(const SectionMap& map, const fs::path& filename)
{
    stdplus::fd::AtomicWriter writer(filename, 0644);
    stdplus::fd::FormatBuffer out(writer);
    for (const auto& [section, maps] : map)
    {
        for (const auto& map : maps)
        {
            out.appends("["sv, section.get(), "]\n"sv);
            for (const auto& [key, vals] : map)
            {
                for (const auto& val : vals)
                {
                    out.appends(key.get(), "="sv, val.get(), "\n"sv);
                }
            }
        }
    }
    out.flush();
    writer.commit();
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
