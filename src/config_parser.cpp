#include "config_parser.hpp"

#include <fmt/compile.h>
#include <fmt/format.h>

#include <functional>
#include <iterator>
#include <stdplus/exception.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/line.hpp>
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
    return dir / fmt::format(FMT_COMPILE("00-bmc-{}.network"), intf);
}

fs::path pathForIntfDev(const fs::path& dir, std::string_view intf)
{
    return dir / fmt::format(FMT_COMPILE("{}.netdev"), intf);
}

Parser::Parser(const fs::path& filename)
{
    setFile(filename);
}

const ValueList& Parser::getValues(std::string_view section,
                                   std::string_view key) const noexcept
{
    static const ValueList empty;
    auto sit = sections.find(section);
    if (sit == sections.end())
    {
        return empty;
    }

    auto kit = sit->second.find(key);
    if (kit == sit->second.end())
    {
        return empty;
    }

    return kit->second;
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
    std::reference_wrapper<const fs::path> filename;
    SectionMap sections;
    KeyValuesMap* section;
    std::vector<std::string> warnings;
    size_t lineno;

    inline Parse(const fs::path& filename) :
        filename(filename), section(nullptr), lineno(0)
    {
    }

    void pumpSection(std::string_view line)
    {
        auto cpos = line.find(']');
        if (cpos == line.npos)
        {
            warnings.emplace_back(fmt::format("{}:{}: Section missing ]",
                                              filename.get().native(), lineno));
        }
        else
        {
            for (auto c : line.substr(cpos + 1))
            {
                if (!isspace(c))
                {
                    warnings.emplace_back(
                        fmt::format("{}:{}: Characters outside section name",
                                    filename.get().native(), lineno));
                    break;
                }
            }
        }
        auto s = line.substr(0, cpos);
        auto it = sections.find(s);
        if (it == sections.end())
        {
            std::tie(it, std::ignore) =
                sections.emplace(Section(s), KeyValuesMap{});
        }
        section = &it->second;
    }

    void pumpKV(std::string_view line)
    {
        auto epos = line.find('=');
        std::vector<std::string> new_warnings;
        if (epos == line.npos)
        {
            new_warnings.emplace_back(fmt::format(
                "{}:{}: KV missing `=`", filename.get().native(), lineno));
        }
        auto k = line.substr(0, epos);
        removePadding(k);
        if (section == nullptr)
        {
            new_warnings.emplace_back(
                fmt::format("{}:{}: Key `{}` missing section",
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
            std::tie(it, std::ignore) = section->emplace(Key(k), ValueList{});
        }
        it->second.emplace_back(v);
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
    catch (const std::exception& e)
    {
        // TODO: Pass exceptions once callers can handle them
        parse.warnings.emplace_back(
            fmt::format("{}: Read error: {}", filename.native(), e.what()));
    }

    this->filename = filename;
    this->sections = std::move(parse.sections);
    this->warnings = std::move(parse.warnings);
}

} // namespace config
} // namespace network
} // namespace phosphor
