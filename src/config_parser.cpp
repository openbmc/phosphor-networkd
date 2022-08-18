#include "config_parser.hpp"

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
    SectionMap sections;
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
            std::tie(it, std::ignore) = section->emplace(Key(k), ValueList{});
        }
        it->second.emplace_back(v);
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

    this->sections = std::move(parse.sections);
    this->warnings = parse.warnings;
}

} // namespace config
} // namespace network
} // namespace phosphor
