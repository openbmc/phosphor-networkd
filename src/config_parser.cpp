#include "config_parser.hpp"

#include <fstream>
#include <regex>
#include <string>

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

void Parser::setValue(const std::string& section, const std::string& key,
                      const std::string& value)
{
    auto sit = sections.find(section);
    if (sit == sections.end())
    {
        std::tie(sit, std::ignore) = sections.emplace(section, KeyValuesMap{});
    }
    auto kit = sit->second.find(key);
    if (kit == sit->second.end())
    {
        std::tie(kit, std::ignore) = sit->second.emplace(key, ValueList{});
    }
    kit->second.push_back(value);
}

void Parser::setFile(const fs::path& filename)
{
    std::fstream stream(filename, std::fstream::in);
    if (!stream.is_open())
    {
        return;
    }
    // clear all the section data.
    sections.clear();
    static const std::regex commentRegex{R"x(\s*[;#])x"};
    static const std::regex sectionRegex{R"x(\s*\[([^\]]+)\])x"};
    static const std::regex valueRegex{R"x(\s*(\S[^ \t=]*)\s*=\s*(\S+)\s*$)x"};
    std::string section;
    std::smatch pieces;
    for (std::string line; std::getline(stream, line);)
    {
        if (line.empty() || std::regex_match(line, pieces, commentRegex))
        {
            // skip comment lines and blank lines
        }
        else if (std::regex_match(line, pieces, sectionRegex))
        {
            if (pieces.size() == 2)
            {
                section = pieces[1].str();
            }
        }
        else if (std::regex_match(line, pieces, valueRegex))
        {
            if (pieces.size() == 3)
            {
                setValue(section, pieces[1].str(), pieces[2].str());
            }
        }
    }
}

} // namespace config
} // namespace network
} // namespace phosphor
