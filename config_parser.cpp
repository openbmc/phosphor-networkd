#include "config_parser.hpp"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <regex>
#include <list>

namespace phosphor
{
namespace network
{
namespace config
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Parser::Parser(const std::string& fileName)
{
    setFile(fileName);
}


KeyValues& Parser::getSection(const std::string& section)
{
    auto it = sections.find(section);
    if (it == sections.end())
    {
        log<level::ERR>("ConfigParser: Section not found");
        elog<InternalFailure>();
    }
    return it->second;
}

const std::vector<std::string> Parser::getValues(const std::string& section,
        const std::string& key)
{
    std::vector<std::string> values;
    auto keyValues = getSection(section);
    auto it = keyValues.find(key);
    if (it == keyValues.end())
    {
        log<level::ERR>("ConfigParser: Key not found");
        elog<InternalFailure>();
    }
    for (; it != keyValues.end() && key == it->first; it++)
    {
        values.push_back(it->second);
    }
    return values;
}


bool Parser::isValueExist(const std::string& section, const std::string& key,
                          const std::string& value)
{
    try
    {
        auto values = getValues(section, key);
        auto it = std::find(values.begin(), values.end(), value);
        return it != std::end(values) ? true : false;
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
    }
    return false;
}

void Parser::setValue(const std::string& section, const std::string& key,
                      const std::string& value)
{
    try
    {
        if (isValueExist(section, key, value))
        {
            return;
        }
        KeyValues values = getSection(section);
        values.emplace(key, value);
        sections[section] = values;
    }
    catch (InternalFailure& e)
    {
        // don't commit the error.
        KeyValues values;
        values.emplace(key, value);
        sections[section] = values;
    }
}


void Parser::print()
{
    for (auto section : sections)
    {
        std::cout << "[" << section.first << "]\n\n";
        for (auto keyValue : section.second)
        {
            std::cout << keyValue.first << "=" << keyValue.second << "\n";
        }
    }
}

void Parser::setFile(const std::string& fileName)
{
    using namespace std::string_literals;
    this->fileName = fileName;
    std::fstream stream;
    stream.open(fileName, std::fstream::in);

    if (!stream.is_open())
    {
        return;
    }
    //clear all the section data.
    sections.clear();
    parse(stream);
    stream.close();
 }

void Parser::parse(std::istream& in)
{
    static const std::regex commentRegex
    {
        R"x(\s*[;#])x"
    };
    static const std::regex sectionRegex
    {
        R"x(\s*\[([^\]]+)\])x"
    };
    static const std::regex valueRegex
    {
        R"x(\s*(\S[^ \t=]*)\s*=\s*((\s?\S+)+)\s*$)x"
    };
    std::string section;
    std::smatch pieces;
    for (std::string line; std::getline(in, line);)
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
            if (pieces.size() == 4)
            {
                setValue(section, pieces[1].str(), pieces[2].str());
            }
        }
    }
}
}//namespace config
}//namespace network
}//namespace phosphor
