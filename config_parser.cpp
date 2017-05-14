#include "config_parser.hpp"

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

Parser::Parser(const std::string& fileName, Mode mode)
{
    setFile(fileName, mode);
}


KeyValues& Parser::getSection(const std::string& section)
{
    auto it = sections.find(section);
    if (it == sections.end())
    {
        throw std::runtime_error("Section not found");
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
        throw std::runtime_error("Key not found");
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
    catch (std::exception& e)
    {
        return false;
    }
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
    catch (std::exception& e)
    {
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

void Parser::setFile(const std::string& fileName, Mode mode)
{
    using namespace std::string_literals;
    this->fileName = fileName;
    std::fstream stream;
    if (mode == Mode::READ)
    {
        stream.open(fileName, std::fstream::in);
    }
    else
    {
        stream.open(fileName, std::fstream::out);
    }

    if (!stream.is_open())
    {
        return;
    }
    //clear all the section data.
    sections.clear();
    parse(stream);
    stream.close();
 }

void Parser::remove(const std::string& section, const std::string& key ,
                    const std::string& value)
{
    auto keyValues = getSection(section);
    auto it = keyValues.find(key);

    if (it == keyValues.end())
    {
        throw std::runtime_error("Key not found");
    }

    for (; it != keyValues.end() && key == it->first; it++)
    {
        if (it->second == value)
        {
            break;
        }
    }

    if (it != keyValues.end())
    {

        keyValues.erase(it);
        sections[section] = keyValues;
    }
}

void Parser::writeToFile()
{
    std::fstream stream;
    stream.open(fileName, std::fstream::out);
    auto values = getValues("Match", "Name");
    //writing Match section
    stream << "[" << "Match" << "]\n\n";
    //Match will always be single entry.
    stream << "Name=" << values[0] << "\n\n";
    auto ipaddresses = getValues("Network", "Address");
    auto gateways = getValues("Network", "Gateway");
    stream << "[" << "Network" << "]\n\n";
    auto it1 = gateways.begin();
    auto it2 = ipaddresses.begin();
    for (it1 = gateways.begin(), it2 = ipaddresses.begin() ;
         it1 != gateways.end() && it2 != ipaddresses.end(); it1++, it2++)
    {
        stream << "Address=" << *it2 << "\n";
        stream << "Gateway=" << *it1 << "\n";
    }
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
