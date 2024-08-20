/**
 * Copyright © 2018 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "argument.hpp"

#include <algorithm>
#include <iostream>
#include <iterator>

namespace phosphor
{
namespace network
{
namespace ncsi
{

ArgumentParser::ArgumentParser(int argc, char** argv)
{
    int option = 0;
    while (-1 != (option = getopt_long(argc, argv, optionStr, options, NULL)))
    {
        if ((option == '?') || (option == 'h'))
        {
            usage(argv);
            exit(-1);
        }

        auto i = &options[0];
        while ((i->val != option) && (i->val != 0))
        {
            ++i;
        }

        if (i->val)
        {
            arguments[i->name] = (i->has_arg ? optarg : trueString);
        }
    }
}

const std::string& ArgumentParser::operator[](const std::string& opt)
{
    auto i = arguments.find(opt);
    if (i == arguments.end())
    {
        return emptyString;
    }
    else
    {
        return i->second;
    }
}

void ArgumentParser::usage(char** argv)
{
    std::cerr << "Usage: " << argv[0] << " [options]\n";
    std::cerr
        << "Options:\n"
           "    --help | -h       Print this menu.\n"
           "    --index=<device index> | -x <device index> Specify device ifindex.\n"
           "    --package=<package> | -p <package> Specify a package.\n"
           "    --channel=<channel> | -c <channel> Specify a channel.\n"
           "    --info  | -i      Retrieve info about NCSI topology.\n"
           "    --set   | -s      Set a specific package/channel.\n"
           "    --clear | -r      Clear all the settings on the interface.\n"
           "    --oem-payload=<hex data...> | -o <hex data...> Send an OEM command with payload.\n"
           "\n"
           "Example commands:\n"
           "    1) Retrieve topology information:\n"
           "         ncsi-netlink -x 3 -p 0 -i\n"
           "    2) Set preferred package\n"
           "         ncsi-netlink -x 3 -p 0 -s\n"
           "    3) Set preferred channel\n"
           "         ncsi-netlink -x 3 -p 0 -c 1 -s\n"
           "    4) Clear preferred channel\n"
           "         ncsi-netlink -x 3 -p 0 -r\n"
           "    5) Send NCSI Command\n"
           "         ncsi-netlink -x 3 -p 0 -c 0 -o 50000001572100\n"
           "    6) Disable Global Multicast Filter\n"
           "         ncsi-netlink -x 2 -p 0 -c 0 -m"
           "\n";
}

const option ArgumentParser::options[] = {
    {"info", no_argument, NULL, 'i'},
    {"set", no_argument, NULL, 's'},
    {"clear", no_argument, NULL, 'r'},
    {"dgmf", no_argument, NULL, 'm'},
    {"oem-payload", required_argument, NULL, 'o'},
    {"package", required_argument, NULL, 'p'},
    {"channel", required_argument, NULL, 'c'},
    {"index", required_argument, NULL, 'x'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

const char* ArgumentParser::optionStr = "irsmx:o:p:c:h?";

const std::string ArgumentParser::trueString = "true";
const std::string ArgumentParser::emptyString = "";

} // namespace ncsi
} // namespace network
} // namespace phosphor
