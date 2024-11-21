/**
 * Copyright © 2018 IBM Corporation
 * Copyright © 2024 Code Construct
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
#include "ncsi_util.hpp"

#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>
#include <stdplus/str/conv.hpp>

#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

using namespace phosphor::network::ncsi;

struct GlobalOptions
{
    std::shared_ptr<Interface> interface;
    unsigned int package;
    std::optional<unsigned int> channel;
};

const struct option options[] = {
    {"package", required_argument, NULL, 'p'},
    {"channel", required_argument, NULL, 'c'},
    {"interface", required_argument, NULL, 'i'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

static void print_usage(const char* progname)
{
    // clang-format off
    std::cerr
        << "Usage:\n"
        "  " << progname << " <options> raw TYPE [PAYLOAD...]\n"
        "  " << progname << " <options> oem [PAYLOAD...]\n"
        "\n"
        "Global options:\n"
        "    --interface IFACE, -i  Specify net device by ifindex.\n"
        "    --package PACKAGE, -p  Specify a package.\n"
        "    --channel CHANNEL, -c  Specify a channel.\n"
        "\n"
        "Both --interface/-i and --package/-p are required.\n"
        "\n"
        "Subcommands:\n"
        "\n"
        "raw TYPE [PAYLOAD...]\n"
        "    Send a single command using raw type/payload data.\n"
        "        TYPE               NC-SI command type, in hex\n"
        "        PAYLOAD            Command payload bytes, as hex\n"
        "\n"
        "oem PAYLOAD\n"
        "    Send a single OEM command (type 0x50).\n"
        "        PAYLOAD            Command payload bytes, as hex\n";
    // clang-format on
}

static std::optional<unsigned int>
    parseUnsigned(const char* str, const char* label)
{
    try
    {
        return std::stoi(str, NULL, 16);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Invalid " << label << " argument '" << str << "'\n";
        return {};
    }
}

static std::optional<std::vector<unsigned char>>
    parsePayload(const std::string& str)
{
    if (str.length() % 2 != 0)
    {
        std::cerr << "Invalid payload length " << str.length()
                  << " (must be a multiple of 2 chars)\n";
        return {};
    }

    std::string_view sv(str);
    std::vector<unsigned char> payload;

    for (unsigned int i = 0; i < sv.size(); i += 2)
    {
        unsigned char byte;
        auto begin = sv.data() + i;
        auto end = begin + 2;

        auto [next, err] = std::from_chars(begin, end, byte, 16);

        if (err != std::errc() || next != end)
        {
            std::cerr << "Invalid payload string\n";
            return {};
        }
        payload.push_back(byte);
    }

    return payload;
}

static std::optional<std::tuple<GlobalOptions, int>>
    parseGlobalOptions(int argc, char* const* argv)
{
    std::optional<unsigned int> chan, package, interface;
    const char* progname = argv[0];
    GlobalOptions opts{};

    for (;;)
    {
        int opt = getopt_long(argc, argv, "p:c:i:h", options, NULL);
        if (opt == -1)
        {
            break;
        }

        switch (opt)
        {
            case 'i':
                interface = parseUnsigned(optarg, "interface");
                if (!interface.has_value())
                {
                    return {};
                }
                break;

            case 'p':
                package = parseUnsigned(optarg, "package");
                if (!package.has_value())
                {
                    return {};
                }
                break;

            case 'c':
                chan = parseUnsigned(optarg, "channel");
                if (!chan.has_value())
                {
                    return {};
                }
                opts.channel = *chan;
                break;

            case 'h':
            default:
                print_usage(progname);
                return {};
        }
    }

    if (!interface.has_value())
    {
        std::cerr << "Missing interface, add an --interface argument\n";
        return {};
    }

    if (!package.has_value())
    {
        std::cerr << "Missing package, add a --package argument\n";
        return {};
    }

    opts.interface = std::make_unique<NetlinkInterface>(*interface);
    opts.package = *package;

    return std::make_tuple(opts, optind);
}

static stdplus::StrBuf toHexStr(std::span<const uint8_t> c) noexcept
{
    stdplus::StrBuf ret;
    if (c.empty())
    {
        /* workaround for lg2's handling of string_view */
        *ret.data() = '\0';
        return ret;
    }
    stdplus::IntToStr<16, uint8_t> its;
    auto oit = ret.append(c.size() * 3);
    auto cit = c.begin();
    oit = its(oit, *cit++, 2);
    for (; cit != c.end(); ++cit)
    {
        *oit++ = ' ';
        oit = its(oit, *cit, 2);
    }
    *oit = 0;
    return ret;
}

/* Helper for the 'raw' and 'oem' command handlers: Construct a single command,
 * issue it to the interface, and print the resulting response payload.
 */
static int ncsiCommand(GlobalOptions options, uint8_t type,
                       std::vector<unsigned char> payload)
{
    NCSICommand cmd(type, options.package, options.channel, payload);

    lg2::debug("Command: type {TYPE}, payload {PAYLOAD_LEN} bytes: {PAYLOAD}",
               "TYPE", type, "PAYLOAD_LEN", payload.size(), "PAYLOAD",
               toHexStr(payload));

    auto resp = options.interface->sendCommand(cmd);
    if (!resp)
    {
        return -1;
    }

    lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN",
               resp->full_payload.size(), "DATA", toHexStr(resp->full_payload));

    return 0;
}

static int ncsiCommandRaw(GlobalOptions options, int argc,
                          const char* const* argv)
{
    std::vector<unsigned char> payload;
    std::optional<uint8_t> type;

    if (argc != 2 && argc != 3)
    {
        std::cerr << "Invalid arguments for 'raw' subcommand\n";
        return -1;
    }

    /* Not only does the type need to fit into one byte, but the top bit
     * is used for the request/response flag, so check for 0x80 here as
     * our max here.
     */
    type = parseUnsigned(argv[1], "command type");
    if (!type.has_value() || *type > 0x80)
    {
        std::cerr << "Invalid command type value\n";
        return -1;
    }

    if (argc == 3)
    {
        auto tmp = parsePayload(argv[2]);
        if (!tmp.has_value())
        {
            return -1;
        }

        payload = *tmp;
    }

    return ncsiCommand(options, *type, payload);
}

static int ncsiCommandOEM(GlobalOptions options, int argc,
                          const char* const* argv)
{
    constexpr uint8_t oemType = 0x50;

    if (argc != 2)
    {
        std::cerr << "Invalid arguments for 'oem' subcommand\n";
        return -1;
    }

    auto payload = parsePayload(argv[1]);
    if (!payload.has_value())
    {
        return -1;
    }

    return ncsiCommand(options, oemType, *payload);
}

/* A note on log output:
 * For output that relates to command-line usage, we just output directly to
 * stderr. Once we have a properly parsed command line invocation, we use lg2
 * for log output, as we want that to use the standard log facilities to
 * catch runtime error scenarios
 */
int main(int argc, char** argv)
{
    const char* progname = argv[0];

    auto opts = parseGlobalOptions(argc, argv);

    if (!opts.has_value())
    {
        return EXIT_FAILURE;
    }

    auto [globalOptions, consumed] = *opts;

    if (consumed >= argc)
    {
        std::cerr << "Missing subcommand command type\n";
        return {};
    }

    argc -= consumed;
    argv += consumed;

    std::string subcommand = argv[0];
    int ret = -1;

    if (subcommand == "raw")
    {
        ret = ncsiCommandRaw(globalOptions, argc, argv);
    }
    else if (subcommand == "oem")
    {
        ret = ncsiCommandOEM(globalOptions, argc, argv);
    }
    else
    {
        std::cerr << "Unknown subcommand '" << subcommand << "'\n";
        print_usage(progname);
    }

    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
