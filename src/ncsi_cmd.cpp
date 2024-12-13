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

#include <assert.h>
#include <getopt.h>
#include <linux/mctp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>
#include <stdplus/str/conv.hpp>

#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

using namespace phosphor::network::ncsi;

const uint32_t NCSI_CORE_DUMP_HANDLE = 0xFFFF0000;
const uint32_t NCSI_CRASH_DUMP_HANDLE = 0xFFFF0001;

struct GlobalOptions
{
    std::unique_ptr<Interface> interface;
    unsigned int package;
    std::optional<unsigned int> channel;
};

struct MCTPAddress
{
    int network;
    uint8_t eid;
};

const struct option options[] = {
    {"package", required_argument, NULL, 'p'},
    {"channel", required_argument, NULL, 'c'},
    {"interface", required_argument, NULL, 'i'},
    {"mctp", required_argument, NULL, 'm'},
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
        "    --mctp [NET,]EID, -m   Specify MCTP network device.\n"
        "    --package PACKAGE, -p  Specify a package.\n"
        "    --channel CHANNEL, -c  Specify a channel.\n"
        "\n"
        "A --package/-p argument is required, as well as interface type "
        "(--interface/-i or --mctp/-m)\n"
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
        "        PAYLOAD            Command payload bytes, as hex\n"
        "\n"
        "dump HANDLE FILE\n"
        "     Perform NCSI core/crash dump and save log to FILE.\n"
        "        HANDLE             Use 'ffff0000' for core dump or 'ffff0001' for crash dump.\n"
        "        FILE               The file to save the core/crash dump log.\n";
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

static std::optional<uint32_t> parseHexHandle(const std::string& handle)
{
    try
    {
        return static_cast<uint32_t>(std::stoul(handle, nullptr, 16));
    }
    catch (const std::exception& e)
    {
        std::cerr << "Invalid data handle argument: " << handle << "\n";
        return {};
    }
}

static std::optional<MCTPAddress> parseMCTPAddress(const std::string& str)
{
    std::string::size_type sep = str.find(',');
    std::string eid_str;
    MCTPAddress addr;

    if (sep == std::string::npos)
    {
        addr.network = MCTP_NET_ANY;
        eid_str = str;
    }
    else
    {
        std::string net_str = str.substr(0, sep);
        try
        {
            addr.network = stoi(net_str);
        }
        catch (const std::exception& e)
        {
            return {};
        }
        eid_str = str.substr(sep + 1);
    }

    try
    {
        addr.eid = stoi(eid_str);
    }
    catch (const std::exception& e)
    {
        return {};
    }

    return addr;
}

static std::optional<std::vector<unsigned char>>
    parsePayload(int argc, const char* const argv[])
{
    /* we have already checked that there are sufficient args in callers */
    assert(argc >= 1);

    std::vector<unsigned char> payload;

    /* we support two formats of payload - all as one argument:
     *   00010c202f
     *
     * or single bytes in separate arguments:
     *   00 01 0c 20 2f
     *
     * both are assumed as entirely hex, but the latter format does not
     * need to be exactly two chars per byte:
     *   0 1 c 20 2f
     */

    size_t len0 = strlen(argv[0]);
    if (argc == 1 && len0 > 2)
    {
        /* single argument format, parse as multiple bytes */
        if (len0 % 2 != 0)
        {
            std::cerr << "Invalid payload length " << len0
                      << " (must be a multiple of 2 chars)\n";
            return {};
        }

        std::string str(argv[0]);
        std::string_view sv(str);

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
    }
    else
    {
        /* multiple payload arguments, each is a separate hex byte */
        for (int i = 0; i < argc; i++)
        {
            unsigned char byte;
            auto begin = argv[i];
            auto end = begin + strlen(begin);

            auto [next, err] = std::from_chars(begin, end, byte, 16);

            if (err != std::errc() || next != end)
            {
                std::cerr << "Invalid payload argument '" << begin << "'\n";
                return {};
            }
            payload.push_back(byte);
        }
    }

    return payload;
}

static std::optional<std::tuple<GlobalOptions, int>>
    parseGlobalOptions(int argc, char* const* argv)
{
    std::optional<unsigned int> chan, package, interface;
    std::optional<MCTPAddress> mctp;
    const char* progname = argv[0];
    GlobalOptions opts{};

    for (;;)
    {
        /* We're using + here as we want to stop parsing at the subcommand
         * name
         */
        int opt = getopt_long(argc, argv, "+p:c:i:m:h", options, NULL);
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

            case 'm':
                mctp = parseMCTPAddress(optarg);
                if (!mctp.has_value())
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

    if (interface.has_value() && mctp.has_value())
    {
        std::cerr << "Only one of --interface or --mctp can be provided\n";
        return {};
    }
    else if (interface.has_value())
    {
        opts.interface = std::make_unique<NetlinkInterface>(*interface);
    }
    else if (mctp.has_value())
    {
        MCTPAddress m = *mctp;
        opts.interface = std::make_unique<MCTPInterface>(m.network, m.eid);
    }
    else
    {
        std::cerr << "Missing interface description, "
                     "add a --mctp or --interface argument\n";
        return {};
    }

    if (!package.has_value())
    {
        std::cerr << "Missing package, add a --package argument\n";
        return {};
    }

    opts.package = *package;

    return std::make_tuple(std::move(opts), optind);
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
static int ncsiCommand(GlobalOptions& options, uint8_t type,
                       std::vector<unsigned char> payload)
{
    NCSICommand cmd(type, options.package, options.channel, payload);

    lg2::debug("Command: type {TYPE}, payload {PAYLOAD_LEN} bytes: {PAYLOAD}",
               "TYPE", lg2::hex, type, "PAYLOAD_LEN", payload.size(), "PAYLOAD",
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

static int ncsiCommandRaw(GlobalOptions& options, int argc,
                          const char* const* argv)
{
    std::vector<unsigned char> payload;
    std::optional<uint8_t> type;

    if (argc < 2)
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

    if (argc >= 3)
    {
        auto tmp = parsePayload(argc - 2, argv + 2);
        if (!tmp.has_value())
        {
            return -1;
        }

        payload = *tmp;
    }

    return ncsiCommand(options, *type, payload);
}

static int ncsiCommandOEM(GlobalOptions& options, int argc,
                          const char* const* argv)
{
    constexpr uint8_t oemType = 0x50;

    if (argc < 2)
    {
        std::cerr << "Invalid arguments for 'oem' subcommand\n";
        return -1;
    }

    auto payload = parsePayload(argc - 1, argv + 1);
    if (!payload.has_value())
    {
        return -1;
    }

    return ncsiCommand(options, oemType, *payload);
}

static std::array<unsigned char, 12>
    generateDumpCmdPayload(uint32_t chunkNum, uint32_t dataHandle, bool isAbort)
{
    std::array<unsigned char, 12> payload = {0x00};

    if (chunkNum == 1)
    {
        // First chunk: Data Handle for core dump
        payload[3] = 0; // Opcode for the first chunk
        payload[8] = (dataHandle >> 24) & 0xFF;
        payload[9] = (dataHandle >> 16) & 0xFF;
        payload[10] = (dataHandle >> 8) & 0xFF;
        payload[11] = dataHandle;
    }
    else
    {
        if (isAbort)
        {
            // For subsequent chunks after abort: Use opcode for abort message
            payload[3] = 3; // Opcode for abort chunk
            payload[8] = (chunkNum >> 24) & 0xFF;
            payload[9] = (chunkNum >> 16) & 0xFF;
            payload[10] = (chunkNum >> 8) & 0xFF;
            payload[11] = chunkNum & 0xFF;
        }
        else
        {
            // For subsequent chunks: Use chunk number instead of data handle
            payload[3] = 2; // Opcode for next chunk
            payload[8] = (chunkNum >> 24) & 0xFF;
            payload[9] = (chunkNum >> 16) & 0xFF;
            payload[10] = (chunkNum >> 8) & 0xFF;
            payload[11] = chunkNum & 0xFF;
        }
    }

    return payload;
}

std::string getDescForResponse(uint16_t response)
{
    switch (response)
    {
        case 0x0000:
            return "Command Completed";
        case 0x0001:
            return "Command Failed";
        case 0x0002:
            return "Command Unavailable";
        case 0x0003:
            return "Command Unsupported";
        case 0x0004:
            return "Delayed Response";
        default:
            return "Unknown response code.";
    }
}

std::string getDescForReason(uint16_t reason)
{
    switch (reason)
    {
        case 0x0001:
            return "Interface Initialization Required";
        case 0x0002:
            return "Parameter Is Invalid, Unsupported, or Out-of-Range";
        case 0x0003:
            return "Channel Not Ready";
        case 0x0004:
            return "Package Not Ready";
        case 0x0005:
            return "Invalid Payload Length";
        case 0x0006:
            return "Information Not Available";
        case 0x0007:
            return "Intervention Required";
        case 0x0008:
            return "Link Command Failed - Hardware Access Error";
        case 0x0009:
            return "Command Timeout";
        case 0x000A:
            return "Secondary Device Not Powered";
        case 0x7FFF:
            return "Unknown/Unsupported Command Type";
        case 0x4D01:
            return "Abort Transfer: NC cannot proceed with transfer.";
        case 0x4D02:
            return "Invalid Handle Value: Data Handle is invalid or not supported.";
        case 0x4D03:
            return "Sequence Count Error: Chunk Number requested is not consecutive with the previous number transmitted.";
        default:
            if (reason >= 0x8000)
            {
                return "OEM Reason Code";
            }
            else
            {
                return "Unknown reason code.";
            }
    }
}

static int ncsiDump(GlobalOptions& options, uint32_t handle,
                    const std::string& fileName)
{
    constexpr auto ncsiCmdCoreDump = 0x4D;
    uint32_t chunkNum = 1;
    bool isTransferComplete = false;
    bool isAbort = false;
    uint8_t opcode = 0;
    uint32_t totalDataSize = 0;
    std::ofstream outFile(fileName, std::ios::binary);

    // Validate handle
    if (handle != NCSI_CORE_DUMP_HANDLE && handle != NCSI_CRASH_DUMP_HANDLE)
    {
        std::cerr
            << "Invalid data handle value. Expected NCSI_CORE_DUMP_HANDLE (0xFFFF0000) or NCSI_CRASH_DUMP_HANDLE (0xFFFF0001), got: "
            << std::hex << handle << "\n";
        return -1;
    }

    if (!outFile.is_open())
    {
        std::cerr << "Failed to open file: " << fileName << "\n";
        return -1;
    }

    while (!isTransferComplete)
    {
        auto payloadArray = generateDumpCmdPayload(chunkNum, handle, isAbort);
        std::vector<unsigned char> payload(payloadArray.begin(),
                                           payloadArray.end());

        NCSICommand cmd(ncsiCmdCoreDump, options.package, options.channel,
                        payload);
        auto resp = options.interface->sendCommand(cmd);
        if (!resp)
        {
            std::cerr << "Failed to send NCSI command for chunk number "
                      << chunkNum << "\n";
            return -1;
        }

        auto response = resp->response;
        auto reason = resp->reason;
        auto length = resp->payload.size();

        if (response != 0)
        {
            std::string responseDesc = getDescForResponse(response);
            std::string reasonDesc = getDescForReason(reason);
            std::cerr << "Error encountered:\n";
            std::cerr << "Response Description: " << responseDesc << "\n";
            std::cerr << "Reason   Description: " << reasonDesc << "\n";
            return -1;
        }

        if (length <= 8 && isAbort) // Abort handling
        {
            break;
        }
        else if (length > 8)
        {
            // Ensure length is 4-byte aligned
            if (length % 4 != 0)
            {
                std::cerr << "Packet length is not 4-byte aligned: " << length
                          << "\n";
                return -1;
            }

            auto dataSize = length - 8;
            totalDataSize += dataSize;
            opcode = resp->payload[7];
            std::cerr << "Response dataSize " << dataSize << " bytes\n";
            std::cerr << "totalDataSize " << totalDataSize << " bytes\n";
            std::cerr << "opcode " << static_cast<int>(opcode) << "\n";

            if (outFile.is_open())
            {
                outFile.write(
                    reinterpret_cast<const char*>(resp->payload.data() + 8),
                    dataSize);
            }
            else
            {
                std::cerr << "Failed to write to file. File is not open.\n";
            }
        }
        else
        {
            std::cerr << "Received response with insufficient payload length: "
                      << length << " Expected more than 8 bytes.\n";
        }

        switch (opcode)
        {
            case 0x1: // Initial chunk, continue to next
                if (chunkNum != 1)
                {
                    std::cerr << "Unexpected initial chunk number: " << chunkNum
                              << "\n";
                    return -1;
                }
                chunkNum++;
                break;
            case 0x2: // Middle chunk, continue to next
                if (chunkNum <= 1)
                {
                    std::cerr << "Unexpected middle chunk number: " << chunkNum
                              << "\n";
                    return -1;
                }
                chunkNum++;
                break;
            case 0x4: // Final chunk
            case 0x5: // Initial and final chunk
                isTransferComplete = true;
                break;
            case 0x8: // Abort transfer
                std::cerr << "Transfer aborted by NIC\n";
                isAbort = true;
                break;
            default:
                std::cerr << "Unexpected opcode: " << static_cast<int>(opcode)
                          << "\n";
                return -1;
        }
    }

    outFile.close();
    return 0;
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

    auto [globalOptions, consumed] = std::move(*opts);

    if (consumed >= argc)
    {
        std::cerr << "Missing subcommand command type\n";
        return {};
    }

    /* We have parsed the global options, advance argv & argc to allow the
     * subcommand handlers to consume their own options
     */
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
    else if (subcommand == "dump")
    {
        if (argc != 3)
        {
            std::cerr << "Invalid arguments for 'dump' subcommand\n";
            print_usage(progname);
            return -1;
        }

        auto handleOpt = parseHexHandle(argv[1]);
        if (!handleOpt.has_value())
        {
            return -1;
        }

        return ncsiDump(globalOptions, *handleOpt, argv[2]);
    }
    else
    {
        std::cerr << "Unknown subcommand '" << subcommand << "'\n";
        print_usage(progname);
    }

    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
