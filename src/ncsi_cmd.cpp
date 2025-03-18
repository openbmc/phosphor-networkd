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

#include <climits>
#include <fstream>
#include <iostream>
#include <map>
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
    std::optional<unsigned int> package;
    std::optional<unsigned int> channel;
};

struct MCTPAddress
{
    int network;
    uint8_t eid;
};

/* MCTP EIDs below 8 are invalid, 255 is broadcast */
static constexpr uint8_t MCTP_EID_MIN = 8;
static constexpr uint8_t MCTP_EID_MAX = 254;

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
        "    --package PACKAGE, -p  For non-discovery commands this is required; for discovery it is optional and\n"
        "                           restricts the discovery to a specific package index.\n"
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
        "core-dump FILE\n"
        "    Perform NCSI core dump and save log to FILE.\n"
        "\n"
        "crash-dump FILE\n"
        "    Perform NCSI crash dump and save log to FILE.\n";
    // clang-format on
}

static std::optional<unsigned int>
    parseUnsigned(const char* str, const char* label)
{
    try
    {
        unsigned long tmp = std::stoul(str, NULL, 16);
        if (tmp <= UINT_MAX)
            return tmp;
    }
    catch (const std::exception& e)
    {}
    std::cerr << "Invalid " << label << " argument '" << str << "'\n";
    return {};
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

    unsigned long tmp;
    try
    {
        tmp = stoul(eid_str);
    }
    catch (const std::exception& e)
    {
        return {};
    }

    if (tmp < MCTP_EID_MIN || tmp > MCTP_EID_MAX)
    {
        return {};
    }

    addr.eid = tmp;

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

static int ncsiCommandReceiveDump(GlobalOptions& options,
                                  const std::string& subcommand, int argc,
                                  const char* const* argv)
{
    if (argc != 2)
    {
        std::cerr << "Invalid arguments for '" << subcommand
                  << "' subcommand\n";
        print_usage(argv[0]); 
        return -1;
    }
    uint32_t handle = (subcommand == "core-dump") ? NCSI_CORE_DUMP_HANDLE :
                                                    NCSI_CRASH_DUMP_HANDLE;
    return ncsiDump(options, handle, argv[1]);
}

static std::array<unsigned char, 12>
    generateDumpCmdPayload(uint32_t chunkNum, uint32_t dataHandle, bool isAbort)
{
    std::array<unsigned char, 12> payload = {};
    uint8_t opcode;

    if (isAbort)
    {
        opcode = 3;
    }
    else if (chunkNum == 1)
    {
        // For the first chunk the chunk number field carries the data handle.
        opcode = 0;
        chunkNum = dataHandle;
    }
    else
    {
        opcode = 2;
    }
    payload[3] = opcode;
    payload[8] = (chunkNum >> 24) & 0xFF;
    payload[9] = (chunkNum >> 16) & 0xFF;
    payload[10] = (chunkNum >> 8) & 0xFF;
    payload[11] = chunkNum & 0xFF;

    return payload;
}

std::string getDescForResponse(uint16_t response)
{
    static const std::map<uint16_t, std::string> descMap = {
        {0x0000, "Command Completed"},
        {0x0001, "Command Failed"},
        {0x0002, "Command Unavailable"},
        {0x0003, "Command Unsupported"},
        {0x0004, "Delayed Response"}};

    try
    {
        return descMap.at(response);
    }
    catch (std::exception&)
    {
        return "Unknown response code: " + std::to_string(response);
    }
}

std::string getDescForReason(uint16_t reason)
{
    static const std::map<uint16_t, std::string> reasonMap = {
        {0x0001, "Interface Initialization Required"},
        {0x0002, "Parameter Is Invalid, Unsupported, or Out-of-Range"},
        {0x0003, "Channel Not Ready"},
        {0x0004, "Package Not Ready"},
        {0x0005, "Invalid Payload Length"},
        {0x0006, "Information Not Available"},
        {0x0007, "Intervention Required"},
        {0x0008, "Link Command Failed - Hardware Access Error"},
        {0x0009, "Command Timeout"},
        {0x000A, "Secondary Device Not Powered"},
        {0x7FFF, "Unknown/Unsupported Command Type"},
        {0x4D01, "Abort Transfer: NC cannot proceed with transfer."},
        {0x4D02,
         "Invalid Handle Value: Data Handle is invalid or not supported."},
        {0x4D03,
         "Sequence Count Error: Chunk Number requested is not consecutive with the previous number transmitted."}};

    if (reason >= 0x8000)
    {
        return "OEM Reason Code" + std::to_string(reason);
    }

    try
    {
        return reasonMap.at(reason);
    }
    catch (std::exception&)
    {
        return "Unknown reason code: " + std::to_string(reason);
    }
}

static int ncsiDump(GlobalOptions& options, uint32_t handle,
                    const std::string& fileName)
{
    constexpr auto ncsiCmdDump = 0x4D;
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
        if (outFile.is_open())
            outFile.close();
        return -1;
    }

    if (!outFile.is_open())
    {
        std::cerr << "Failed to open file: " << fileName << "\n";
        return -1;
    }

    while (!isTransferComplete && !isAbort)
    {
        auto payloadArray = generateDumpCmdPayload(chunkNum, handle, false);
        std::span<const unsigned char> payload(payloadArray.data(),
                                               payloadArray.size());

        NCSICommand cmd(ncsiCmdDump, options.package, options.channel, payload);
        auto resp = options.interface->sendCommand(cmd);
        if (!resp)
        {
            std::cerr << "Failed to send NCSI command for chunk number "
                      << chunkNum << "\n";
            outFile.close();
            return -1;
        }

        auto response = resp->response;
        auto reason = resp->reason;
        auto length = resp->payload.size();

        if (response != 0)
        {
            std::cerr << "Error encountered on chunk " << chunkNum << ":\n"
                      << "Response Description: "
                      << getDescForResponse(response) << "\n"
                      << "Reason Description: " << getDescForReason(reason)
                      << "\n";
            outFile.close();
            return -1;
        }

        if (length > 8)
        {
            auto dataSize = length - 8;
            totalDataSize += dataSize;
            opcode = resp->payload[7];
            if (outFile.is_open())
            {
                outFile.write(
                    reinterpret_cast<const char*>(resp->payload.data() + 8),
                    dataSize);
            }
            else
            {
                std::cerr << "Failed to write to file. File is not open.\n";
                isAbort = true;
            }
        }
        else
        {
            std::cerr << "Received response with insufficient payload length: "
                      << length << " Expected more than 8 bytes.  Chunk: "
                      << chunkNum << "\n";
            isAbort = true;
        }

        switch (opcode)
        {
            case 0x1: // Initial chunk, continue to next
            case 0x2: // Middle chunk, continue to next
                chunkNum++;
                break;
            case 0x4: // Final chunk
            case 0x5: // Initial and final chunk
                isTransferComplete = true;
                break;
            case 0x8: // Abort transfer
                std::cerr << "Transfer aborted by NIC\n";
                isTransferComplete = true;
                break;
            default:
                std::cerr << "Unexpected opcode: " << static_cast<int>(opcode)
                          << " at chunk " << chunkNum << "\n";
                isAbort = true;
                break;
        }
    }

    // Handle abort explicitly if an unexpected opcode was encountered.
    if (isAbort)
    {
        std::cerr << "Issuing explicit abort command...\n";
        auto abortPayloadArray = generateDumpCmdPayload(chunkNum, handle, true);
        std::span<const unsigned char> abortPayload(abortPayloadArray.data(),
                                                    abortPayloadArray.size());
        NCSICommand abortCmd(ncsiCmdDump, options.package, options.channel,
                             abortPayload);
        auto abortResp = options.interface->sendCommand(abortCmd);
        if (!abortResp)
        {
            std::cerr << "Failed to send abort command for chunk number "
                      << chunkNum << "\n";
        }
        else
        {
            std::cerr << "Abort command issued.\n";
        }
    }
    else
    {
        std::cout << "Dump transfer complete. Total data size: "
                  << totalDataSize << " bytes\n";
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
        return EXIT_FAILURE;
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
    else if (subcommand == "core-dump" || subcommand == "crash-dump")
    {
        ret = ncsiCommandReceiveDump(globalOptions, subcommand, argc, argv);
    }
    else
    {
        std::cerr << "Unknown subcommand '" << subcommand << "'\n";
        print_usage(progname);
    }

    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
