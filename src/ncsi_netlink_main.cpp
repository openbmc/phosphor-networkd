// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2018 IBM Corporation

#include "ncsi_util.hpp"

#include <string.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <string>
#include <vector>

static void usage(char** argv)
{
    CLI::App app;
    app.name(argv[0]);
    app.add_option("-x,--index", "Network interface index");
    app.add_option("-p,--package", "Package ID");
    app.add_option("-c,--channel", "Channel ID");
    app.add_flag("-i,--info", "Retrieve topology information");
    app.add_flag("-s,--set", "Set preferred package/channel");
    app.add_flag("-r,--clear", "Clear interface settings");
    app.add_option("-j,--pmask", "Package enable/disable bitmask");
    app.add_option("-k,--cmask", "Channel enable/disable bitmask");
    app.add_option("-o,--oem-payload", "OEM payload (hex string)");
    app.formatter(std::make_shared<CLI::Formatter>());

    std::cerr << app.help();
    std::cerr << "\nExample commands:\n"
                 "    1) Retrieve topology information:\n"
                 "         ncsi-netlink -x 3 -p 0 -i\n"
                 "    2) Set preferred package\n"
                 "         ncsi-netlink -x 3 -p 0 -s\n"
                 "    3) Set preferred channel\n"
                 "         ncsi-netlink -x 3 -p 0 -c 1 -s\n"
                 "    4) Clear preferred channel\n"
                 "         ncsi-netlink -x 3 -p 0 -r\n"
                 "    5) Set Package Mask\n"
                 "         ncsi-netlink -x 3 -j 1\n"
                 "    6) Set Channel Mask\n"
                 "         ncsi-netlink -x 3 -p 0 -k 1\n"
                 "\n";
}

static void exitWithError(const char* err, char** argv)
{
    usage(argv);
    if (err)
    {
        lg2::error("ERROR: {ERROR}", "ERROR", err);
    }
    exit(EXIT_FAILURE);
}

static void printInfo(phosphor::network::ncsi::InterfaceInfo& info)
{
    using namespace phosphor::network::ncsi;

    for (PackageInfo& pkg : info.packages)
    {
        lg2::debug("Package id : {ID}", "ID", pkg.id);
        if (pkg.forced)
        {
            lg2::debug("  package is forced");
        }
        for (ChannelInfo& chan : pkg.channels)
        {
            lg2::debug("    Channel id : {ID}", "ID", chan.id);
            if (chan.forced)
            {
                lg2::debug("    channel is forced");
            }
            if (chan.active)
            {
                lg2::debug("    channel is active");
            }

            lg2::debug("      version {MAJOR}.{MINOR} ({STR})", "MAJOR",
                       chan.version_major, "MINOR", chan.version_minor, "STR",
                       chan.version);

            lg2::debug("      link state {LINK}", "LINK", lg2::hex,
                       chan.link_state);

            auto& vlans = chan.vlan_ids;

            if (!vlans.empty())
            {
                lg2::debug("      Active VLAN IDs:");
                for (uint16_t vlan : vlans)
                {
                    lg2::debug("        VID: {VLAN_ID}", "VLAN_ID", vlan);
                }
            }
        }
    }
}

struct Options
{
    std::string index;
    std::string package;
    std::string channel;
    bool help = false;
    bool info = false;
    bool set = false;
    bool clear = false;
    std::string pmask;
    std::string cmask;
    std::string oemPayload;
};

int main(int argc, char** argv)
{
    using namespace phosphor::network;
    using namespace phosphor::network::ncsi;

    CLI::App app{"ncsi-netlink"};
    app.allow_windows_style_options(false);

    Options opts;
    app.set_help_flag("");
    app.add_flag("-h,--help", opts.help, "Print help and exit");
    app.add_option("-x,--index", opts.index, "Network interface index");
    app.add_option("-p,--package", opts.package, "Package ID");
    app.add_option("-c,--channel", opts.channel, "Channel ID");
    app.add_flag("-i,--info", opts.info, "Retrieve topology information");
    app.add_flag("-s,--set", opts.set, "Set preferred package/channel");
    app.add_flag("-r,--clear", opts.clear, "Clear interface settings");
    app.add_option("-j,--pmask", opts.pmask, "Package enable/disable bitmask");
    app.add_option("-k,--cmask", opts.cmask, "Channel enable/disable bitmask");
    app.add_option("-o,--oem-payload", opts.oemPayload,
                   "OEM payload (hex string)");

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        usage(argv);
        exit(app.exit(e));
    }

    if (opts.help)
    {
        usage(argv);
        exit(EXIT_SUCCESS);
    }

    int packageInt{};
    int channelInt{};
    int indexInt{};

    // Parse out interface argument.
    try
    {
        indexInt = stoi(opts.index, nullptr);
    }
    catch (const std::exception& e)
    {
        exitWithError("Interface not specified.", argv);
    }

    if (indexInt < 0)
    {
        exitWithError("Interface value should be greater than equal to 0",
                      argv);
    }

    NetlinkInterface interface(indexInt);

    // Parse out package argument.
    try
    {
        packageInt = stoi(opts.package, nullptr);
    }
    catch (const std::exception& e)
    {
        packageInt = DEFAULT_VALUE;
    }

    if (packageInt < 0)
    {
        packageInt = DEFAULT_VALUE;
    }

    // Parse out channel argument.
    try
    {
        channelInt = stoi(opts.channel, nullptr);
    }
    catch (const std::exception& e)
    {
        channelInt = DEFAULT_VALUE;
    }

    if (channelInt < 0)
    {
        channelInt = DEFAULT_VALUE;
    }

    if (!opts.oemPayload.empty())
    {
        auto& payloadStr = opts.oemPayload;
        if (payloadStr.size() % 2 || payloadStr.size() < 2)
            exitWithError("Payload invalid: specify two hex digits per byte.",
                          argv);

        std::string typeStr(payloadStr.substr(0, 2));
        std::string dataStr(payloadStr.substr(2));

        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }

        std::vector<std::string> args = {
            "ncsi-cmd",
            "-i",
            std::to_string(indexInt),
            "-p",
            std::to_string(packageInt),
        };

        if (channelInt != DEFAULT_VALUE)
        {
            args.push_back("-c");
            args.push_back(std::to_string(channelInt));
        }

        args.push_back("raw");
        args.push_back(typeStr);
        args.push_back(dataStr);

        char** argv = new char*[args.size() + 1]();
        for (size_t i = 0; i < args.size(); i++)
        {
            argv[i] = strdup(args[i].c_str());
        }
        argv[args.size()] = NULL;

        lg2::debug("ncsi-netlink [..] -o is deprecated by ncsi-cmd");
        execvp(argv[0], argv);
        lg2::error("exec failed; use ncsi-cmd directly");

        for (size_t i = 0; i < args.size(); i++)
        {
            free(argv[i]);
        }
        delete[] argv;
        return EXIT_FAILURE;
    }
    else if (opts.set)
    {
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }
        return interface.setChannel(packageInt, channelInt);
    }
    else if (opts.info)
    {
        auto info = interface.getInfo(packageInt);
        if (!info)
        {
            return EXIT_FAILURE;
        }
        printInfo(*info);
    }
    else if (opts.clear)
    {
        return interface.clearInterface();
    }
    else if (!opts.pmask.empty())
    {
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = std::stoul(opts.pmask, &lastChar, 0);
            if (lastChar < (opts.pmask.size()))
            {
                exitWithError("Package mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Package mask value is not valid", argv);
        }
        return interface.setPackageMask(mask);
    }
    else if (!opts.cmask.empty())
    {
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package is not specified", argv);
        }
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = stoul(opts.cmask, &lastChar, 0);
            if (lastChar < (opts.cmask.size()))
            {
                exitWithError("Channel mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Channel mask value is not valid", argv);
        }
        return interface.setChannelMask(packageInt, mask);
    }
    else
    {
        exitWithError("No Command specified", argv);
    }
    return 0;
}
