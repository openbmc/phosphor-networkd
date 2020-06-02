vlan_h = custom_target(
                'server.hpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-header',
                    'xyz.openbmc_project.Network.VLAN.Create',
                ],
                input : '../Create.interface.yaml',
                capture : true,
                output : 'server.hpp',
                install : true,
                install_dir: get_option('includedir') / '/xyz/openbmc_project/Network/VLAN/Create'
            )    

vlan_c = custom_target(
                'server.cpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-cpp',
                    'xyz.openbmc_project.Network.VLAN.Create'
                ],
                input : '../Create.interface.yaml',
                depends : vlan_h,
                capture : true,
                output : 'server.cpp'
            )

