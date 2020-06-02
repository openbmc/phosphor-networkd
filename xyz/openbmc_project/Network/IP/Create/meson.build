ip_create_h = custom_target(
                'server.hpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-header',
                    'xyz.openbmc_project.Network.IP.Create',
                ],
                input : '../Create.interface.yaml',
                capture : true,
                output : 'server.hpp',
                install : true,
                install_dir: get_option('includedir') / '/xyz/openbmc_project/Network/IP/Create'
            )    

ip_create_c = custom_target(
                'server.cpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-cpp',
                    'xyz.openbmc_project.Network.IP.Create'
                ],
                input : '../Create.interface.yaml',
                depends : ip_create_h,
                capture : true,
                output : 'server.cpp'
            )
