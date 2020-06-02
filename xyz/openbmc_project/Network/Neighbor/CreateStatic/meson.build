neighbor_h = custom_target(
                'server.hpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-header',
                    'xyz.openbmc_project.Network.Neighbor.CreateStatic',
                ],
                input : '../CreateStatic.interface.yaml',
                capture : true,
                output : 'server.hpp',
                install : true,
                install_dir: get_option('includedir') / '/xyz/openbmc_project/Network/Neighbor/CreateStatic'
            )    

neighbor_c = custom_target(
                'server.cpp',
                command : [
                    sdbuspp, '-r', meson.source_root(),
                    'interface',
                    'server-cpp',
                    'xyz.openbmc_project.Network.Neighbor.CreateStatic'
                ],
                input : '../CreateStatic.interface.yaml',
                depends : neighbor_h,
                capture : true,
                output : 'server.cpp'
            )


