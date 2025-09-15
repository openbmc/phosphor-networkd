lldp_default_busname = 'xyz.openbmc_project.LLDP'
configure_file(
    input: 'xyz.openbmc_project.LLDP.service.in',
    output: 'xyz.openbmc_project.LLDP.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'HYP_DEFAULT_NETWORK_BUSNAME': lldp_default_busname,
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)

lldp_src_includes = include_directories('.')

lldp_lib = static_library(
    'lldp-lib',
    'lldp_manager.cpp',
    'lldp_neighbor.cpp',
    implicit_include_directories: false,
    include_directories: [src_includes, lldp_src_includes],
    dependencies: networkd_deps,
)

executable(
    'phosphor-lldpd',
    'lldp_manager_main.cpp',
    link_with: lldp_lib,
    implicit_include_directories: false,
    dependencies: [
        lldpctl_dep,
        sdbusplus_dep,
        stdplus_dep,
        dependency('phosphor-logging'),
        dependency('sdeventplus'),
    ],
    install: true,
    install_dir: get_option('bindir'),
)
