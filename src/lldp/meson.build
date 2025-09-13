lldp_default_busname = 'xyz.openbmc_project.LLDP'

config = configuration_data()
config.set_quoted('LLDP_DEFAULT_BUSNAME', lldp_default_busname)
config.set_quoted('LLDP_OBJECT_PATH', '/xyz/openbmc_project/network/lldp')

configure_file(output: 'lldp_config.h', configuration: config)

configure_file(
    input: 'xyz.openbmc_project.LLDP.service.in',
    output: 'xyz.openbmc_project.LLDP.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'LLDP_DEFAULT_BUSNAME': lldp_default_busname,
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)

lldp_src_includes = include_directories('.')

lldpctl_dep = dependency('lldpctl', required: true)

executable(
    'phosphor-lldpd',
    ['lldp_manager.cpp', 'lldp_manager_main.cpp'],
    implicit_include_directories: false,
    include_directories: [src_includes, lldp_src_includes],
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
