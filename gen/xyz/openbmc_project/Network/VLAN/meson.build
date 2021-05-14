# Generated file; do not modify.
subdir('Create')
generated_others += custom_target(
    'xyz/openbmc_project/Network/VLAN/Create__markdown'.underscorify(),
    input: [ meson.project_source_root() / 'xyz/openbmc_project/Network/VLAN/Create.interface.yaml',  ],
    output: [ 'Create.md' ],
    command: [
        sdbuspp_gen_meson_prog, '--command', 'markdown',
        '--output', meson.current_build_dir(),
        '--tool', sdbusplusplus_prog,
        '--directory', meson.project_source_root(),
        'xyz/openbmc_project/Network/VLAN/Create',
    ],
    build_by_default: true,
)

