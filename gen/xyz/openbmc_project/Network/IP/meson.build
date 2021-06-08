# Generated file; do not modify.
subdir('Create')
generated_others += custom_target(
    'xyz/openbmc_project/Network/IP/Create__markdown'.underscorify(),
    input: [ '../../../../../xyz/openbmc_project/Network/IP/Create.interface.yaml',  ],
    output: [ 'Create.md' ],
    command: [
        sdbuspp_gen_meson_prog, '--command', 'markdown',
        '--output', meson.current_build_dir(),
        '--tool', sdbusplusplus_prog,
        '--directory', meson.current_source_dir() / '../../../../..',
        'xyz/openbmc_project/Network/IP/Create',
    ],
)

