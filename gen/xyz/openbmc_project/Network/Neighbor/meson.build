# Generated file; do not modify.
subdir('CreateStatic')
generated_others += custom_target(
    'xyz/openbmc_project/Network/Neighbor/CreateStatic__markdown'.underscorify(),
    input: [ '../../../../../yaml/xyz/openbmc_project/Network/Neighbor/CreateStatic.interface.yaml',  ],
    output: [ 'CreateStatic.md' ],
    command: [
        sdbuspp_gen_meson_prog, '--command', 'markdown',
        '--output', meson.current_build_dir(),
        '--tool', sdbusplusplus_prog,
        '--directory', meson.current_source_dir() / '../../../../../yaml',
        'xyz/openbmc_project/Network/Neighbor/CreateStatic',
    ],
)

