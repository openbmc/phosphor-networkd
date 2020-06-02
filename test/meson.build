
tests1 = [
  'test_util.cpp',
  'test_netlink.cpp',
  'test_network_manager.cpp',
  'test_config_parser.cpp',
]

tests2 = [
'test_rtnetlink.cpp',
'test_neighbor.cpp',
'test_ethernet_interface.cpp',
'test_vlan_interface.cpp'
  ]

incdir = ['.','../']


tests = tests1 + tests2

syscalllib = declare_dependency(sources:['mock_syscall.cpp'],
  dependencies : deps)

test('Test',executable('test-binary',tests,
  include_directories : incdir,
  link_with : [
    libnetworkd
    ],
  link_args: dynamic_linker,
  build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
  dependencies : [
    gtest,
    gmock,
    syscalllib,
    thread_dep
    ] + deps),
  timeout:40,
  is_parallel : false)
