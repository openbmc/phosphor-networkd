#################################################################################
# Get the rpath, when executing in an x86 sdk
if get_option('oe-sdk').enabled()
  # Setup OE SYSROOT
  OECORE_TARGET_SYSROOT = run_command('sh', '-c', 'echo $OECORE_TARGET_SYSROOT').stdout().strip()
  if OECORE_TARGET_SYSROOT == ''
    error('Unable to get $OECORE_TARGET_SYSROOT, check your environment.')
  endif
  message('OE_SYSROOT: ' + OECORE_TARGET_SYSROOT)
  rpath = ':'.join([OECORE_TARGET_SYSROOT + '/lib', OECORE_TARGET_SYSROOT + '/usr/lib'])
  ld_so = run_command('sh', '-c', 'find ' + OECORE_TARGET_SYSROOT + '/lib/ld-*.so | sort -r -n | head -n1').stdout().strip()
  dynamic_linker = ['-Wl,-dynamic-linker,' + ld_so]
else
  dynamic_linker = []
endif

##################################################################################
# declare dependency tests

syscalllib = declare_dependency(sources: 'mock_syscall.cpp', dependencies : deps)

##################################################################################
# declare the test sources

test_list = [
  'test_util.cpp',
  'test_netlink.cpp',
  'test_network_manager.cpp',
  'test_config_parser.cpp',
  'test_rtnetlink.cpp',
  'test_neighbor.cpp',
  'test_ethernet_interface.cpp',
  'test_vlan_interface.cpp'
]

incdir = ['.','../']

###################################################################################
# Run the tests

foreach tests:test_list
  test_name = tests.split('.')[0]
  test(test_name,
       executable(test_name,tests,
                 include_directories : incdir,
                 link_with : libnetworkd,
                 link_args: dynamic_linker,
                 build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
                 dependencies : [ gtest,
                                  gmock,
                                  syscalllib,
                                  thread_dep,
				  dl_dep,
                                ] + deps), timeout:40)
endforeach
