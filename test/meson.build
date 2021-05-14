gtest = dependency('gtest', main: true, disabler: true, required: false)
gmock = dependency('gmock', disabler: true, required: false)
if not gtest.found() or not gmock.found()
  gtest_opts = import('cmake').subproject_options()
  gtest_opts.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
  gtest_proj = import('cmake').subproject(
    'googletest',
    options: gtest_opts,
    required: false)
  if gtest_proj.found()
    gtest = declare_dependency(
      dependencies: [
        dependency('threads'),
        gtest_proj.dependency('gtest'),
        gtest_proj.dependency('gtest_main'),
      ])
    gmock = gtest_proj.dependency('gmock')
  else
    assert(not build_tests.enabled(), 'Googletest is required')
  endif
endif


test(
  'unittest',
  executable(
    'unittest',
    'mock_syscall.cpp',
    'global_network_objects.cpp',
    'test_config_parser.cpp',
    'test_ethernet_interface.cpp',
    'test_neighbor.cpp',
    'test_netlink.cpp',
    'test_network_manager.cpp',
    #'test_rtnetlink.cpp',
    'test_util.cpp',
    'test_vlan_interface.cpp',
    implicit_include_directories: false,
    dependencies: [
      meson.get_compiler('cpp').find_library('dl'),
      networkd_dep,
      gtest,
      gmock]))
