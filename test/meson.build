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

test_headers = include_directories('.')

test_deps = [
  meson.get_compiler('cpp').find_library('dl'),
  networkd_dep,
  gtest,
  gmock,
]

test_lib = static_library(
  'networkd-test',
  'mock_syscall.cpp',
  'global_network_objects.cpp',
  implicit_include_directories: false,
  include_directories: test_headers,
  dependencies: test_deps)

test_dep = declare_dependency(
  dependencies: test_deps,
  include_directories: test_headers,
  link_with: test_lib)

tests = [
  'config_parser',
  'ethernet_interface',
  'neighbor',
  'netlink',
  'network_manager',
  #'rtnetlink',
  'util',
  'vlan_interface',
]

foreach t : tests
  test(
    t,
    executable(
      t.underscorify(),
      'test_' + t + '.cpp',
      implicit_include_directories: false,
      dependencies: test_dep))
endforeach
