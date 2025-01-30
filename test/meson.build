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
    assert(not get_option('tests').allowed(), 'Googletest is required')
  endif
endif

test_headers = include_directories('.')

test_deps = [
  meson.get_compiler('cpp').find_library('dl'),
  networkd_dep,
  gtest,
  gmock,
  dependency('stdplus-gtest'),
]

test_lib = static_library(
  'networkd-test',
  'mock_syscall.cpp',
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
  'netlink',
  'network_manager',
  'rtnetlink',
  'types',
  'util',
]

run_with_tmp = find_program('run_with_tmp', native: true)

add_test_setup(
  'networkd',
  exe_wrapper: run_with_tmp,
  env: {'TMPTMPL': 'phosphor-networkd-test.XXXXXXXXXX'},
  is_default: true)

add_test_setup(
  'valgrind',
  exe_wrapper: [run_with_tmp, 'valgrind'],
  env: {'TMPTMPL': 'phosphor-networkd-test.XXXXXXXXXX'})

foreach t : tests
  test(
    t,
    executable(
      t.underscorify(),
      'test_' + t + '.cpp',
      implicit_include_directories: false,
      dependencies: test_dep))
endforeach

if (get_option('hyp-nw-config') == true)
  subdir('ibm/hypervisor-network-mgr-test')
endif
