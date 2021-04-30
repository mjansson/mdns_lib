#!/usr/bin/env python

"""Ninja build configurator for mdns library"""

import sys
import os

sys.path.insert( 0, os.path.join( 'build', 'ninja' ) )

import generator

dependlibs = [ 'mdns', 'network', 'foundation' ]

generator = generator.Generator( project = 'mdns', dependlibs = dependlibs, variables = [ ( 'bundleidentifier', 'com.rampantpixels.mdns.$(binname)' ) ] )
target = generator.target
writer = generator.writer
toolchain = generator.toolchain

mdns_lib = generator.lib( module = 'mdns', sources = [
  'discovery.c', 'mdns.c', 'query.c', 'record.c', 'service.c', 'socket.c', 'string.c', 'version.c' ] )

#No test cases if we're a submodule
if generator.is_subninja():
  sys.exit()

includepaths = generator.test_includepaths()

extralibs = []
if target.is_windows():
  extralibs += ['iphlpapi', 'ws2_32']

if not target.is_ios() and not target.is_android():
  configs = [ config for config in toolchain.configs if config not in [ 'profile', 'deploy' ] ]
  if not configs == []:
    generator.bin( 'mdns', [ 'main.c' ], 'mdns', basepath = 'tools', implicit_deps = [ mdns_lib ], libs = dependlibs + extralibs, configs = configs )

test_cases = [
  'dnssd'
]
if toolchain.is_monolithic() or target.is_ios() or target.is_android() or target.is_tizen():
  #Build one fat binary with all test cases
  test_resources = []
  test_extrasources = []
  test_cases += ['all']
  if target.is_ios():
    test_resources = [os.path.join('all', 'ios', item) for item in ['test-all.plist', 'Images.xcassets', 'test-all.xib']]
    test_extrasources = [os.path.join('all', 'ios', 'viewcontroller.m')]
  elif target.is_android():
    test_resources = [os.path.join( 'all', 'android', item) for item in [
      'AndroidManifest.xml', os.path.join('layout', 'main.xml'), os.path.join('values', 'strings.xml'),
      os.path.join('drawable-ldpi', 'icon.png'), os.path.join('drawable-mdpi', 'icon.png'), os.path.join('drawable-hdpi', 'icon.png'),
      os.path.join('drawable-xhdpi', 'icon.png'), os.path.join('drawable-xxhdpi', 'icon.png'), os.path.join('drawable-xxxhdpi', 'icon.png')
    ]]
    test_extrasources = [os.path.join('all', 'android', 'java', 'com', 'maniccoder', 'foundation', 'test', item) for item in [
      'TestActivity.java'
    ]]
  if target.is_macos() or target.is_ios() or target.is_android() or target.is_tizen():
    generator.app(module = '', sources = [os.path.join(module, 'main.c') for module in test_cases] + test_extrasources, binname = 'test-all', basepath = 'test', implicit_deps = [mdns_lib], libs = ['test'] + dependlibs, resources = test_resources, includepaths = includepaths)
  else:
    generator.bin(module = '', sources = [os.path.join(module, 'main.c') for module in test_cases] + test_extrasources, binname = 'test-all', basepath = 'test', implicit_deps = [mdns_lib], libs = ['test'] + dependlibs, resources = test_resources, includepaths = includepaths)
else:
  #Build one binary per test case
  generator.bin(module = 'all', sources = ['main.c'], binname = 'test-all', basepath = 'test', implicit_deps = [mdns_lib], libs = dependlibs + extralibs, includepaths = includepaths)
  for test in test_cases:
    generator.bin(module = test, sources = ['main.c'], binname = 'test-' + test, basepath = 'test', implicit_deps = [mdns_lib], libs = ['test'] + dependlibs + extralibs, includepaths = includepaths)
