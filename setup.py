#!/usr/bin/env python3

from setuptools import setup

setup(name='frizzer',
      version='0.1',
      description='A coverage-guided blackbox fuzzer based on the frida instrumentation framework',
      url='http://github.com/ernw/frizzer',
      author='Dennis Mantz',
      author_email='dmantz@ernw.de',
      license='MIT',
      packages=['frizzer'],
      package_data={
        '': ['*.js'],
      },
      install_requires=[
          'frida-tools',
          'toml'
      ],
      entry_points = {
        'console_scripts': ['frizzer=frizzer.fuzzer:main']
      },
      zip_safe=False)
