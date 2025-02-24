from setuptools import setup, Extension, find_packages
import os
import sys

# Check for GMP library
if sys.platform == 'win32':
    gmp_lib = ['gmp']
    gmp_include_dirs = []
    gmp_library_dirs = []
    extra_compile_args = ['-O3']
else:
    # For Linux/Mac - link statically on Linux
    gmp_lib = ['gmp']
    gmp_include_dirs = ['/usr/include', '/usr/local/include']
    gmp_library_dirs = ['/usr/lib', '/usr/local/lib', '/usr/lib/x86_64-linux-gnu']
    extra_compile_args = ['-O3']

# Generate tables.h before building
if not os.path.exists('tables.h'):
    import subprocess
    subprocess.run(['python3', 'makeCtables.py'], stdout=open('tables.h', 'w'))

twofish_module = Extension('_twofish',
                          sources=['twofish_wrap.c', 'twofish.c'],
                          extra_compile_args=extra_compile_args)

multipowerrsa_module = Extension('_multipowerrsa',
                                sources=['rsa_wrapper.c', 'multipowerrsa.c'],
                                libraries=gmp_lib,
                                include_dirs=gmp_include_dirs,
                                library_dirs=gmp_library_dirs,
                                extra_compile_args=extra_compile_args)

setup(name='pangfish',
      version='0.5.0',
      description='Pangfish encryption library with Twofish and Multi-Power RSA by Pang Construction',
      author='Rizky Azmi Swandy',
      author_email='rizkyswandy@gmail.com',
      packages=['pangfish'],
      package_dir={'pangfish': '.'},
      py_modules=[],
      ext_modules=[twofish_module, multipowerrsa_module],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'Topic :: Security :: Cryptography',
          'Programming Language :: Python :: 3',
          'Programming Language :: C',
      ],
      python_requires='>=3.6'
      )