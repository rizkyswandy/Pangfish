from setuptools import setup, Extension, find_packages
from setuptools.command.bdist_wheel import bdist_wheel
import os
import sys

# Custom wheel command class
class BdistWheelCommand(bdist_wheel):
   def finalize_options(self):
       bdist_wheel.finalize_options(self)
       self.root_is_pure = False
       self.plat_name_supplied = True
       self.plat_name = "manylinux2014_x86_64"

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
                               include_dirs=gmp_include_dirs + ['.'],  
                               library_dirs=gmp_library_dirs,
                               extra_compile_args=extra_compile_args)

setup(name='pangfish',
     version='0.7.3',
     description='Pangfish encryption library with Twofish and Multi-Power RSA by Pang Construction',
     author='Rizky Azmi Swandy',
     author_email='rizkyswandy@gmail.com',
     packages=['pangfish'],
     package_dir={'pangfish': '.'},
     py_modules=[],
     ext_modules=[twofish_module, multipowerrsa_module],
     cmdclass={
         'bdist_wheel': BdistWheelCommand,
     },
     classifiers=[
         'Development Status :: 3 - Alpha',
         'Intended Audience :: Developers',
         'Topic :: Security :: Cryptography',
         'Programming Language :: Python :: 3',
         'Programming Language :: C',
         'Operating System :: OS Independent',
     ],
     python_requires='>=3.10,<3.11'
)