from distutils.core import setup, Extension

module1 = Extension('muser',
                    sources = ['python_bindings.c'],
                    #library_dirs=['/usr/local/lib'],
                    libraries=['muser'],
                    #extra_compile_args=['-g', '-O0']
)

setup (name = 'PackageName',
       version = '1.0',
       description = 'This is a demo package',
       ext_modules = [module1])
