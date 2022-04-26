from distutils.core import setup
long_description = ("README.md").read_text()

setup(name='NetworkScan',
      version='1.1',
      py_modules=['networkscan'],
      description="Cross platform threaded tcp network port scanner with module support.",
      long_description=long_description,
      long_description_content_type='text/markdown'
      )
