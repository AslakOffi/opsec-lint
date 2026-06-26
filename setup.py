from setuptools import setup, find_packages

setup(
    name='opsec-lint',
    version='0.1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'opsec-lint=opsec_lint.main:main',
        ],
    },
    python_requires='>=3.8',
)
