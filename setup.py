import os
from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

try:
    with open('requirements.txt', 'r') as f:
        requirements = f.read().splitlines() if os.path.exists('requirements.txt') else []

except FileNotFoundError:
    requirements = []

setup(
    name='slackattack',
    version='1.0.8',
    author='Jonathan Stines',
    description='Description of your tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/fr4nk3nst1ner/slackattack',
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
