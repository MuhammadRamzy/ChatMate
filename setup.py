from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name="chatmate",
    version="1.0.0",
    description="ChatMate is a local network-based chat application where users can create and join chat groups with a passkey. The program allows multiple users to connect within the same local network, chat in real-time, and assigns each user a unique color for their messages.",
    author="Muhammad Ramzy",
    author_email="mhdramzy777@gmail.com",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/MuhammadRamzy/ChatMate',
    packages=find_packages(),
    install_requires=[
        "termcolor",
        "pyfiglet",
        "PyQt5"
    ],
    entry_points={
        'console_scripts': [
            'chatmate=src.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)