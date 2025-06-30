#!/usr/bin/env python3
"""
Setup configuration for Packet Insight
Enables publishing to PyPI with 'pip install packet-insight'
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from package
version = {}
with open("insight/version.py") as fp:
    exec(fp.read(), version)

# Read long description from README
long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = []
with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="packet-insight",
    version=version["__version__"],
    author="Packet Insight Contributors",
    author_email="contact@packetinsight.dev",
    description="Advanced PCAP Analysis for Support Engineers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ghostinator/packet_insightPy",
    project_urls={
        "Bug Reports": "https://github.com/ghostinator/packet_insightPy/issues",
        "Source": "https://github.com/ghostinator/packet_insightPy",
        "Documentation": "https://packet-insight.readthedocs.io/",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
            "mypy>=1.0.0",
            "bandit>=1.7.0",
            "safety>=2.3.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
        "build": [
            "build>=0.10.0",
            "wheel>=0.40.0",
            "twine>=4.0.0",
            "pyinstaller>=5.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "packet-insight=insight.cli:main",
            "pi-analyze=insight.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "insight": [
            "*.yaml",
            "*.json",
        ],
    },
    zip_safe=False,
    keywords=[
        "network", "packet", "analysis", "pcap", "wireshark", "tshark",
        "network-monitoring", "network-troubleshooting", "cybersecurity",
        "network-forensics", "packet-capture", "network-analysis"
    ],
)
