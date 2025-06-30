=================================
Packet Insight Documentation
=================================

.. image:: https://img.shields.io/pypi/v/packet-insight.svg
   :target: https://pypi.org/project/packet-insight/
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/pyversions/packet-insight.svg
   :target: https://pypi.org/project/packet-insight/
   :alt: Python Versions

.. image:: https://readthedocs.org/projects/packet-insight/badge/?version=latest
   :target: https://packet-insight.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://github.com/ghostinator/packet_insightPy/workflows/CI/badge.svg
   :target: https://github.com/ghostinator/packet_insightPy/actions
   :alt: CI Status

**Packet Insight** is a cross-platform, Python-based toolkit that streamlines 
packet-capture (PCAP) triage for support and field engineers. It provides CLI 
workflows for live capture, automated baseline creation, anomaly detection, and 
rich summary reports.

Quick Start
-----------

Install Packet Insight:

.. code-block:: bash

   pip install packet-insight

Run interactive mode:

.. code-block:: bash

   packet-insight interactive

Analyze a PCAP file:

.. code-block:: bash

   packet-insight analyze sample.pcap

Features
--------

🔍 **Intelligent Analysis**
   Advanced packet analysis with automated baseline comparison and anomaly detection

📊 **Rich Reporting** 
   Comprehensive reports with colored console output and multiple export formats

🖥️ **Cross-Platform**
   Works seamlessly on Windows, macOS, and Linux with native OS integration

⚡ **High Performance**
   Optimized for large PCAP files with streaming analysis and progress tracking

🛠️ **Developer Friendly**
   Clean API, comprehensive type hints, and extensive test coverage

Documentation Contents
----------------------

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: User Guide
   
   user-guide/index
   user-guide/basic-usage
   user-guide/advanced-features
   user-guide/configuration

.. toctree::
   :maxdepth: 2
   :caption: API Reference
   
   api/index

.. toctree::
   :maxdepth: 2
   :caption: Developer Guide
   
   developer/index
   developer/contributing
   developer/architecture
   developer/testing

.. toctree::
   :maxdepth: 1
   :caption: About
   
   changelog
   license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`