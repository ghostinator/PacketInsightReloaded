# Packet Insight 🕵️‍♂️📦

Advanced PCAP Analysis for Support Engineers

[![CI/CD Pipeline](https://github.com/ghostinator/PacketInsightReloaded/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/ghostinator/PacketInsightReloaded/actions/workflows/ci-cd.yml)
[![PyPI version](https://badge.fury.io/py/packet-insight.svg)](https://badge.fury.io/py/packet-insight)
[![Python Support](https://img.shields.io/pypi/pyversions/packet-insight.svg)](https://pypi.org/project/packet-insight/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Coverage](https://codecov.io/gh/ghostinator/packet_insightPy/branch/main/graph/badge.svg)](https://codecov.io/gh/ghostinator/packet_insightPy)

## 🚀 Features

- **Cross-platform PCAP analysis** with automated baseline creation
- **Real-time packet capture** with rolling file support
- **Comprehensive network diagnostics** including TCP, UDP, DNS, HTTP, TLS, and DHCP analysis
- **Multiple output formats** (text, JSON, CSV, HTML)
- **Interactive troubleshooting mode** for field engineers
- **Anonymous telemetry** (opt-in) for product improvement
- **Modular architecture** with comprehensive test coverage
- **Professional packaging** with PyPI distribution

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install packet-insight
```

### From Source

```bash
git clone https://github.com/ghostinator/PacketInsightReloaded.git
cd packet_insightPy
pip install -e .
```

### Standalone Executables

Download platform-specific executables from the [Releases](https://github.com/ghostinator/PacketInsightReloaded/releases) page.

## 🛠️ Prerequisites

- **Python 3.8+**
- **Wireshark/tshark** installed and accessible
- **Administrative privileges** for live packet capture

### Installing Wireshark/tshark

- **macOS**: `brew install wireshark`
- **Ubuntu/Debian**: `sudo apt install tshark`
- **CentOS/RHEL**: `sudo yum install wireshark`
- **Windows**: Download from [wireshark.org](https://www.wireshark.org/download.html)

## 🎯 Quick Start

### Analyze a PCAP file

```bash
packet-insight capture.pcap
```

### Live capture and analysis

```bash
packet-insight --live --interface eth0 --duration 60
```

### Interactive mode

```bash
packet-insight --interactive
```

### Export results

```bash
packet-insight capture.pcap --format json --output report.json
```

## 📊 Sample Output

```
## Network Summary [Packets: 15,847 | Duration: 300.2s]
- Total Data: 23.4 MB
- Avg Packet Size: 1,518 bytes
- Estimated Throughput: 0.62 Mbps

### Protocol Distribution
- TCP: 12,458 packets (78.6%)
- UDP: 2,891 packets (18.2%)
- ICMP: 498 packets (3.1%)

### Network Issues
- TCP Retransmissions: 23
- TCP Resets: 5
- DNS Timeouts/Failures: 12
- HTTP Errors: 8 total
  • 404: 6 errors
  • 500: 2 errors

⚠️ CRITICAL: High retransmission rate (0.15% > 5% threshold)
```

## 🔧 Configuration

Create a configuration file to customize analysis thresholds:

```yaml
# packet_insight.yaml
retransmission_threshold: 0.05
high_jitter_threshold: 0.1
syn_delay_threshold: 0.5
dns_timeout_threshold: 1.0
default_output_format: "json"
telemetry_enabled: false
```

Use with:

```bash
packet-insight --config packet_insight.yaml capture.pcap
```

## 🧪 Development

### Setup Development Environment

```bash
git clone https://github.com/ghostinator/PacketInsightReloaded.git
cd packet_insightPy
pip install -r requirements-dev.txt
pip install -e .
```

### Run Tests

```bash
pytest tests/ -v --cov=insight
```

### Code Formatting

```bash
black insight/ tests/
isort insight/ tests/
```

### Type Checking

```bash
mypy insight/
```

## 🏗️ Architecture

The refactored codebase follows clean architecture principles:

```
insight/
├── __init__.py          # Package initialization
├── version.py           # Version information
├── exceptions.py        # Custom exception hierarchy
├── config.py           # Configuration management
├── utils.py            # Consolidated utility functions
├── core.py             # Core analytics engine
├── cli.py              # Thin CLI wrapper
├── telemetry.py        # Anonymous telemetry system
├── report.py           # Report generation
└── live_capture.py     # Live capture management
```

### Key Improvements

1. **Modular Design**: Clear separation of concerns
2. **Comprehensive Testing**: Unit and integration tests
3. **Type Safety**: Full type hints and mypy validation
4. **Error Handling**: Specific exception types
5. **CI/CD Pipeline**: Automated testing and deployment
6. **Production Ready**: Proper packaging and distribution

## 📈 Telemetry

Packet Insight includes optional anonymous telemetry to help improve the product:

- **Opt-in only**: Telemetry is disabled by default
- **Anonymous**: No personal information is collected
- **Transparent**: View and export your data anytime
- **Privacy-focused**: Only usage patterns and performance metrics

Enable telemetry:

```bash
packet-insight --interactive
# Select "7. Telemetry settings" -> "Enable telemetry"
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on [PyShark](https://github.com/KimiNewt/pyshark) for packet parsing
- Inspired by Wireshark and tshark capabilities
- Thanks to all contributors and users

## 📚 Documentation

Full documentation is available at [packet-insight.readthedocs.io](https://packet-insight.readthedocs.io/).

## 🐛 Bug Reports

Please report bugs on our [GitHub Issues](https://github.com/ghostinator/PacketInsightReloaded/issues) page.

## 🗺️ Roadmap

- [ ] Web-based dashboard
- [ ] Machine learning anomaly detection
- [ ] Advanced protocol analysis
- [ ] Integration with SIEM systems
- [ ] Cloud deployment options

---

Made with ❤️ for network engineers and security professionals.
