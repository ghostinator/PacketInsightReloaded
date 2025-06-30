# Quick Start Commands - Packet Insight

## TL;DR - Get Running in 5 Minutes

### Basic Setup
```bash
# 1. Navigate to your project directory
cd /path/to/packet-insight-refactored

# 2. Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux  
source .venv/bin/activate

# 3. Install in development mode
pip install -e .

# 4. Test it works
packet-insight --help
```

### Quick Usage Examples

```bash
# Interactive mode (recommended for first-time users)
packet-insight interactive

# Analyze a PCAP file
packet-insight analyze sample.pcap

# Live capture for 30 seconds
packet-insight capture --duration 30

# Check configuration
packet-insight config show

# View telemetry status
packet-insight telemetry status
```

## Alternative: Run Without Installation

If you don't want to install, just run directly:

```bash
# Install dependencies only
pip install -r requirements.txt

# Run the CLI directly
python -m insight.cli --help
python -m insight.cli analyze sample.pcap
python -m insight.cli interactive

# Or run the script directly
python insight/cli.py --help
```

## Verification Commands

```bash
# Check if installed correctly
pip list | grep packet-insight

# Test CLI access
packet-insight --version

# Test direct module access
python -c "from insight.core import PacketAnalyzer; print('Import successful')"
```

## Common First Steps

1. **Start with interactive mode**: `packet-insight interactive`
2. **Test with a small PCAP**: `packet-insight analyze test.pcap`
3. **Check your interfaces**: `packet-insight capture --list-interfaces`
4. **Review configuration**: `packet-insight config show`

## Platform-Specific Setup

### Windows
```bash
# Install Wireshark (includes tshark)
# Download from: https://www.wireshark.org/download.html

# Activate virtual environment
.venv\Scripts\activate
```

### macOS
```bash
# Install tshark via Homebrew
brew install wireshark

# Activate virtual environment
source .venv/bin/activate
```

### Linux (Ubuntu/Debian)
```bash
# Install tshark
sudo apt-get update
sudo apt-get install tshark

# Add user to wireshark group (optional, for packet capture)
sudo usermod -a -G wireshark $USER

# Activate virtual environment
source .venv/bin/activate
```

## Troubleshooting Quick Fixes

### "Command not found"
```bash
# Make sure virtual environment is activated
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Reinstall in editable mode
pip install -e .
```

### "Module not found" 
```bash
# Install dependencies
pip install -r requirements.txt

# Check you're in the right directory
ls -la  # should see setup.py and insight/ directory
```

### "Permission denied" (packet capture)
```bash
# On Linux, run with sudo or add to wireshark group
sudo packet-insight capture --duration 10

# Or add user to group (requires logout/login)
sudo usermod -a -G wireshark $USER
```

## Development Mode Benefits

- **Instant code changes**: Modifications take effect immediately
- **Easy debugging**: Full access to source code
- **Test modifications**: Make changes and test without reinstalling
- **Proper CLI commands**: Access via `packet-insight` instead of long Python paths

## Next Steps After Installation

1. Run `packet-insight interactive` to explore features
2. Try analyzing a sample PCAP file
3. Configure your preferences with `packet-insight config`
4. Set up telemetry preferences if desired
5. Review the full documentation for advanced features