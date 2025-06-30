# How to Set Up ReadTheDocs for Packet Insight

## Step 1: Add Files to Your Repository

Copy these files to your project repository:

### Required Files

1. **`.readthedocs.yaml`** - Place in your repository root (same level as setup.py)
2. **`docs/conf.py`** - Sphinx configuration
3. **`docs/requirements.txt`** - Documentation dependencies  
4. **`docs/index.rst`** - Main documentation page
5. **`docs/api/index.rst`** - API documentation (autodoc)

### Directory Structure After Setup

```
packet-insight/
├── .readthedocs.yaml          ← Place in repository root
├── docs/                      ← Create this directory
│   ├── conf.py               ← Sphinx configuration
│   ├── requirements.txt      ← Documentation dependencies
│   ├── index.rst            ← Main documentation page
│   ├── api/                 ← API documentation
│   │   └── index.rst        ← API autodoc page
│   ├── _static/             ← Create for static files (images, CSS)
│   └── _templates/          ← Create for custom templates
├── insight/                  ← Your existing package
│   ├── __init__.py
│   ├── core.py
│   ├── cli.py
│   └── ...
├── setup.py                  ← Your existing setup file
└── requirements.txt          ← Your existing requirements
```

## Step 2: Create Missing Directories

Run these commands in your project root:

```bash
mkdir -p docs/api
mkdir -p docs/_static
mkdir -p docs/_templates
```

## Step 3: Update Your setup.py (if needed)

Ensure your setup.py includes documentation dependencies in extras_require:

```python
setup(
    name="packet-insight",
    # ... other configuration ...
    extras_require={
        "dev": [
            "pytest",
            "pytest-asyncio", 
            "black",
            "ruff",
            "mypy",
            # Documentation dependencies
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
            "sphinx-autodoc-typehints>=1.24.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0", 
            "sphinx-autodoc-typehints>=1.24.0",
            "sphinx-copybutton>=0.5.2",
            "numpydoc>=1.5.0",
        ]
    }
)
```

## Step 4: Set Up ReadTheDocs Account

1. **Go to ReadTheDocs**: Visit https://readthedocs.org/
2. **Sign Up/Login**: Use your GitHub account 
3. **Import Project**: Click "Import a Project"
4. **Connect Repository**: Select your packet-insight repository
5. **Build Settings**: ReadTheDocs will automatically detect your `.readthedocs.yaml`

## Step 5: Verify Local Build (Optional but Recommended)

Test your documentation locally before pushing:

```bash
# Create virtual environment
python -m venv docs-env
source docs-env/bin/activate  # On Windows: docs-env\Scripts\activate

# Install requirements
pip install -r docs/requirements.txt
pip install -e .  # Install your package in development mode

# Build documentation
cd docs
sphinx-build -b html . _build/html

# Open documentation
open _build/html/index.html  # On Windows: start _build/html/index.html
```

## Step 6: Customize Your Documentation

### Add More Content

Create additional documentation files:

```bash
# User guide
mkdir -p docs/user-guide
echo "User Guide" > docs/user-guide/index.rst
echo "Basic Usage" > docs/user-guide/basic-usage.rst

# Developer guide  
mkdir -p docs/developer
echo "Developer Guide" > docs/developer/index.rst
echo "Contributing" > docs/developer/contributing.rst
```

### Update Docstrings

Ensure your Python modules have good docstrings. ReadTheDocs will automatically generate API documentation from these:

```python
def analyze_packets(pcap_file: str, baseline: Optional[str] = None) -> Dict[str, Any]:
    """Analyze packets from a PCAP file.
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        baseline: Optional path to baseline configuration file
        
    Returns:
        Dictionary containing analysis results with keys:
        - packet_count: Total number of packets
        - protocols: Protocol distribution  
        - anomalies: List of detected anomalies
        
    Raises:
        FileNotFoundError: If pcap_file doesn't exist
        AnalysisError: If analysis fails
        
    Example:
        >>> results = analyze_packets("capture.pcap")
        >>> print(f"Found {results['packet_count']} packets")
    """
```

### Add Images and Static Files

Place images in `docs/_static/`:

```bash
# Copy logo or screenshots  
cp logo.png docs/_static/
cp screenshot.png docs/_static/
```

Reference them in your .rst files:

```rst
.. image:: _static/logo.png
   :alt: Packet Insight Logo
   :width: 200px
```

## Step 7: Configure Advanced Features

### Enable Search Ranking

Edit `.readthedocs.yaml` to prioritize different content:

```yaml
search:
  ranking:
    api/: -1          # Lower priority for API docs  
    user-guide/: 5    # Higher priority for user guides
    quickstart.rst: 10 # Highest priority for quickstart
```

### Add Multiple Output Formats

Update `.readthedocs.yaml`:

```yaml
formats:
  - pdf
  - epub
  - htmlzip
```

### Set Up Custom Domain (Optional)

In your ReadTheDocs project settings, you can configure a custom domain like `docs.packet-insight.com`.

## Step 8: Automate with GitHub Actions

Add to `.github/workflows/docs.yml`:

```yaml
name: Documentation

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: |
        pip install -r docs/requirements.txt
        pip install -e .
    - name: Build docs
      run: |
        cd docs
        sphinx-build -b html . _build/html -W
    - name: Upload docs artifact
      uses: actions/upload-artifact@v3
      with:
        name: documentation
        path: docs/_build/html
```

## Troubleshooting Common Issues

### 1. "Module not found" errors in ReadTheDocs

**Problem**: `WARNING: autodoc: failed to import module 'insight.core'`

**Solution**: Ensure your package is installable and .readthedocs.yaml includes:

```yaml
python:
  install:
    - requirements: docs/requirements.txt
    - method: pip
      path: .  # This installs your package
```

### 2. Missing dependencies

**Problem**: Import errors for packages like pyshark, click, etc.

**Solution**: Add all runtime dependencies to `docs/requirements.txt` or install your package with dependencies:

```yaml
python:
  install:
    - requirements: docs/requirements.txt
    - method: pip
      path: .
      extra_requirements:
        - dev  # Includes all development dependencies
```

### 3. Build warnings causing failures

**Problem**: Build fails due to warnings when `fail_on_warning: true`

**Solution**: Either fix the warnings or temporarily disable:

```yaml
sphinx:
  configuration: docs/conf.py
  fail_on_warning: false  # Temporarily disable until warnings are fixed
```

### 4. Incorrect Python path

**Problem**: Autodoc can't find your modules

**Solution**: Verify `docs/conf.py` has correct path setup:

```python
sys.path.insert(0, str(Path(__file__).parent.parent))
```

## Summary

With these files and setup steps, you'll have:

✅ **Professional Documentation**: Modern ReadTheDocs theme with search  
✅ **Automatic API Docs**: Generated from your docstrings  
✅ **Multiple Formats**: HTML, PDF, and ePub output  
✅ **Continuous Integration**: Automatic builds on every commit  
✅ **Custom Branding**: Logo, custom CSS, and styling options  
✅ **Advanced Features**: Search ranking, social sharing, analytics ready

Your documentation will be automatically built and deployed every time you push to your repository!