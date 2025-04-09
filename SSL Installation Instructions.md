# SSL Installation Instructions

## SSL Dependencies Overview

The script requires SSL functionality which depends on the following packages:
- `pyOpenSSL` - Python wrapper for OpenSSL
- `cryptography` - Provides cryptographic recipes and primitives
- `certifi` - Collection of root certificates for validating SSL certificates
- `urllib3` - HTTP client with SSL support

These packages are now included in the `requirements.txt` file.

## Installation Instructions by Environment

### Standard Python Environment (Linux/macOS)

For standard Python installations on Linux or macOS, installing the dependencies from requirements.txt should be sufficient:

```bash
pip install -r requirements.txt
```

### Windows with Standard Python

For Windows with a standard Python installation:

```bash
pip install -r requirements.txt
```

If you still encounter SSL errors, you may need to ensure your Windows has the latest security updates which include OpenSSL libraries.

### Windows with Anaconda

Anaconda environments on Windows often have issues with SSL modules. Here are the steps to fix:

1. First, try installing from requirements.txt:
   ```bash
   pip install -r requirements.txt
   ```

2. If you still encounter SSL errors, install OpenSSL through conda:
   ```bash
   conda install -c anaconda openssl
   ```

3. If the error persists, you may need to set environment variables:
   ```bash
   set SSL_CERT_FILE=%CONDA_PREFIX%\Library\ssl\cert.pem
   set SSL_CERT_DIR=%CONDA_PREFIX%\Library\ssl\certs
   ```

4. As a last resort, you can use the SSL-compatible version of the script (`external_recon_risk_no_ssl.py`) which works without requiring the SSL module.

### Verifying SSL Installation

To verify that SSL is working correctly in your Python environment, run:

```python
import ssl
print(ssl.OPENSSL_VERSION)
```

This should print the OpenSSL version without errors.

## Troubleshooting SSL Issues

### Common SSL Errors and Solutions

1. **DLL load failed while importing _ssl**
   - Solution: Install OpenSSL via conda or ensure Windows has the necessary DLLs

2. **Certificate verification failed**
   - Solution: Update certifi package or set SSL_CERT_FILE environment variable

3. **SSL module is not available**
   - Solution: Use the SSL-compatible version of the script or reinstall Python with SSL support

### For Persistent Issues

If you continue to experience SSL issues after trying the above solutions:

1. Use the SSL-compatible version of the script (`external_recon_risk_no_ssl.py`)
2. Consider using a virtual environment with a fresh Python installation
3. On Windows, you might need to install the Visual C++ Redistributable packages

## SSL-Compatible Script Usage

The SSL-compatible version of the script works without requiring the SSL module:

```bash
python external_recon_risk_no_ssl.py example.com --output html
```

This version maintains all the enhancements (progress reporting, output formatting, parallel processing, and configuration options) while avoiding the SSL dependency.
