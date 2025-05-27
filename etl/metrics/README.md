# Metrics Pipeline: Remediation Status Resolver

## Purpose

The `remediation_status_resolver.py` module is responsible for determining the remediation status of vulnerabilities before any metrics are calculated. It must be run as the **first step** in the metrics pipeline.

## How It Works

- Compares vulnerabilities from the current scan with those from the previous scan.
- Assigns a `remediation_status` to each vulnerability:
  - `open`: Vulnerability is present in the current scan
  - `remediated`: Vulnerability was present in a previous scan but is not present in the current scan
  - `reopened`: Vulnerability was remediated but has reappeared

## Usage

Import and call the resolver before running MTTR or other metrics calculations:

```python
from etl.metrics.remediation_status_resolver import resolve_remediation_status
vulnerabilities = resolve_remediation_status(current_vulnerabilities, previous_vulnerabilities)
```

## Pipeline Order

1. **Remediation Status Resolver** (must run first)
2. MTTR Calculator
3. Metrics Generator
4. Reporting Tables Manager

This ensures all downstream metrics are based on accurate remediation status for each vulnerability. 