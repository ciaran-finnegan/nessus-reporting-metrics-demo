# Nessus Sample Files - Vulnerability Progression Over Time

This directory contains Nessus scan files that demonstrate realistic vulnerability management progression over a 5-week period. These files are designed to show how vulnerabilities are discovered, remediated, and how new ones appear over time.

## File Overview

### Original Files
- `nessus_v_unknown.nessus` - Original sample file (2013 scan date)
- `nessus-02_v_unknown.xml` - Additional XML format sample

### Time Series Progression (2024)

#### Week 1 - `nessus_scan_week1.nessus` (2024-01-01)
**Initial Discovery Scan**
- All vulnerabilities present from original scan
- Baseline security posture assessment
- Multiple RDP/Terminal Services issues identified
- SMB signing disabled
- Various informational findings

**Key Vulnerabilities:**
- Terminal Services NLA not enabled (Medium)
- Terminal Services encryption issues (Medium/Low)
- RDP Man-in-the-Middle weakness (Medium)
- SMB Signing Disabled (Medium)

#### Week 2 - `nessus_scan_week2.nessus` (2024-01-08)
**Some Remediation + New Critical Issue**
- Fixed: Terminal Services NLA and encryption issues
- **NEW CRITICAL**: SSL Certificate Expired (High severity)
- Shows how new vulnerabilities can appear

**Changes:**
- ✅ Removed: Plugin 58453 (Terminal Services NLA)
- ✅ Removed: Plugin 57690 (Terminal Services Encryption)
- 🆕 Added: Plugin 99999 (SSL Certificate Expired - High)

#### Week 3 - `nessus_scan_week3.nessus` (2024-01-15)
**Critical Issue Resolved + New Medium Vulnerability**
- Fixed: SSL Certificate issue (quick response to critical)
- **NEW**: SSH weak encryption algorithms discovered
- Demonstrates prioritisation of critical issues

**Changes:**
- ✅ Removed: Plugin 99999 (SSL Certificate Expired - FIXED)
- 🆕 Added: Plugin 88888 (SSH Weak Encryption - Medium)

#### Week 4 - `nessus_scan_week4.nessus` (2024-01-22)
**SSH Fixed + New Low Priority Finding**
- Fixed: SSH encryption issue
- **NEW**: HTTP security headers missing (Low priority)
- RDP issues still remain (lower priority)

**Changes:**
- ✅ Removed: Plugin 88888 (SSH Weak Encryption - FIXED)
- 🆕 Added: Plugin 77777 (HTTP Security Headers - Low)

#### Week 5 - `nessus_scan_week5.nessus` (2024-01-29)
**Major Cleanup Complete**
- Fixed: Most remaining issues including FIPS compliance and HTTP headers
- Only RDP Man-in-the-Middle weakness remains
- Demonstrates significant security improvement

**Changes:**
- ✅ Removed: Plugin 30218 (Terminal Services FIPS - FIXED)
- ✅ Removed: Plugin 77777 (HTTP Security Headers - FIXED)
- Remaining: Plugin 18405 (RDP MITM - ongoing)

## Vulnerability Progression Summary

| Week | Critical | High | Medium | Low | Total | Key Changes |
|------|----------|------|--------|-----|-------|-------------|
| 1    | 0        | 0    | 4      | 1   | 5     | Baseline scan |
| 2    | 0        | 1    | 2      | 1   | 4     | +SSL Critical, -RDP fixes |
| 3    | 0        | 0    | 3      | 1   | 4     | -SSL fixed, +SSH issue |
| 4    | 0        | 0    | 2      | 2   | 4     | -SSH fixed, +HTTP headers |
| 5    | 0        | 0    | 1      | 0   | 1     | Major cleanup complete |

## MTTR Demonstration

These files demonstrate realistic Mean Time To Remediate (MTTR) patterns:

- **Critical/High**: 7 days (SSL certificate - immediate priority)
- **Medium**: 7-14 days (RDP/SSH issues - planned maintenance)
- **Low**: 14-21 days (HTTP headers - next maintenance window)
- **Ongoing**: Some issues may persist (RDP MITM - requires infrastructure changes)

## Usage for Testing

These files can be used to test:
1. **Vulnerability trend analysis** - How vulnerability counts change over time
2. **MTTR calculations** - Time between discovery and remediation
3. **Risk scoring progression** - How overall risk posture improves
4. **Remediation effectiveness** - Which vulnerability types are addressed fastest
5. **New vulnerability discovery** - How new issues appear in subsequent scans

## Metrics Generated

When processed through the vulnerability management pipeline, these files will generate:
- Vulnerability count trends
- MTTR by severity level
- Remediation velocity metrics
- Risk score progression
- Campaign effectiveness data
- Business group performance comparisons