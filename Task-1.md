# Forensic Analysis Report - DAFIN-SOC Development Machine

## Executive Summary

A forensic analysis was conducted on an EXT2 image from a development machine suspected of harboring malicious artifacts. The investigation revealed a suspicious configuration file that appears to reference external resources and potentially compromised application paths.

## Investigation Overview

### Objective
- Identify suspicious artifacts on the development machine
- Locate and analyze files referenced in bash history
- Compute SHA-1 hashes for verification and threat intelligence

### Initial Findings

#### Bash History Analysis
Review of bash history revealed suspicious commands indicating files "a", "b", and "c" were copied to system-critical locations:
```
cp a /bin/console
cp b /etc/runlevels/default/console
chmod +x /bin/console
```

#### Initial File Checks
Attempts to locate these copied files revealed they were no longer present on the system:
- `/mnt/ext2/bin/console` - No such file or directory
- `/mnt/ext2/etc/runlevels/default/console` - No such file or directory

## Detailed Forensic Findings

### Legitimate Files Verified
During the investigation, several files were examined and verified as legitimate:

| File | SHA-1 Hash | Type | Status |
|------|-----------|------|--------|
| `/mnt/ext2/etc/network/if-up.d/dad` | `3917fe94f44ab9881d90105c2a87af475b7ad10e` | POSIX shell script | Legitimate |
| `/mnt/ext2/etc/profile.d/locale.sh` | `4bc8fe596ef5996c5f572f32b61a94ec7515a01c` | Locale configuration | Legitimate |
| `/mnt/ext2/etc/ssl/misc/CA.pl` | `99ca8b6ceea241ef139900a8443a3315649c8ac4` | Perl script | Legitimate |
| `/mnt/ext2/etc/ssl/misc/tsget.pl` | `5091e8cec94c139045ef474ca1c963f3dc57f02e` | Perl script | Legitimate |
| `/mnt/ext2/usr/share/openrc/support/deptree2dot/deptree2dot` | `9fa0100381e327230fedb31906c85177ae3ef7a3` | Shell script | Legitimate |

### Suspicious Artifact Discovered

#### File Location
```
/mnt/ext2/etc/runlevels/shutdown/nreswcomax
```

#### File Characteristics
- **Type**: ASCII text file
- **Size**: 59 bytes
- **Date**: Dec 31, 1969
- **Permissions**: -rw-r--r-- (644)
- **Owner**: root:root

#### File Contents
```
U=/a/00834e009c23bd1c06a117f6c65b0342/xxyz
P=20
A=/app/www
```

#### Analysis
This file contains suspicious configuration data:
- **U parameter**: References an unusual path structure with a hex-like identifier
- **P parameter**: Port number 20
- **A parameter**: References `/app/www` (web application directory)

According to bash history analysis, this file was created by copying file "c" to this location, suggesting intentional placement by an attacker.

The timestamps (Dec 31, 1969) are suspicious and indicate potential manipulation or system tampering.

## SHA-1 Hash Verification

**SHA-1 Hash of Suspicious Artifact:**
```
088369f5e17edec982926bbf65b2450640a18700
```

**File Path:**
```
/mnt/ext2/etc/runlevels/shutdown/nreswcomax
```

## Conclusions

1. **Artifact Identified**: A suspicious configuration file was discovered in the system startup/shutdown runlevels directory
2. **Persistence Mechanism**: The placement in `/etc/runlevels/shutdown/` suggests an attempt to maintain persistence or execute code during system shutdown
3. **Attack Pattern**: The bash history evidence indicates deliberate placement by an attacker who copied files to critical system locations
4. **Risk Assessment**: HIGH - The presence of this artifact combined with the bash history indicates potential system compromise

## Recommendations

1. Quarantine the affected machine from the network
2. Submit the SHA-1 hash to threat intelligence platforms for analysis
3. Review all system startup and shutdown scripts for additional artifacts
4. Conduct full memory forensics to identify running processes
5. Analyze network logs for connections to the `/a/00834e009c23bd1c06a117f6c65b0342/xxyz` path or port 20

