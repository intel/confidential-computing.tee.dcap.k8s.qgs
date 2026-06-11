# get_platform_info tool

## Overview
A C tool that retrieves and displays platform information from Intel SGX enclaves in JSON format.

## Prerequisites
- libsgx-headers package installed (for SGX header files)
- libsgx-ae-id-enclave and libsgx-urts packages installed
- libsgx-ae-pce package installed (for PCE enclave functionality)
- SGX-enabled platform

## Building

Build the tool:
```bash
make
```

## Running

**Note:** The ID and PCE enclaves require provisioning permissions. You have two options:

### Option 1: Run with sudo
```bash
sudo ./get_platform_info
```

### Option 2: Add user to sgx_prv group
```bash
sudo usermod -aG sgx_prv $USER
# Log out and log back in for group changes to take effect
./get_platform_info
```

Or use the make target:
```bash
sudo make run
```

## Output

The tool outputs a single-line JSON string to stdout with the following keys:
- `cpu_svn` - 32-character hex string (16 bytes) - CPU security version number
- `enc_ppid` - 768-character hex string (384 bytes) - Encrypted platform provisioning ID
- `pce_id` - 4-character hex string (2 bytes) - PCE identifier
- `pce_svn` - 4-character hex string (2 bytes) - PCE security version number
- `qe_id` - 32-character hex string (16 bytes) - Platform ID (Quoting Enclave ID)

Error messages are sent to stderr.

Example output:
```json
{"cpu_svn":"0102030405060708090a0b0c0d0e0f10","enc_ppid":"abcd1234...","pce_id":"0000","pce_svn":"0b00","qe_id":"615a30c55f38bce32870cc9d1fa4a1e5"}
```

This format makes it easy to parse in scripts:
```bash
JSON=$(sudo ./get_platform_info)
QE_ID=$(echo $JSON | jq -r '.qe_id')
```

## Common Issues

### Permission Denied Error
If you see:
```
Enclave not authorized to run... You need add the user id to group sgx_prv or run the app as root.
```

**Solution**: Run with `sudo` or add your user to the `sgx_prv` group as shown in the Running section above.

## Architecture
The tool:
1. Loads the SGX uRTS library (`libsgx_urts.so`)
2. Loads the ID enclave from `/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1`
3. Loads the PCE enclave from `/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1`
4. Gets PCE target info and encryption key from ID enclave via `ide_get_pce_encrypt_key()` ECALL
5. Calls `get_pc_info()` on the PCE enclave to get certification data (encrypted PPID, PCE ID, CPU SVN, PCE SVN)
6. Calls `ide_get_id()` on the ID enclave to retrieve the platform ID (QE ID)
7. Outputs all data as a single JSON string to stdout
8. Properly unloads enclaves and library

## Cleaning

Remove built artifacts:
```bash
make clean
```
