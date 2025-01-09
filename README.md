# Scoop the (Paged) Pool Template
Scoop the Pool is an exploitation technique applicable to many Windows pool overflow vulnerabilities. This example of the technique creates an arbitrary read primitive and arbitrary decrement from a paged pool overflow (See [this article](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf) for further details on adapting this to the non-paged pool). The arbitrary decrement is utilized to change the current thread's PreviousMode bit to 0, enabling the thread to read and write kernel memory with Windows APIs. 

Note the PreviousMode technique does not work in latest Windows 11 builds, including build 26100. The technique **does** work on Windows 11 build 26100. *The arbitrary read and decrement function on all versions of Windows; that functionality is separate from the PreviousMode decrement.*

The template's payload will utilize the read/write primitives to elevate privileges, stealing the SYSTEM process token and spawning cmd.exe as NT AUTHORITY\SYSTEM.

## Usage
This exploit template is designed to function from low integrity, enabling a full elevation of privilege with a pool overflow exploit.

Search for the 'TODO' sections of the code to view where code must be updated or added. The TODOs are as follows:
- Line 10: Update offset constants. The current template uses hardcoded offsets for Windows 10 build 19042.
- Line 608: Add any necessary code to initialize the exploit without triggering it.
- Line 639: Trigger the pool overflow vulnerability.

Build the exploit in Visual Studio. Execute scoop_pool.exe. If the exploit fails, you may try again. If it fails consistently, you may need to increase the INITIAL_LFH_SPRAY constant defined in [scoop_pool.cpp](scoop_pool/scoop_pool.cpp) or reboot the system.

## Stability
This exploit template is moderately stable. The exploit succeeded 10 consecutive times during testing with CVE-2021-31956.

Grooming the kernel pool may fail due to low-fragmentation heap (LFH) entropy. Executing the exploit multiple times may increase chance of Blue Screen of Death (BSOD).
