# VirtualQuery
VirtualQuery is a Windows API function used to search for information about a specified memory region. This function is very useful for memory analysis and malware detection, especially when analyzing the memory distribution of a process.
## Syntax
```Cpp

SIZE_T VirtualQuery(
  [in, optional] LPCVOID                   lpAddress, //A pointer to the base address of the region of pages
  [out]          PMEMORY_BASIC_INFORMATION lpBuffer,  //A pointer to a MEMORY_BASIC_INFORMATION structure
  [in]           SIZE_T                    dwLength //The size of the buffer pointed to by the lpBuffer
);
```
For more detailed information about VirtualQuery keywords and methods, please refer to its documentation.
https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery

## MEMORY_BASIC_INFORMATION
Including information related to a range of pages in the process's virtual address space (e.g., base address, size, state, protection attributes, and type). The VirtualQuery function utilizes this structure.
### Syntax
```
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;         // The base address of the memory region
    PVOID  AllocationBase;      // The base address of the allocated memory region
    DWORD  AllocationProtect;   // The protection attributes of the allocated memory region
    WORD   PartitionId;         // The partition ID, a member added in Windows 10 version 2004
    SIZE_T RegionSize;          // The size of the memory region
    DWORD  State;               // The state of the memory region（MEM_COMMIT,MEM_FREE,MEM_RESERVE）
    DWORD  Protect;             // The protection attributes of the current memory region
    DWORD  Type;                // The type of the memory region（MEM_IMAGE,MEM_MAPPED,MEM_PRIVATE）
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

```
For more detailed information about MEMORY_BASIC_INFORMATION keywords and methods, please refer to its documentation.
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

## Example 1 of VirtualQuery
How to use the VirtualQuery function to query and output information about a specific memory region
```c
#include <windows.h>
#include <stdio.h>

void PrintMemoryInfo(LPCVOID address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        printf("Base Address: %p\n", mbi.BaseAddress);
        printf("Allocation Base: %p\n", mbi.AllocationBase);
        printf("Region Size: %zu bytes\n", mbi.RegionSize);
        printf("State: 0x%lx\n", mbi.State);
        printf("Type: 0x%lx\n", mbi.Type);
    } else {
        printf("VirtualQuery failed with error code %lu\n", GetLastError());
    }
}

int main() {
    PrintMemoryInfo((LPCVOID)0x00400000); 
    return 0;
}
```
The return values: 
```
Base Address: 0x00400000
Allocation Base: 0x00400000
Region Size: 4096 bytes
State: 0x1000 //MEM_COMMIT
Type: 0x20000 //MEM_PRIVATE
```
## Example 2 of VirtualQuery
We allocated a 1024-byte virtual memory block with VirtualAlloc, queried its information using VirtualQuery, and released it with VirtualFree. Ensure the lpBuffer size passed to VirtualQuery is sufficient to hold the queried virtual memory information to avoid ERROR_INSUFFICIENT_BUFFER.
```CPP
#include <windows.h>
#include <iostream>
 
#include <windows.h>
#include <iostream>
 
int main() {
    // Allocate a virtual memory block of size 1024 bytes
    LPVOID p = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL) {
        // Memory allocation failed
        return -1;
    }
 
    // Define structure to store virtual memory information
    MEMORY_BASIC_INFORMATION mbi;
 
    // Query virtual memory information
    SIZE_T size = VirtualQuery(p, &mbi, sizeof(mbi));
    if (size == 0) {
        // Query failed
        return -1;
    }
 
    // Output virtual memory information
    std::cout << "Base address of the virtual memory block: " << mbi.BaseAddress << std::endl;
    std::cout << "Size of the virtual memory block: " << mbi.RegionSize << std::endl;
    std::cout << "State of the virtual memory block: " << mbi.State << std::endl;
    std::cout << "Protection level of the virtual memory block: " << mbi.Protect << std::endl;
    std::cout << "Type of access to the virtual memory block: " << mbi.Type << std::endl;

    // Free virtual memory
    VirtualFree(p, 0, MEM_RELEASE);
 
    return 0;
}

```

## Other similar software
- Volatility:
Volatility is a powerful tool for memory forensics and analysis, extracting valuable information from memory snapshots without directly using VirtualQuery.
- Rekall:
Similar to Volatility, Rekall is a memory forensics tool that achieves comparable effects in memory analysis, also without direct use of VirtualQuery.
- Process Hacker:
Process Hacker is a robust tool for task management and system monitoring. It utilizes various techniques, including VirtualQuery or similar APIs, to access and modify memory.
- Cheat Engine:
Cheat Engine is an open-source tool for scanning and modifying memory, commonly used for game cheats. It employs VirtualQuery and other APIs for these tasks.
- WinDbg:
WinDbg, a Microsoft debugging tool, is used for memory analysis and debugging. While not primarily a memory scanning tool, it can assist in memory analysis using techniques that may involve VirtualQuery.



### Resource
https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hooking/
https://www.secforce.com/blog/whisper2shout-unhooking-technique/
https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/debugger/getting-started-with-windbg.md
