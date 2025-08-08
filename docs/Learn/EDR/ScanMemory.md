# Scan Process Memory

In addition to scanning static files with Yara rules, directly scanning memory is another effective strategy for detecting malicious behavior. To scan a process's memory, we can use the VirtualQuery function. VirtualQuery is a Windows API function that retrieves information about a specified memory region. This function is very useful for memory analysis and malware detection, particularly when analyzing the memory distribution of a process.

## VirtualQuery

Parameters of `VirtualQuery` (see: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery):

```c

SIZE_T VirtualQuery(
  [in, optional] LPCVOID                   lpAddress, // A pointer to the base address of the region of pages
  [out]          PMEMORY_BASIC_INFORMATION lpBuffer,  // A pointer to a MEMORY_BASIC_INFORMATION structure
  [in]           SIZE_T                    dwLength   // The size of the buffer pointed to by the lpBuffer
);
```

## MEMORY_BASIC_INFORMATION

The output of `VirtualQuery` is stored in `MEMORY_BASIC_INFORMATION`, which describes a range of pages in a process's virtual address space (base address, size, state, protection, type). See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

```c
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

## Example 1: VirtualQuery basics

Query and print information about a specific memory region:

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
State: 0x1000 // MEM_COMMIT
Type: 0x20000 // MEM_PRIVATE
```

## Example 2: Allocate, query, and free

Allocate a 1024-byte virtual memory block with VirtualAlloc, query it using VirtualQuery, then release it with VirtualFree. Ensure `lpBuffer` is large enough or you may get `ERROR_INSUFFICIENT_BUFFER`.

```c
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

### Resources

- https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hooking/
- https://www.secforce.com/blog/whisper2shout-unhooking-technique/
- https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/debugger/getting-started-with-windbg.md
