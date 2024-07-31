# API hooking

API hooking is a process of intercepting and altering the behavior of API calls. This technique is commonly used by many Endpoint Detection and Response (EDR) or antivirus vendors to monitor processes or code execution in real-time for malicious activity.

## The process of API hooking

API hooking occurs during the startup of a program when certain libraries/DLLs are loaded as modules into the address space of the corresponding user program.

![API hooking](../../assets/API-Hooking/APIHooking.png)

Step 1: When the program calls MessageBoxA(), it jumps to the address of that function.

Step 2: Insert a jump instruction (jmp) in MessageBoxA() to redirect it to our hook function.

Step 3: After executing the hook, it jumps to the trampoline function, which contains a copy of the original first few bytes of MessageBoxA(). This allows the original function's logic to continue after the hook function executes.

Step 4: Once MessageBoxA() finishes executing, it returns to the user code to continue execution.

## Microsoft Detours

Microsoft Detours is a software package for monitoring and intercepting API calls on Windows. It provides a general method for implementing x86 and x64 Windows API hooking, allowing for monitoring, tampering, or any other actions you wish to perform using API hooking. For more details, please refer to [Detours](https://github.com/microsoft/Detours).

Example:

The following code demonstrates how to use the Detours library to hook a function on the Windows platform and how to unhook it.

```c++
#include <windows.h>
#include <detours.h>
#include <iostream>

typedef BOOL(WINAPI* FuncMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
FuncMessageBoxA pMessageBoxA = MessageBoxA;

BOOL WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Intercepted MessageBoxA called!" << std::endl;
    std::cout << "Text: " << lpText << std::endl;
    std::cout << "Caption: " << lpCaption << std::endl;
    BOOL result = pMessageBoxA(hWnd, "Hooked Function", lpCaption, uType);
    return result;
}
int main()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread()); //Setting the current thread as the target thread for Detours
    DetourAttach(&(PVOID&)pMessageBoxA, HookedMessageBoxA); //Replacing the function pointer for MessageBoxA with the function pointer for HookedMessageBoxA
    DetourTransactionCommit(); //Submitting the hook operation
    // Hooked
    MessageBoxA(NULL, "Original MessageBox!", "Hooked MessageBoxA", MB_OK);
    getchar();

    /*DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)pMessageBoxA, HookedMessageBoxA); //Removing a previously added hook
    DetourTransactionCommit();
    // Original
    MessageBoxA(NULL, "Really Original Messagebox!", "Original MessageBoxA", MB_OK);
    */

    return 0;
}
```

Hooking :
![Ex1](../../assets/API-Hooking/AttachExample.png)
Cancel hooking :
![Ex2](../../assets/API-Hooking/DetachExample.png)

## EDR hook list

Antivirus software and Endpoint Detection and Response (EDR) platforms can also use behavior-based analysis to identify suspicious API activities. For a list of commonly used EDR hooks, you can refer to this curated [EDR hook list](https://github.com/Mr-Un1k0d3r/EDRs).

![EDR hook list](../../assets/API-Hooking/EDRHookList.png)

## Tools

- https://github.com/microsoft/Detours
- https://github.com/Mr-Un1k0d3r/EDRs

## Resource

- https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++
- https://khaled0x07.medium.com/windows-api-hooking-malware-analysis-960da6af5433
- https://www.linkedin.com/pulse/eppedr-api-hooking-daniel-feichter-1e/
- https://medium.com/@s12deff/api-hooking-with-detours-8d57313e59f6
