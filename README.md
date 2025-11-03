# IAT Hook
This project demonstrates Import Address Table (IAT) inspection and hooking on Windows using C++.
It’s a minimal example that shows how to list imported functions from the current process and dynamically replace one with a custom implementation.

## Overview
The Import Address Table (IAT) is part of a PE (Portable Executable) file that stores the addresses of imported functions from external DLLs.
This project contains two key features:

1. IAT Dumping – Enumerates and prints all DLL imports and their functions.
2. IAT Hooking – Replaces a specific imported function (in this case, IsDebuggerPresent) with a custom function at runtime.

## How It Works
* The ``IAT::dump()`` function walks through the PE headers, finds the Import Directory, and lists every imported DLL and its symbols.
* The ``IAT::HookIAT()`` function searches for a given DLL and function name, changes the page protection, and swaps out the original function pointer for your own.
* In this example, it hooks ``IsDebuggerPresent`` from ``kernel32.dll`` and redirects it to a custom function that always returns ``false``.

The sample output will first show the original import table, then the results before and after hooking.
```
[KERNEL32.dll]    IsDebuggerPresent

IsDebuggerPresent: True
Hooked IsDebuggerPresent in kernel32.dll
IsDebuggerPresent: False
Original return: True
```

This code is for educational and research purposes only.
Hooking APIs can interfere with system behavior or trigger anti-tamper/anti-cheat systems.
Run only in a controlled test environment.
The example uses VirtualProtect to modify memory protection before writing into the IAT.
