#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <cstdint>

namespace IAT {
    enum IATRESULT {
        IAT_SUCCESS = 0,
        IAT_ERROR_NOT_FOUND,
        IAT_ERROR_INVALID_HANDLE,
        IAT_ERROR_INVALID_SIGNATURE
	};

    void dump() {
        HMODULE hModule = GetModuleHandle(NULL); 
        if (!hModule) {
            std::cerr << "Failed to get module handle\n";
            return;
        }
        // Get DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS signature\n";
            return;
        }
        // Get NT headers
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid NT signature\n";
            return;
        }
        // Get import directory
        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) {
            std::cout << "No imports found.\n";
            return;
        }
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

            PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk); // Import names
            PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);         // Addresses
            while (thunkILT->u1.AddressOfData) {
                if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Imported by ordinal
                    WORD ordinal = IMAGE_ORDINAL(thunkILT->u1.Ordinal);
                    std::cout << "  Ordinal: " << ordinal << "\n";
                }
                else {
                    // Imported by name
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + thunkILT->u1.AddressOfData);
                    std::cout << "[" << dllName << "]\t\t" << import->Name << std::endl;
                }
				++thunkILT;
                ++thunkIAT;
            }
            ++importDesc;
        }
	}

    IATRESULT HookIAT(const char* dllName, const char* funcName, void* newFunc, void** originalFunc) {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) {
            return IAT_ERROR_INVALID_HANDLE;
        }
        // Get DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return IAT_ERROR_INVALID_SIGNATURE;
        }
        // Get NT headers
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return IAT_ERROR_INVALID_SIGNATURE;
        }
        // Get import directory
        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) {
            return IAT_ERROR_NOT_FOUND;
        }
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            const char* currentDllName = (const char*)((BYTE*)hModule + importDesc->Name);
            if (_stricmp(currentDllName, dllName) == 0) {
                PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
                while (thunkILT->u1.AddressOfData) {
                    if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + thunkILT->u1.AddressOfData);
                        if (_stricmp(import->Name, funcName) == 0) {
                            DWORD oldProtect;
                            VirtualProtect(&thunkIAT->u1.Function, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
                            *originalFunc = (void*)thunkIAT->u1.Function; // Save original function address
							thunkIAT->u1.Function = (DWORD_PTR)newFunc;
                            VirtualProtect(&thunkIAT->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                            std::cout << "Hooked " << funcName << " in " << dllName << "\n";
                            return IAT_SUCCESS;
                        }
                    }
                    ++thunkILT;
                    ++thunkIAT;
                }
            }
            ++importDesc;
        }
        std::cerr << "Function " << funcName << " not found in " << dllName << "\n";
		return IAT_ERROR_NOT_FOUND;
	}
}

typedef BOOL(WINAPI* IsDebuggerPresentFunc)();
IsDebuggerPresentFunc originalFunc = NULL;

bool fake_isdebugger_present() {
    if (originalFunc)
    {
        printf("Original return: %s\n", originalFunc() ? "True" : "False");
    }
    return false;
}

int main()
{
    std::cout << "IAT Example\n";

    IAT::dump();
    /*
[KERNEL32.dll]          GetModuleHandleW
[KERNEL32.dll]          IsDebuggerPresent
[KERNEL32.dll]          RaiseException
[KERNEL32.dll]          MultiByteToWideChar
[KERNEL32.dll]          WideCharToMultiByte
[KERNEL32.dll]          RtlCaptureContext
[KERNEL32.dll]          RtlLookupFunctionEntry
[KERNEL32.dll]          RtlVirtualUnwind
[KERNEL32.dll]          UnhandledExceptionFilter
[KERNEL32.dll]          SetUnhandledExceptionFilter
[KERNEL32.dll]          GetCurrentProcess
[KERNEL32.dll]          TerminateProcess
[KERNEL32.dll]          IsProcessorFeaturePresent
[KERNEL32.dll]          QueryPerformanceCounter
[KERNEL32.dll]          GetCurrentProcessId
[KERNEL32.dll]          GetSystemTimeAsFileTime
[KERNEL32.dll]          InitializeSListHead
[KERNEL32.dll]          GetStartupInfoW
[KERNEL32.dll]          GetLastError
[KERNEL32.dll]          GetProcAddress
[KERNEL32.dll]          HeapAlloc
[KERNEL32.dll]          HeapFree
[KERNEL32.dll]          GetProcessHeap
[KERNEL32.dll]          VirtualQuery
[KERNEL32.dll]          FreeLibrary
[KERNEL32.dll]          GetCurrentThreadId
[KERNEL32.dll]          VirtualProtect
[MSVCP140D.dll]         ?uncaught_exception@std@@YA_NXZ
[MSVCP140D.dll]         ?good@ios_base@std@@QEBA_NXZ
[MSVCP140D.dll]         ?flags@ios_base@std@@QEBAHXZ
[MSVCP140D.dll]         ?width@ios_base@std@@QEBA_JXZ
[MSVCP140D.dll]         ?width@ios_base@std@@QEAA_J_J@Z
[MSVCP140D.dll]         ?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z
[MSVCP140D.dll]         ?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z
[MSVCP140D.dll]         ?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
[MSVCP140D.dll]         ?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
[MSVCP140D.dll]         ?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ
[MSVCP140D.dll]         ??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z
[MSVCP140D.dll]         ?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ
[MSVCP140D.dll]         ?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADXZ
[MSVCP140D.dll]         ?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ
[MSVCP140D.dll]         ?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_ostream@DU?$char_traits@D@std@@@2@XZ
[MSVCP140D.dll]         ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z
[MSVCP140D.dll]         ?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z
[MSVCP140D.dll]         ??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z
[MSVCP140D.dll]         ?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z
[MSVCP140D.dll]         ??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z
[VCRUNTIME140_1D.dll]           __CxxFrameHandler4
[VCRUNTIME140D.dll]             __C_specific_handler
[VCRUNTIME140D.dll]             __C_specific_handler_noexcept
[VCRUNTIME140D.dll]             memcpy
[VCRUNTIME140D.dll]             __std_type_info_destroy_list
[VCRUNTIME140D.dll]             __current_exception
[VCRUNTIME140D.dll]             __current_exception_context
[VCRUNTIME140D.dll]             __vcrt_LoadLibraryExW
[VCRUNTIME140D.dll]             __vcrt_GetModuleFileNameW
[VCRUNTIME140D.dll]             __vcrt_GetModuleHandleW
[ucrtbased.dll]         _initialize_onexit_table
[ucrtbased.dll]         _register_onexit_function
[ucrtbased.dll]         _execute_onexit_table
[ucrtbased.dll]         _crt_atexit
[ucrtbased.dll]         _crt_at_quick_exit
[ucrtbased.dll]         terminate
[ucrtbased.dll]         _wmakepath_s
[ucrtbased.dll]         _wsplitpath_s
[ucrtbased.dll]         wcscpy_s
[ucrtbased.dll]         _seh_filter_dll
[ucrtbased.dll]         strcpy_s
[ucrtbased.dll]         __p__commode
[ucrtbased.dll]         _set_new_mode
[ucrtbased.dll]         _configthreadlocale
[ucrtbased.dll]         _register_thread_local_exe_atexit_callback
[ucrtbased.dll]         __stdio_common_vsprintf_s
[ucrtbased.dll]         __p___argv
[ucrtbased.dll]         __p___argc
[ucrtbased.dll]         _set_fmode
[ucrtbased.dll]         _exit
[ucrtbased.dll]         exit
[ucrtbased.dll]         _initterm_e
[ucrtbased.dll]         _initterm
[ucrtbased.dll]         _get_initial_narrow_environment
[ucrtbased.dll]         _initialize_narrow_environment
[ucrtbased.dll]         _configure_narrow_argv
[ucrtbased.dll]         __setusermatherr
[ucrtbased.dll]         _set_app_type
[ucrtbased.dll]         _seh_filter_exe
[ucrtbased.dll]         _CrtDbgReportW
[ucrtbased.dll]         _CrtDbgReport
[ucrtbased.dll]         strlen
[ucrtbased.dll]         _c_exit
[ucrtbased.dll]         strcat_s
[ucrtbased.dll]         _cexit
[ucrtbased.dll]         __stdio_common_vfprintf
[ucrtbased.dll]         __acrt_iob_func
[ucrtbased.dll]         _stricmp
    */

	// This is the original IsDebuggerPresent function without any hooks. 
	// Should return true as we're debugging through Visual Studio.
	printf("IsDebuggerPresent: %s\n", IsDebuggerPresent() ? "True" : "False");

	auto result = IAT::HookIAT("kernel32.dll", "IsDebuggerPresent", (void*)fake_isdebugger_present, (void**)&originalFunc);
    if(result != IAT::IAT_SUCCESS) {
        std::cerr << "Failed to hook IsDebuggerPresent, error code: " << result << "\n";
        return -1;
	}
    else if(result == IAT::IAT_SUCCESS) {
        std::cout << "Successfully hooked IsDebuggerPresent\n";
	}
    printf("IsDebuggerPresent: %s\n", IsDebuggerPresent() ? "True" : "False");
}
