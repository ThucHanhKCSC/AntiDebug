# Process Memory

![download](https://user-images.githubusercontent.com/101321172/157797737-1e3ba116-8acc-477d-9428-80b74163045a.svg)


Một tiến trình có thể tự phát hiện debugger bằng việc kiểm tra bộ nhớ của nó

# 1.Breakpoints
kiểm tra chương trình có breakpoint hay kiểm tra các thanh ghi debug

# 1.1 Software Breakpoints (INT3): tìm breakpoint

Ý tưởng ở đây là tìm trong phần mã máy  byte 0xCC của 1 số hàm. 

```C
bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory; 
    for (SIZE_T i = 0; ; i++)
    {
        // Break on RET (0xC3) if we don't know the function's size
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}

bool IsDebugged()
{
    PVOID functionsToCheck[] = {
        &Function1,
        &Function2,
        &Function3,
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr))
            return true;
    }
    return false;
}
```

# 1.2. Anti-Step-Over

Phát hiện software breakpoint (0xcc) ở địa chỉ trả về khi gọi hàm, nếu phát hiện được => thay địa chỉ trả về bằng nop => crash phần mềm

# 1.2.1. Thay đổi bộ nhớ một cách trực tiếp

Kiểm tra nếu trong địa chỉ trả về có 0xcc (có breakpoint) => thay đổi dữ liệu, bộ nhớ để làm crash chương trình

```C
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void foo()
{
    // ...
    
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC) // int 3
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90; // nop: nop địa chỉ trả về
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
    
    // ...
}
```

# 1.2.2. ReadFile()

Sử dụng ```ReadFile()``` để patch đoạn code ở địa chỉ trả về.
Ý tưởng sẽ là đọc file của tiến trình và truyền địa chỉ trả về vào bộ nhớ đệm của hàm ```ReadFile()``` => crash chương trình

```C
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void foo()
{
    // ...
    
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC) // int 3             phát hiện software breakpoint
    {
        DWORD dwOldProtect, dwRead;
        CHAR szFilePath[MAX_PATH];
        HANDLE hFile;

        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            if (GetModuleFileNameA(NULL, szFilePath, MAX_PATH))
            {
                hFile = CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);     
                if (INVALID_HANDLE_VALUE != hFile)
                    ReadFile(hFile, pRetAddress, 1, &dwRead, NULL);
            }
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
    
    // ...
}
```

# 1.2.3. WriteProcessMemory()


```C
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void foo()
{
    // ...
    
    BYTE Patch = 0x90;
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC)
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            WriteProcessMemory(GetCurrentProcess(), pRetAddress, &Patch, 1, NULL); // thay pRetAddress bằng Patch == 0x90 == nop
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
    
    // ...
}
```

# 1.2.4. Toolhelp32ReadProcessMemory()

Hàm ```Toolhelp32ReadProcessMemory()``` để để đọc dữ liệu từ tiến trình, tuy nhiên còn có thể anti-step-over

```C

#include <TlHelp32.h>

bool foo()
{
    // ..
    
    PVOID pRetAddress = _ReturnAddress();
    BYTE uByte;       // ptr đến bộ đệm, và được nhận giá trị trong địa chỉ của tiến trình
    if (FALSE != Toolhelp32ReadProcessMemory(GetCurrentProcessId(), _ReturnAddress(), &uByte, sizeof(BYTE), NULL))
    {
        if (uByte == 0xCC)    //Nếu tìm được software breakpoint
            ExitProcess(0);
    }
    
    // ..
```
# 1.3. Memory Breakpoints

Nếu chương trình đang chạy dưới 1 debugger như Olly hoặc Immunity, thì chúng sẽ dùng guard pages

Chúng ta có thể thay đổi cách mà debugger sử dụng bộ nhớ.

Trước hết là cấp phát 1 bộ đệm chỉ có 1 lệnh ```ret```, sau đó đánh dấu guard pages cho vùng này, push địa chỉ nơi xử lý trường hợp nếu có debugger vào ngăn xếp và chuyển đến vùng đệm được cấp phát. Lệnh RET sẽ được thực thi và nếu debugger (OllyDbg hoặc ImmunityDebugger) có mặt,

```C
bool IsDebugged()
{
    DWORD dwOldProtect = 0;
    SYSTEM_INFO SysInfo = { 0 };

    GetSystemInfo(&SysInfo);
    PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (NULL == pPage)
        return false; 

    PBYTE pMem = (PBYTE)pPage;
    *pMem = 0xC3; 

    // Make the page a guard page         
    if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect))
        return false;

    __try
    {
        __asm
        {
            mov eax, pPage                  
            push mem_bp_being_debugged
            jmp eax
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        VirtualFree(pPage, NULL, MEM_RELEASE);
        return false;
    }

mem_bp_being_debugged:
    VirtualFree(pPage, NULL, MEM_RELEASE);
    return true;
}

```

# 1.4. Hardware Breakpoints

Kiểm tra giá trị trong các thanh ghi debug: DR0, DR1, DR2, DR3 trong thread context, nếu != 0 => có thể đang vị debug

```C
bool IsDebugged()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT)); 
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 

    if(!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
```

# 2. Một số kĩ thuật khác

# 2.1. NtQueryVirtualMemory()

Kiểm tra phần 2 trường Shared and ShareCount of the [Working Set Block](https://docs.microsoft.com/en-us/windows/win32/memory/working-set?redirectedfrom=MSDN), nếu có breakpoint thì 2 trường này sẽ không đưuoc jtaoj

NTDLL
```C
namespace ntdll
{
//...

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// ...

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
} MEMORY_INFORMATION_CLASS;

// ...

typedef union _PSAPI_WORKING_SET_BLOCK {
    ULONG Flags;
    struct {
        ULONG Protection :5;
        ULONG ShareCount :3;
        ULONG Shared     :1;
        ULONG Reserved   :3;
        ULONG VirtualPage:20;
    };
} PSAPI_WORKING_SET_BLOCK, *PPSAPI_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_LIST
{
    ULONG NumberOfPages;
    PSAPI_WORKING_SET_BLOCK WorkingSetList[1];
} MEMORY_WORKING_SET_LIST, *PMEMORY_WORKING_SET_LIST;

// ...
}
```

```C
bool IsDebugged()
{
#ifndef _WIN64
    NTSTATUS status;
    PBYTE pMem = nullptr;
    DWORD dwMemSize = 0;

    do
    {
        dwMemSize += 0x1000;
        pMem = (PBYTE)_malloca(dwMemSize);
        if (!pMem)
            return false;

        memset(pMem, 0, dwMemSize);
        status = ntdll::NtQueryVirtualMemory(
            GetCurrentProcess(), 
            NULL, 
            ntdll::MemoryWorkingSetList, 
            pMem, 
            dwMemSize, 
            NULL);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    ntdll::PMEMORY_WORKING_SET_LIST pWorkingSet = (ntdll::PMEMORY_WORKING_SET_LIST)pMem;
    for (ULONG i = 0; i < pWorkingSet->NumberOfPages; i++)
    {
        DWORD dwAddr = pWorkingSet->WorkingSetList[i].VirtualPage << 0x0C;
        DWORD dwEIP = 0;
        __asm
        {
            push eax
            call $+5
            pop eax
            mov dwEIP, eax
            pop eax
        }

        if (dwAddr == (dwEIP & 0xFFFFF000))
            return (pWorkingSet->WorkingSetList[i].Shared == 0) || (pWorkingSet->WorkingSetList[i].ShareCount == 0);
    }
#endif // _WIN64
    return false;
}
```

# 2.2 Phát hiệu patch trong hàm

ở phần [flag](https://github.com/ThucHanhKCSC/AntiDebug/tree/main/Debug%20Flags) đã đề cập đến việc sử dụng hàm ```IsDebuggerPresent()``` bằng cách trả về thanh eax giá trị 0 cho không debug, != 0 cho việc debug, bypass cái này bằng việc thay đổi giá trị eax một cách dễ ràng

Ở phần này tìm hiểu xem hàm ```IsDebuggerPresent()``` có bị thay đổi không bằng cách so sánh byte đầu của func này với byte đầu của func tương tự trong cùng tiến trình. Bởi chúng phải luôn giữ nguyên, nên nếu phát hiện có sự khác nhay thì có thể tiến trình đang bị debug

```C
bool IsDebuggerPresent()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return false;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDebuggerPresent)
        return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
        return false;

    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &ProcessEntry))
        return false;

    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do
    {
        __try
        {
            if (dwCurrentPID == ProcessEntry.th32ProcessID)
                continue;

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess)
                continue;

            if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
                continue;

            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
            {
                bDebuggerPresent = true;
                break;
            }
        }
        __finally
        {
            if (hProcess)
                CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));

    if (hSnapshot)
        CloseHandle(hSnapshot);
    return bDebuggerPresent;
}
```
# 2.3 Patch DbgBreakPoint()

![dbgbreakpoint](https://user-images.githubusercontent.com/101321172/157676172-26a545fd-bb29-444b-ade1-fe6aad17c25a.png)

Lệnh cho phép debugger có được quyền kiểm soát, nên nếu chúng ta xóa breakpoint ở trong hàm ```DbgBreakPoint()``` thì debugger sẽ không thể đặt breakpoint

```C
void Patch_DbgBreakPoint()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret
}
```

# 2.4. Patch ntdll!DbgUiRemoteBreakin()

Khi 1 debugger gọi hàm ```DebugActiveProcess()```, nó sẽ đợi thông báo từ ```DbgUiRemoteBreakin()```, để ngăn debugger tác động vào tiến trình, có thể patch ```DbgUiRemoteBreakin()``` để gọi ``` TerminateProcess()```

```nasm
6A 00             push 0
68 FF FF FF FF    push -1 ; GetCurrentProcess() result
B8 XX XX XX XX    mov  eax, kernel32!TreminateProcess
FF D0             call eax
```

Tiến trình sẽ tự terninate bản thân nếu phát hiện chúng ta sử dụng debugger

```C
#pragma pack(push, 1)
    struct DbgUiRemoteBreakinPatch
    {
        WORD  push_0;
        BYTE  push;
        DWORD CurrentPorcessHandle;
        BYTE  mov_eax;
        DWORD TerminateProcess;
        WORD  call_eax;
    };
#pragma pack(pop)

void Patch_DbgUiRemoteBreakin()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (!pDbgUiRemoteBreakin)
        return;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return;

    FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
    if (!pTerminateProcess)
        return;

    DbgUiRemoteBreakinPatch patch = { 0 };
    patch.push_0 = '\x6A\x00';
    patch.push = '\x68';
    patch.CurrentPorcessHandle = 0xFFFFFFFF;
    patch.mov_eax = '\xB8';
    patch.TerminateProcess = (DWORD)pTerminateProcess;
    patch.call_eax = '\xFF\xD0';

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
        return;

    ::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
        &patch, sizeof(DbgUiRemoteBreakinPatch));
    VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}
```


# 2.5 Tổng kiểm tra checksum của code

```C
PVOID g_pFuncAddr;
DWORD g_dwFuncSize;         //giá trị size thự tế đo được
DWORD g_dwOriginalChecksum; //giá trị size đúng của hàm

static void VeryImportantFunction()
{
    // ...
}

static DWORD WINAPI ThreadFuncCRC32(LPVOID lpThreadParameter)
{
    while (true)
    {
        if (CRC32((PBYTE)g_pFuncAddr, g_dwFuncSize) != g_dwOriginalChecksum)
            ExitProcess(0);
        Sleep(10000);
    }
    return 0;
}

size_t DetectFunctionSize(PVOID pFunc)
{
    PBYTE pMem = (PBYTE)pFunc;
    size_t nFuncSize = 0;
    do
    {
        ++nFuncSize;                          //Tăng size với mỗi instruction
    } while (*(pMem++) != 0xC3); /ret
    return nFuncSize;
}

int main()
{
    g_pFuncAddr = (PVOID)&VeryImportantFunction;
    g_dwFuncSize = DetectFunctionSize(g_pFuncAddr);
    g_dwOriginalChecksum = CRC32((PBYTE)g_pFuncAddr, g_dwFuncSize);
    
    HANDLE hChecksumThread = CreateThread(NULL, NULL, ThreadFuncCRC32, NULL, NULL, NULL);
    
    // ...
    
    return 0;
}
```

# Khắc phục
- Khi đang debug: khi step trong func có Anti-Step-Over, thì dùng step in
- Cố gắng tìm đoạn mã thay đổi dữ liệu khi phát biện DBG và ```nop``` nó đi

