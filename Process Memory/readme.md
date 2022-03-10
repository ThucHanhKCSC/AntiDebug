# Process Memory

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
