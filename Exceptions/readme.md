# Exceptions

Cố tình tạo ra các exception để phát hiện tiến trình hiện tại có đang bị debug không

# 1. UnhandledExceptionFilter()

Nếu có exception xảy ra mà chưa có handle cho exception thì hàm ```UnhandledExceptionFilter()``` sẽ được gọi. Có thể tạo 1 bộ lọc cho các unhandled exception bằng ```SetUnhandledExceptionFilter()```, nhưng nếu tiến trình đang bị debug thì exception sẽ chuyển cho debugger thay vì gọi cho bộ lọc. vì thế nếu có bộ lọc unhandled exception và có đầy đủ dữ liệu thì nghĩa là không có debugger nào, ngược lại là có

```nasm
include 'win32ax.inc'

.code

start:
        jmp begin

not_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Not Debugged","",MB_OK
        invoke  ExitProcess,0                                     ; Thoát chương trình luôn do gặp exception

begin:
        invoke SetUnhandledExceptionFilter, not_debugged          ; gọi SetUnhandledExceptionFilter và truyền not_debugged
        int  3                                                    ; nếu vẫn đến được đây => SetUnhandledExceptionFilter không được tạo => debugger
        jmp  being_debugged

being_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Debugged","",MB_OK
        invoke  ExitProcess,0

.end start
```

```C
LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)UnhandledExceptionFilter);
    __asm
    {
        int 3                      // CC
        jmp near being_debugged    // EB ??
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}
```
# 2. RaiseException()
 
Một số exception như DBC_CONTROL_C, DBG_RIPEVENT được sử dụng bởi debugger, vì thế thử gọi các execption này bằng ```RaiseException()```, không gọi được => đang debug

```C
bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except(DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER 
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}
```

# 3. Giấu luồng dữ liệu bằng các Exception Handle

Cách này không phát hiện được debugger, nhưng có thể giấu luồng dữ liệu của chường trình.

Có thể tạo 1 exception handle có thể tạo một tạo 1 exception có thể tạo 1 exception và cứ như vậy cho đến đoạn dữ liệu chúng ta muốn giấu 

```C
#include <Windows.h>

void MaliciousEntry()
{
    // ...
}

void Trampoline2()
{
    __try
    {
        __asm int 3;               // Đây là Debugger trap
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MaliciousEntry();
    }
}

void Trampoline1()
{
    __try 
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Trampoline2();
    }
}

int main(void)
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        Trampoline1();
    }

    return 0;
}
```

```C
#include <Windows.h>

PVOID g_pLastVeh = nullptr;

void MaliciousEntry()
{
    // ...
}

LONG WINAPI ExeptionHandler2(PEXCEPTION_POINTERS pExceptionInfo)
{
    MaliciousEntry();
    ExitProcess(0);
}

LONG WINAPI ExeptionHandler1(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (g_pLastVeh)
    {
        RemoveVectoredExceptionHandler(g_pLastVeh);
        g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler2);
        if (g_pLastVeh)
            __asm int 3;
    }
    ExitProcess(0);
}


int main(void)
{
    g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler1);
    if (g_pLastVeh)
        __asm int 3;

    return 0;
}
```

#Khắc phục:
- Khi đang debug: thấy dấu hiệu => nop
- giấu luồng: phải kiên trì trace đến khi tìm được payload
