# Trực tiếp kiểm tra tương tác

Các kĩ thuật này cho phép tiến trình quản lý giao diện người dùng hay tham gia vào tiền trình cha để phát hiện debugger

# 1.Tự Debug

Phải dùng ít nhất 3 hàm sau để attach debugger vào tiến trình:

- kernel32!DebugActiveProcess()

- ntdll!DbgUiDebugActiveProcess()

- ntdll!NtDebugActiveProcess()

* Vì trong 1 thời điểm chỉ có 1 debugger có thể attach vào tiến trình, nên nếu có thêm 1 debugger khác attach vào  => crash

VD:

```C
#define EVENT_SELFDBG_EVENT_NAME L"SelfDebugging"

bool IsDebugged()
{
    WCHAR wszFilePath[MAX_PATH], wszCmdLine[MAX_PATH];
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hDbgEvent;

    hDbgEvent = CreateEventW(NULL, FALSE, FALSE, EVENT_SELFDBG_EVENT_NAME);
    if (!hDbgEvent)
        return false;

    if (!GetModuleFileNameW(NULL, wszFilePath, _countof(wszFilePath)))
        return false;

    swprintf_s(wszCmdLine, L"%s %d", wszFilePath, GetCurrentProcessId());
    if (CreateProcessW(NULL, wszCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return WAIT_OBJECT_0 == WaitForSingleObject(hDbgEvent, 0);      
    }

    return false;
}

bool EnableDebugPrivilege() 
{
    bool bResult = false;
    HANDLE hToken = NULL;
    DWORD ec = 0;

    do
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
            break;

        TOKEN_PRIVILEGES tp; 
        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
            break;

        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            break;

        bResult = true;
    }
    while (0);

    if (hToken) 
        CloseHandle(hToken);

    return bResult;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {        
        if (IsDebugged())
            ExitProcess(0);
    }
    else
    {
        DWORD dwParentPid = atoi(argv[1]);
        HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, EVENT_SELFDBG_EVENT_NAME);
        if (hEvent && EnableDebugPrivilege())
        {
            if (FALSE == DebugActiveProcess(dwParentPid))
                SetEvent(hEvent);
            else
                DebugActiveProcessStop(dwParentPid);
        }
        ExitProcess(0);
    }
    
    // ...
    
    return 0;
}
```

# 2. GenerateConsoleCtrlEvent()

Khi user nhấn Ctrl + C hay Ctrl + break, hệ thống sẽ kiểm tra có handler nào chuẩn bị cho việc này không. Vì hầu hết các chương trình console mặc định đều sẽ có handler gọi đến hàm ```ExitProcess()```, nên chúng ta có thể tạo một handler để bỏ qua lệnh Ctrl+C hay Ctrl+Break

Tuy nhiên khi chương trình đã bị debug mà handler vẫn chưa được tạo thì exception ```DBG_CONTROL_C``` sẽ được tạo. Do đó chúng ta có thể kiểm tra nếu có exception ```DBG_CONTROL_C``` trong tiến trình thì có thể tiến trình đó đang bị debug.

VD

```C
bool g_bDebugged{ false };
std::atomic<bool> g_bCtlCCatched{ false };

static LONG WINAPI CtrlEventExeptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == DBG_CONTROL_C)
    {
        g_bDebugged = true;
        g_bCtlCCatched.store(true);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType)
    {
    case CTRL_C_EVENT:
        g_bCtlCCatched.store(true);
        return TRUE;
    default:
        return FALSE;
    }
}

bool IsDebugged()
{
    PVOID hVeh = nullptr;
    BOOL bCtrlHadnlerSet = FALSE;

    __try
    {
        hVeh = AddVectoredExceptionHandler(TRUE, CtrlEventExeptionHandler);
        if (!hVeh)
            __leave;

        bCtrlHadnlerSet = SetConsoleCtrlHandler(CtrlHandler, TRUE);
        if (!bCtrlHadnlerSet)
            __leave;

        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        while (!g_bCtlCCatched.load())
            ;
    }
    __finally
    {
        if (bCtrlHadnlerSet)
            SetConsoleCtrlHandler(CtrlHandler, FALSE);

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);
    }

    return g_bDebugged;
}
```

# 3. BlockInput()

```BlockInput()``` có thể block tất cả event của chuột và bàn phím (từ bản Win Vista trở lên thì cần quyền administrator)

Có thể phát hiện tool đang chuyển hướng ```BlockInput()```. Bởi hàm này chỉ block đươc 1 lần, lần gọi sau sẽ trả về false. Nếu sau cùng mà nó vẫn trả về true => đang bị debug

```C
bool IsHooked ()
{
    BOOL bFirstResult = FALSE, bSecondResult = FALSE;
    __try
    {
        bFirstResult = BlockInput(TRUE);
        bSecondResult = BlockInput(TRUE);
    }
    __finally
    {
        BlockInput(FALSE);
    }
    return bFirstResult && bSecondResult;
}
```


