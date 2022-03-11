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

Có thể phát hiện tool đang chuyển hướng ```BlockInput()```. Bởi hàm này chỉ block đươc 1 lần, lần gọi sau sẽ trả về false. Nếu sau cùng mà nó vẫn trả về 
về true => đang bị debug

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

# 4. NtSetInformationThread()

Hàm này có thể giấu 1 thread khỏi debugger

Khi thread bị giấu debugger sẽ không nhận được bất cứ event nào liên quan đến thread này. Do đó chúng ta có thể tình checksum, hay debug flag tại đây.

Tuy nhiên nếu trong thread đã có breakpoint, hay giấu thread main thì tiến trình sẽ bị crash do debugger không start được tiến trình.


VD nếu step vào đây bằng 1 debugger, thì thì debugger sẽ đơ ngay khi hàm ```NtSetInformationThread()``` được gọi

```C
#define NtCurrentThread ((HANDLE)-2)

bool AntiDebug()
{
    NTSTATUS status = ntdll::NtSetInformationThread(
        NtCurrentThread, 
        ntdll::THREAD_INFORMATION_CLASS::ThreadHideFromDebugger, 
        NULL, 
        0);
    return status >= 0;
}
```

# 5. EnumWindows() and SuspendThread()

Ý tưởng ở đây là suspend 1 thread nào đó của tiến trình cha

Đầu tiên chúng ta xác nhận tiến trình cha có đang bị debug không, ví dụ ở đây là kiểm tra bằng hàm ```EnumWindows(``` hoặc ```EnumThreadWindows()```, hay tìm dựa trên PID ```GetWindowThreadProcessId()```

Sau đó kiểm tra title (tiêu đề) của các window bằng ```GetWindowTextW()```, nếu trả về là các tiêu đề liên quan đến debug thì dừng luôn thread đó bằng ```SuspendThread()```

VD:

```C
DWORD g_dwDebuggerProcessId = -1;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    DWORD dwProcessId = *(PDWORD)lParam;

    DWORD dwWindowProcessId;
    GetWindowThreadProcessId(hwnd, &dwWindowProcessId);

    if (dwProcessId == dwWindowProcessId)
    {
        std::wstring wsWindowTitle{ string_heper::ToLower(std::wstring(GetWindowTextLengthW(hwnd) + 1, L'\0')) };
        GetWindowTextW(hwnd, &wsWindowTitle[0], wsWindowTitle.size());

        if (string_heper::FindSubstringW(wsWindowTitle, L"dbg") || 
            string_heper::FindSubstringW(wsWindowTitle, L"debugger"))         //Nếu 1 trong 2 chuỗi này trong tiến trình
        {
            g_dwDebuggerProcessId = dwProcessId;
            return FALSE;
        }
        return FALSE;
    }

    return TRUE;
}

bool IsDebuggerProcess(DWORD dwProcessId) const
{
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&dwProcessId));
    return g_dwDebuggerProcessId == dwProcessId;          //Lấy PID của tiến trình vừa bị phát hiện
}

bool SuspendDebuggerThread()
{
    THREADENTRY32 ThreadEntry = { 0 };
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    DWORD dwParentProcessId = process_helper::GetParentProcessId(GetCurrentProcessId());
    if (-1 == dwParentProcessId)
        return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwParentProcessId);
    if(Thread32First(hSnapshot, &ThreadEntry))        
    {
        do
        {
            if ((ThreadEntry.th32OwnerProcessID == dwParentProcessId) && IsDebuggerProcess(dwParentProcessId))         //Next liên tiếp đến khi tìm được PID của tiến trình hiện tạo của tiến trình cha và tiến trình cha đang bị debug
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
                if (hThread)
                    SuspendThread(hThread);                     //Đóng thread
                break;
            }
        } while(Thread32Next(hSnapshot, &ThreadEntry));      
    }

    if (hSnapshot)
        CloseHandle(hSnapshot);

    return false;
}

```

# 6. SwitchDesktop()

Chuyển hướng tiến trình đến một desktop khác, bởi window chấp nhận nhiều window trong 1 phiên, nên khi chuyển hướng tiến trình đến 1 desktop khác thì event chuột bà bàn phím sẽ không còn hiệu lực => không debug được

```C
BOOL Switch()
{
    HDESK hNewDesktop = CreateDesktopA(
        m_pcszNewDesktopName, 
        NULL, 
        NULL, 
        0, 
        DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP, 
        NULL);
    if (!hNewDesktop) //Nếu không tạo được thì trả về false
        return FALSE;

    return SwitchDesktop(hNewDesktop); //Chuyển Desktop đến NewDesktop vừa tạo
}
```

# 7. OutputDebugString()

Trước các phiên bản win Vista, ý tưởng là kiểm tra nếu không có debuger mà hàm ```OutputDebugString()``` lại được gọi ra thì sẽ báo lỗi

```C
bool IsDebugged()
{
    if (IsWindowsVistaOrGreater())
        return false;

    DWORD dwLastError = GetLastError();
    OutputDebugString(L"AntiDebug_OutputDebugString");
    return GetLastError() != dwLastError;
}
```

# Khắc phục

KHi đang debug thì có thể skip các hàm nghi là check debug

Chuyển hướng khi thấy các hàm sau:

```C
kernel32!DebugActiveProcess()
ntdll!DbgUiDebugActiveProcess()
ntdll!NtDebugActiveProcess()
kernel32!GenerateConsoleCtrlEvent()
user32!NtUserBlockInput()
ntdll!NtSetInformationThread()
user32!NtUserBuildHwndList()
kernel32!SuspendThread()
user32!SwitchDesktop()
kernel32!OutputDebugStringW()
```
