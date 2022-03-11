# một số cách khác
![download](https://user-images.githubusercontent.com/101321172/157797686-d4ca3d33-4858-47ff-b0c1-ff3963f1cf7c.svg)


# 1. FindWindow()

Cách này liệt kê ra các window class trong hệ thống và so sánh với window class của debugger

Có thể dùng 1 số hàm sau

```C
user32!FindWindowW()
user32!FindWindowA()
user32!FindWindowExW()
user32!FindWindowExA()
```

code C

```C
const std::vector<std::string> vWindowClasses = {
    "OLLYDBG",
    "WinDbgFrameClass", // WinDbg
    "ID",               // Immunity Debugger
    "Zeta Debugger",
    "Rock Debugger",
    "ObsidianGUI",
};

bool IsDebugged()
{
    for (auto &sWndClass : vWindowClasses)
    {
        if (NULL != FindWindowA(sWndClass.c_str(), NULL))               //Ktra nếu 1 trong các window class bên trên đươc mở
            return true;                                          
    }
    return false;
}

```


# 2. Kiểm tra tiến trình cha

Ý tưởng sẽ là kiểm tra PID (process ID) của tiến trình với PID tìm được trong task manager được tạo bằng cách đúp chuột (khi tạo bằng Debugger thì sẽ có PID khác)


# 2.1. NtQueryInformationProcess()

Nhận handle bằng ```GetShellWindow()``` sau đó nhận PID bằng ```GetWindowThreadProcessId()```
Tiến trình cha sẽ được nhận từ ```PROCESS_BASIC_INFORMATION```

```C
bool IsDebugged()
{
    HWND hExplorerWnd = GetShellWindow();
    if (!hExplorerWnd)
        return false;

    DWORD dwExplorerProcessId;
    GetWindowThreadProcessId(hExplorerWnd, &dwExplorerProcessId);

    ntdll::PROCESS_BASIC_INFORMATION ProcessInfo;
    NTSTATUS status = ntdll::NtQueryInformationProcess(
        GetCurrentProcess(),
        ntdll::PROCESS_INFORMATION_CLASS::ProcessBasicInformation,
        &ProcessInfo,
        sizeof(ProcessInfo),
        NULL);
    if (!NT_SUCCESS(status))
        return false;

    return (DWORD)ProcessInfo.InheritedFromUniqueProcessId != dwExplorerProcessId;
}
```

# 2.2. CreateToolhelp32Snapshot()

PID của tiến trình cha và tên tiến trình cha có thể đươc lấy từ ```CreateToolhelp32Snapshot()``` và ```Process32Next()```

```C
DWORD GetParentProcessId(DWORD dwCurrentProcessId)
{
    DWORD dwParentProcessId = -1;
    PROCESSENTRY32W ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32FirstW(hSnapshot, &ProcessEntry))
    {
        do
        {
            if (ProcessEntry.th32ProcessID == dwCurrentProcessId)
            {
                dwParentProcessId = ProcessEntry.th32ParentProcessID;
                break;
            }
        } while(Process32NextW(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return dwParentProcessId;
}

bool IsDebugged()
{
    bool bDebugged = false;
    DWORD dwParentProcessId = GetParentProcessId(GetCurrentProcessId());

    PROCESSENTRY32 ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32First(hSnapshot, &ProcessEntry))
    {
        do
        {
            if ((ProcessEntry.th32ProcessID == dwParentProcessId) &&
                (strcmp(ProcessEntry.szExeFile, "explorer.exe")))
            {
                bDebugged = true;
                break;
            }
        } while(Process32Next(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return bDebugged;
}
```

# 3. Selectors

Các giá trị selector này có thể vi phạm 1 số trường hợp và nhận giá trị khác nhau trên các phiên bản khác nhau

VD: 

```nasm
    xor  eax, eax 
    push fs 
    pop  ds 
l1: xchg [eax], cl 
    xchg [eax], cl
```


Trên phiên bản 64 bit window, step từng dòng code một sẽ tạo ra exception ở đoạn l1.  Bởi selector DS sẽ phục hồi giá trị mặc định khi đến đoạn l1.
Ở win 32 bit, DS không có giá trị nếu có non-debugger exception. Sự khác biệt về hành vi theo phiên bản cụ thể còn mở rộng hơn nữa nếu selector SS được sử dụng. Như ở win 64 bit, selector ss sẽ được phục hồi về giá trị mặc định

```nasm
   xor  eax, eax 
    push offset l2 
    push d fs:[eax] 
    mov  fs:[eax], esp 
    push fs 
    pop  ss 
    xchg [eax], cl 
    xchg [eax], cl 
l1: int  3 ;force exception to occur 
l2: ;looks like it would be reached 
    ;if an exception occurs 
    ...
```

khi đoạn ```int 3``` đến l1, và có exception breakpoint, exception l2 sẽ không được gọi mà tiến trình sẽ bị terminate

```nasm
push 3 
pop  gs 
mov  ax, gs 
cmp  al, 3 
jne  being_debugged
```

FS và GS là một trường hợp đặc biệt. Với các giá trị cho trước, chúng sẽ bị ảnh hưởng bởi step, kể cả là trong win 32 bit. TUy nhiên trong trường hợp selector FS, giá trị mặc định của nó sẽ không được phục hồi ở win 32 bit. Nếu đúng ra là từ 0 đến 3 thì nó chỉ được set là 0. (GS cũng vậy, nhưng mặc định của GS là 0). Còn trên win 64 bit, chúng sẽ được phục hồi giá trị mặc định.

Đoạn code dưới đây cũng dễ bị ảnh hưởng bởi event ```thread-switch```. Nếu có thread-switch, thì nó sẽ như là 1 exception. là giá trị trong selector sẽ bị thay đổi. Điều này cũng đúng với ```FS```, nghĩa là nó sẽ bị đặt = 0

```nasm
    push 3 
    pop  gs 
l1: mov  ax, gs 
    cmp  al, 3 
    je   l1
```
Tuy nhiên đoạn code này dễ bị ảnh hưởng bởi vấn đề mà nó đã cố gắng phát hiện ngay từ đầu, vì nó không kiểm tra xem nhiệm vụ ban đầu có thành công hay không. bằng cách đợi cho đến khi sự kiện chuyển thread xảy ra, sau đó thực hiện việc gán trong khoảng thời gian sẽ tồn tại cho đến khi sự kiện tiếp theo xảy ra

```C
bool IsTraced()
{
    __asm
    {
        push 3
        pop  gs

    __asm SeclectorsLbl:
        mov  ax, gs
        cmp  al, 3
        je   SeclectorsLbl

        push 3
        pop  gs
        mov  ax, gs
        cmp  al, 3
        jne  Selectors_Debugged
    }

    return false;

Selectors_Debugged:
    return true;
}
```

# 4. DbgPrint()

hàm debug ```DbgPrint()``` và ```OutputDebugStringW()``` sẽ tạo ra exception ```DBG_PRINTEXCEPTION_C``` (0x40010006). Nếu cương trình bị debugger attach, debugger sẽ giải quyết cái exception này, nếu không thì excemtion handler sẽ xuất hiện. exception này sẽ trace sự tồn tại của exception handler, không tồn tại => debug

```C
bool IsDebugged()
{
    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
    }
    __except(GetExceptionCode() == DBG_PRINTEXCEPTION_C) //Neus DBG đã giải quyết exception này thì trong list exception handler sẽ không phát hiện được DBG_PRINTEXCEPTION_C
    {
        return false;
    }

    return true;
}
```

# 5. DbgSetDebugFilterState()

Hàm ```DbgSetDebugFilterState()``` và ```NtSetDebugFilterState()``` chỉ set flag khi nó kiểm tra debugger. trả về true nếu debugger attach hệ thống.
Hai hàm này cần quyền administrator

```C
bool IsDebugged()
{
    return NT_SUCCESS(ntdll::NtSetDebugFilterState(0, 0, TRUE));
}
```

# 6. NtYieldExecution() / SwitchToThread()

Cách này không đáng tin lắm vì ó chỉ cho thấy các thread có dặc quyền cao trong tiến trình hiện tại. Tuy nhiên nó có thể trở thành một kĩ năng anti-tracing

Khi đang bị trace bởi 1 debugger bằng step, thì nội dung của nó không thể bị chuyển cho thread khác. nghĩa là ```NtYieldExecution()``` sẽ trả về ```STATUS_NO_YIELD_PERFORMED``` (0x40000024) => ```SwitchToThread()``` trả về 0

Ý tưởng là dùng vòng lặp, thay đổi counter nếu ```SwitchToThread()``` trả về 0, hay ```NtYieldExecution()``` trả về ```STATUS_NO_YIELD_PERFORMED```. Nếu counter cho ra một giá trị biết trước nào đó thì có thể chương trình đang bị debug

```C
bool IsDebugged()
{
    BYTE ucCounter = 1;
    for (int i = 0; i < 8; i++)
    {
        Sleep(0x0F);
        ucCounter <<= (1 - SwitchToThread()); // Nếu switch thread thành công thì trả về 1 => không shift
    }

    return ucCounter == 0;
}
```

# Khắc phục
- ```nop``` các câu lệnh
- Với hàm ```FindWindow()```, chuyển hướng lệnh ```NtUserFindWindowEx()```, trong đoạn chuyển hướng, gọi tới hàm ```NtUserFindWindowEx()```. Nếu nó được goi từ tiến trình bị debug, hay tiến trình cha tronong khả nghi thì trả về False trong lệnh chuyển hướng.
- Với các hàm kiểm tra của tiến trình cha, chuyển hướng ```NtQuerySystemInformation()``` nếu trong ```SystemInformationClassSystemInformationClass``` có một trong các giá trị sau:
    - SystemProcessInformation
    - SystemSessionProcessInformation
    - SystemExtendedProcessInformation
Và tên của tiến trình có vẻ khả nghi, thì trong đoạn chuyển hướng phải thay đổi tên tiến trình

- Với ```DbgPrint```, sử dụng các plugin trong debugger và chuyển hành động với handler sau khi nhận exception ```DBG_PRINTEXCEPTION_C```

- Với ```DbgSetDebugFilterState()```:  chuyển hướng hàm ```NtSetDebugFilterState()```, nếu tiến trình chạy dưới quyền debug, trả về False.

- Với ```SwitchToThread()```: chuyển hướng hàm ```NtSetDebugFilterState()```, nếu tiến trình chạy dưới quyền debug, trả về False.
