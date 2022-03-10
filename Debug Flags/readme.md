# DEBUG FLAG

![svg](https://user-images.githubusercontent.com/101321172/157626299-b462065b-7290-4de7-a22c-247f4b4bb74f.svg)

Là một cờ trong bảng hệ thống, lưu trữ dữ liệu của tiến trình và được hệ điều hành đặt, có thể dùng để phát hiện một tiến trình đang chạy trên một phần mềm debug nào đó. Các trạng thái có thể được xác mình thông qua các hàm API hay kiểm tra trong bảng hệ thống

# 1. <ins>Sử dụng winAPI</ins>
Sử dụng các hàm trong thư viện WinAPI hay NativeAPI có thể kiểm tra được cấu trúc của hệ thống trong dữ liệu của tiến trình để xác định tiến trình có đang chạy trên một debugger nào không

# 1.1 IsDebuggerPresent()
Hàm ```IsDebuggerPresent()``` có thể phát hiện tiến trình thực hiện lời gọi có đang bị debug bằng các Debugger người dùng như OllyDBG, x64dbg, thông thường thì nó kiểm tra cờ BeingDebugged của phần [Process Envirement Block](https://www.nirsoft.net/kernel_struct/vista/PEB.html) (PEB).</br>
Mã ASM:
```nasm
    call IsDebuggerPresent    
    test al, al
    jne  being_debugged
    ...
being_debugged:
    push 1
    call ExitProcess
```

(Giải thích: hàm ```IsDebbugerPreset``` trả về giá trị khác 0 nếu tiến trình đang bị debug, nếu tiến trình đó đang được debug thì al sẽ nhận giá trị != 0 do đó hệ thống sẽ jump đến being_debugged và kết thúc chương trình)

Trong C:

```C
if (IsDebuggerPresent())
    ExitProcess(-1);
````
# 1.2 CheckRemoteDebuggerPresent()

Hàm ```CheckRemoteDebuggerPresent()``` kiểm tra debugger (từ một tiến trình khác trong hệ thống) có đang tác động vào tiến trình hiện tại không (trả về TRUE hoặc FALSE, nếu TRUE thì nghĩa là đang bị debug)

(hàm CheckRemoteDebuggerPresent() nhận 2 parameter là handle của tiến trình và con trỏ kiểu bool pbDebuggerPresent)

Code ASM:
```nasm
    lea eax, [bDebuggerPresent]                       ; con trỏ kiểu bool
    
    push eax                                          ;
    push -1       ; GetCurrentProcess()               ; truyền 2 parameter vào hàm
    call CheckRemoteDebuggerPresent                   ; 
    
    cmp [bDebuggerPresent], 1                         ; kiểm tra với 1 (là TRUE)
    
    jz being_debugged                                 ; Nếu giá trị trả về == 1=> đang bị debug
    ...
being_debugged:
    push -1
    call ExitProcess
```

Code C:
```C
BOOL bDebuggerPresent;
if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && TRUE == bDebuggerPresent)
    ExitProcess(-1);
```

# 1.3. NtQueryInformationProcess()
Hàm ```NtQueryInformationProcess()``` có thể truy xuát nhiều loại thông tin khác nhau trong tiến trình. Nó chấp nhận parameter ProcessInformationClass, là thứ xác định loại thông tin bạn muốn có và định nghĩa lại đầu ra của ProcessInformation

# 1.3.1 ProcessDebugPort 
Có thể truy xuất giá trị cổng của debugger đang chạy trên tiến trình bằng cách sử dụng NtQueryInformationProcess(). [ProcessDebugPort](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#PROCESSDEBUGPORT) trả về giá trị DWORD = 0xFFFFFFFF (= -1) nếu tiến trình hiện tại đang bị debug
code C:
```C
typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");
    
    if (pfnNtQueryInformationProcess)
    {
        DWORD dwProcessDebugPort, dwReturned;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &dwProcessDebugPort,
            sizeof(DWORD),
            &dwReturned);

        if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
            ExitProcess(-1);
    }
}
```
```nasm
    lea eax, [dwReturned]         
    push eax ; ReturnLength                       ;
    push 4   ; ProcessInformationLength           ; kích cỡ của phần bộ nhớ đệm, đây dùng 4 byte thể hiện cho sizeof(DWORD)
    lea ecx, [dwProcessDebugPort]
    push ecx ; ProcessInformation                 ; truyền 5 parameter để gọi hàm NtQueryInformationProcess
    push 7   ; ProcessInformationClass            ; 7 là ProcessDebugPort
    push -1  ; ProcessHandle                      ;
    call NtQueryInformationProcess
    
    inc dword ptr [dwProcessDebugPort]            ; hàm sẽ trả về cho [dwProcessDebugPort] giá trị == -1 nếu đang bị debug, do đó +1 vào giá trị đó. Nếu == 0 => Đang bị debug
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess 
```

# 1.3.2 ProcessDebugFlags

Một cấu trúc trong phần kernel là [EPROCESS](https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html) đại diện cho đối tượng tiến tình. Nó có bao gồm vùng NoDebugInherit, giá trị nghịch đảo của vùng này có thể được truy xuất bằng cách sử dụng lớp ```ProcessDebugFlags (0x1f)```. Do đó, nếu trả về 0 thì nghĩa là đang bị debug.
code C:
```C
typedef NTSTATUS(NTAPI *TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwProcessDebugFlags, dwReturned;
        const DWORD ProcessDebugFlags = 0x1f;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &dwProcessDebugFlags,
            sizeof(DWORD),
            &dwReturned);

        if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
            ExitProcess(-1);
    }
}
```

ASM
```nasm
    lea eax, [dwReturned]
    push eax ; ReturnLength
    push 4   ; ProcessInformationLength     ;sizeof(DWORD)
    lea ecx, [dwProcessDebugPort]
    push ecx ; ProcessInformation
    push 1Fh ; ProcessInformationClass 
    push -1  ; ProcessHandle   
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], 0   ;gọi hàm, sau đó so sánh giá trị trả về trong [dwProcessDebugPort], nếu == 0 => đang bị debug
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess
```

# 1.3.3. ProcessDebugObjectHandle

Khi một tiến trình bắt đầu bị debug, một đối tượng kernel là "đối tượng debug" sẽ được gọi. Có thể truy xuất giá trị của xử lý này bằng cách sử dụng lớp ProcessDebugObjectHandle (0x1e).

Code C:
```C
typedef NTSTATUS(NTAPI * TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwReturned;
        HANDLE hProcessDebugObject = 0;
        const DWORD ProcessDebugObjectHandle = 0x1e;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &hProcessDebugObject,
            sizeof(HANDLE),
            &dwReturned);

        if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
            ExitProcess(-1);
    }
}
```

```nasm
    lea eax, [dwReturned]
    push eax ; ReturnLength
    push 4   ; ProcessInformationLength
    lea ecx, [hProcessDebugObject]
    push ecx ; ProcessInformation
    push 1Eh ; ProcessInformationClass
    push -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [hProcessDebugObject], 0
    jnz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess
```

# 1.4. tlQueryProcessHeapInformation()
Hàm ```tlQueryProcessHeapInformation()``` có thể đọc cờ heap của dữ liệu tiến trình trong tiến tình hiện tại

code C:
```C
bool Check()
{
    ntdll::PDEBUG_BUFFER pDebugBuffer = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
    if (!SUCCEEDED(ntdll::RtlQueryProcessHeapInformation((ntdll::PRTL_DEBUG_INFORMATION)pDebugBuffer)))
        return false;

    ULONG dwFlags = ((ntdll::PRTL_PROCESS_HEAPS)pDebugBuffer->HeapInformation)->Heaps[0].Flags;
    return dwFlags & ~HEAP_GROWABLE;
}
```

# 1.5. RtlQueryProcessDebugInformation
Hàm ```RtlQueryProcessDebugInformation()``` có thể được sử dụng để đọc một phần nào đó trong dữ liệu của tiến trình, bao gồm cả phần heap flag

code C:
```C
bool Check()
{
    ntdll::PDEBUG_BUFFER pDebugBuffer = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
    if (!SUCCEEDED(ntdll::RtlQueryProcessDebugInformation(GetCurrentProcessId(), ntdll::PDI_HEAPS | ntdll::PDI_HEAP_BLOCKS, pDebugBuffer)))
        return false;

    ULONG dwFlags = ((ntdll::PRTL_PROCESS_HEAPS)pDebugBuffer->HeapInformation)->Heaps[0].Flags;
    return dwFlags & ~HEAP_GROWABLE;
}
```

# 1.6. NtQuerySystemInformation()
hàm ```NtQuerySystemInformation()``` có tham số (parameter) là lớp thông tin cần truy vấn. Hầu hết các lớp không được ghi lại. Các lớp đó bao gồm ```SystemKernelDebuggerInformation (0x23)``` SystemKernelDebuggerInformation trả về giá trị của hai cờ: KdDebuggerEnabled trong al và KdDebuggerNotPresent trong ah. Do đó, giá trị trả về trong ah bằng 0 nếu có debugger.

Code C
```C
enum { SystemKernelDebuggerInformation = 0x23 };

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { 
    BOOLEAN DebuggerEnabled; 
    BOOLEAN DebuggerNotPresent; 
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION; 

bool Check()
{
    NTSTATUS status;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;
    
    status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
        &SystemInfo,
        sizeof(SystemInfo),
        NULL);

    return SUCCEEDED(status)
        ? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
        : false;
}
```

# Cách khắc phục:
Đối với IsDebuggerPresent (): Đặt cờ BeingDebugged của Process Environment Block (PEB) thành 0
Đối với CheckRemoteDebuggerPresent () và NtQueryInformationProcess ():
  - Khi CheckRemoteDebuggerPresent () gọi NtQueryInformationProcess (), cách duy nhất là nối NtQueryInformationProcess () và đặt các giá trị sau trong bộ đệm trả về:
           - 0 (hoặc bất kỳ giá trị nào ngoại trừ -1) trong trường hợp truy vấn ProcessDebugPort.
           - Giá trị khác 0 trong trường hợp truy vấn ProcessDebugFlags.
           - 0 trong trường hợp truy vấn ProcessDebugObjectHandle.
  - Cách duy nhất để giảm thiểu những kiểm tra này với các hàm RtlQueryProcessHeapInformation (), RtlQueryProcessDebugInformation () và NtQuerySystemInformation () là nối chúng và sửa đổi các giá trị trả về:
           - RTL_PROCESS_HEAPS :: HeapInformation :: Heaps [0] :: Gắn cờ cho HEAP_GROWABLE cho
RtlQueryProcessHeapInformation () và RtlQueryProcessDebugInformation ().
           - SYSTEM_KERNEL_DEBUGGER_INFORMATION :: DebuggerEnabled thành 0 và SYSTEM_KERNEL_DEBUGGER_INFORMATION :: DebuggerNotPresent thành 1 cho hàm NtQuerySystemInformation () trong trường hợp truy vấn SystemKernelDebuggerInformation.


