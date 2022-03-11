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

(Giải thích: hàm ```IsDebbugerPreset()``` trả về giá trị khác 0 nếu tiến trình đang bị debug, nếu tiến trình đó đang được debug thì al sẽ nhận giá trị != 0 do đó hệ thống sẽ jump đến ```being_debugged``` và kết thúc chương trình)

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
Đối với ```IsDebuggerPresent ()```: Đặt cờ BeingDebugged của Process Environment Block (PEB) thành 0
Đối với ```CheckRemoteDebuggerPresent ()``` và ```NtQueryInformationProcess ()```:
  - Khi ```CheckRemoteDebuggerPresent ()``` gọi ```NtQueryInformationProcess ()```, cách duy nhất là nối ```NtQueryInformationProcess ()``` và đặt các giá trị sau trong bộ đệm trả về:
  
      - 0 (hoặc bất kỳ giá trị nào ngoại trừ -1) trong trường hợp truy vấn ```ProcessDebugPort```.
          
      - Giá trị khác 0 trong trường hợp truy vấn ```ProcessDebugFlags```.
           
       - 0 trong trường hợp truy vấn ```ProcessDebugObjectHandle```.
  - Cách duy nhất để giảm thiểu những kiểm tra này với các hàm ```RtlQueryProcessHeapInformation ()```, ```RtlQueryProcessDebugInformation ()``` và ```NtQuerySystemInformation ()``` là nối chúng và sửa đổi các giá trị trả về:
 
       - ```RTL_PROCESS_HEAPS :: HeapInformation :: Heaps [0]``` :: Gắn cờ cho ```HEAP_GROWABLE``` cho
```RtlQueryProcessHeapInformation ()``` và ```RtlQueryProcessDebugInformation ()```.

       - SYSTEM_KERNEL_DEBUGGER_INFORMATION :: DebuggerEnabled thành 0 và SYSTEM_KERNEL_DEBUGGER_INFORMATION :: DebuggerNotPresent thành 1 cho hàm NtQuerySystemInformation () trong trường hợp truy vấn SystemKernelDebuggerInformation.
       
       
# 2. <ins>Kiểm tra thủ công</ins>

Cách tiếp cận này được sử dụng để phát hiện cờ debug trong cấu trúc hệ thống. có thể kiểm tra bộ nhớ của tiến trình thủ công mà không cần đến các hàm API

# 2.1. Cờ PEB!BeingDebugged
phương pháp này là một cách khác để kiểm tra cờ ```beingDebugged``` của PEB mà không cần gọi tới hàm ```IsDebuggerPresent()```

asm 32 bit:
```nasm
mov eax, fs:[30h]
cmp byte ptr [eax+2], 0              ; nếu trả về != 0 => đang bị debug
jne being_debugged
```

asm 64 bit:
```nasm
mov rax, gs:[60h]
cmp byte ptr [rax+2], 0
jne being_debugged
```

WOW64:
```nasm
mov eax, fs:[30h]
cmp byte ptr [eax+1002h], 0
```

C/C++:
```C
#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif // _WIN64
 
if (pPeb->BeingDebugged)
    goto being_debugged;
```

# 2.2. NtGlobalFlag

Trường NtGlobalFlag của khối PEB (offset 0x68 trên 32bit và 0xBC trên 64 bit) mặc định là 0. Việc bị attach bởi 1 trình debugger thì giá trị NtGlobalFlag không thay đổi. Nhưng nếu tiến trình đó được tạo vởi Debugger thì các cờ sau sẽ được set: 

- ```FLG_HEAP_ENABLE_TAIL_CHECK (0x10)```

- ```FLG_HEAP_ENABLE_FREE_CHECK (0x20)```

-``` FLG_HEAP_VALIDATE_PARAMETERS (0x40)```

Sự hiện diện của trình gỡ lỗi có thể được phát hiện bằng cách kiểm tra sự kết hợp của các cờ đó.

asm 32 bit:
```nasm
mov eax, fs:[30h]
mov al, [eax+68h]        ; 3 cờ này đươc set nếu debug tạo tiến trình, kiểm tra tổng với 0x70, nếu bằng thì nghĩa là tiến trình vừa đươc debugger tạo 
and al, 70h
cmp al, 70h
jz  being_debugged
```

asm 64 bit:
```nasm
mov rax, gs:[60h]
mov al, [rax+BCh]
and al, 70h
cmp al, 70h
jz  being_debugged
```

WOW64:
```nasm
mov eax, fs:[30h]
mov al, [eax+10BCh]
and al, 70h
cmp al, 70h
jz  being_debugged
```

C/C++:
```C
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#endif // _WIN64
 
if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
    goto being_debugged;
```

# 2.3. Heap Flags
Heap chứa hai trường bị ảnh hưởng bởi sự hiện diện của debugger. Chính xác cách chúng bị ảnh hưởng phụ thuộc vào phiên bản Windows. Các trường này là Flags và ForceFlags.

Khi có Debugger, trường cờ sẽ là sự kết hợp của các trường trên WinNY, Win2000 và WinXP 32bit:

- HEAP_GROWABLE (2)
 
- HEAP_TAIL_CHECKING_ENABLED (0x20)

- HEAP_FREE_CHECKING_ENABLED (0x40)

- HEAP_SKIP_VALIDATION_CHECKS (0x10000000)

- HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

Với WinXP 64 bit (có cái này à? @@) hay WinVista hoặc cao hơn, nếu có debugger, trường cờ sẽ được đặt bằng sự kết hợp của các cờ sau 

- HEAP_GROWABLE (2)

- HEAP_TAIL_CHECKING_ENABLED (0x20)

- HEAP_FREE_CHECKING_ENABLED (0x40)

- HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

Khi có Debugger, trường ForceFlags sẽ gồm:

- HEAP_TAIL_CHECKING_ENABLED (0x20)

- HEAP_FREE_CHECKING_ENABLED (0x40)

- HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

Code C:
```C
bool Check()
{
#ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    PVOID pHeapBase = !m_bIsWow64
        ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
        : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
    DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x40
        : 0x0C;
    DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x44 
        : 0x10;
#else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
    DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x70 
        : 0x14;
    DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x74 
        : 0x18;
#endif // _WIN64

    PDWORD pdwHeapFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    PDWORD pdwHeapForceFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);
    return (*pdwHeapFlags & ~HEAP_GROWABLE) || (*pdwHeapForceFlags != 0);
```

# 2.3. Bảo vệ Heap

Nếu cờ HEAP_TAIL_CHECKING_ENABLED được đặt trong NtGlobalFlag, chuỗi 0xABABABAB sẽ được nối thêm (hai lần trong 32-Bit và 4 lần trong Windows 64-Bit) ở cuối khối heap được phân bổ.

Nếu cờ HEAP_FREE_CHECKING_ENABLED được đặt trong NtGlobalFlag, chuỗi 0xFEEEFEEE sẽ được thêm vào nếu cần thêm byte để lấp đầy khoảng trống cho đến khối bộ nhớ tiếp theo.

Code C:
```C
bool Check()
{
    PROCESS_HEAP_ENTRY HeapEntry = { 0 };
    do
    {
        if (!HeapWalk(GetProcessHeap(), &HeapEntry))
            return false;
    } while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

    PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
    return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}
```

# Cách khắc phục:

Với cờ ```PEB!BeingDebugged```: Đặt cờ ```BeingDebugged``` thành 0. Điều này có thể được thực hiện bằng cách DLLINJECTION.

```C 
#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif // _WIN64
pPeb->BeingDebugged = 0;
```

Với ```NtGlobalFlag```:  Đặt cờ ```NtGlobalFlag``` thành 0. Điều này có thể được thực hiện bằng cách DLLINJECTION.
```C
#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
*(PDWORD)((PBYTE)pPeb + 0x68) = 0;
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
*(PDWORD)((PBYTE)pPeb + 0xBC); = 0;
#endif // _WIN64
```

Với cờ Heap: 
Đặt giá trị Flags thành HEAP_GROWABLE và giá trị ForceFlags thành 0. Điều này có thể được thực hiện bằng cách DLLINJECTION.

```C
#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
PVOID pHeapBase = !m_bIsWow64
    ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
    : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x40
    : 0x0C;
DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x44 
    : 0x10;
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x70 
    : 0x14;
DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x74 
    : 0x18;
#endif // _WIN64

*(PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset) = HEAP_GROWABLE;
*(PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset) = 0;
```

Với bảo vệ Heap:

Vá lại 12 bit trong hệ thống chạy 32 bit sau heap
       20 bit trong hệ thống chạy 64 bit sau heap
Chuyển hướng kernel32! HeapAlloc() và vá heap


Một VD về DebugFlag: [link](https://hutaobestgirl.wordpress.com/2022/03/07/anti-debug-one-for-all/)

