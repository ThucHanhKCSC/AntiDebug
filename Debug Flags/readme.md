# DEBUG FLAG

![svg](https://user-images.githubusercontent.com/101321172/157626299-b462065b-7290-4de7-a22c-247f4b4bb74f.svg)

Là một cờ trong bảng hệ thống, lưu trữ dữ liệu của tiến trình và được hệ điều hành đặt, có thể dùng để phát hiện một tiến trình đang chạy trên một phần mềm debug nào đó. Các trạng thái có thể được xác mình thông qua các hàm API hay kiểm tra trong bảng hệ thống

# <ins>Sử dụng winAPI</ins>
Sử dụng các hàm trong thư viện WinAPI hay NativeAPI có thể kiểm tra được cấu trúc của hệ thống trong dữ liệu của tiến trình để xác định tiến trình có đang chạy trên một debugger nào không

# IsDebuggerPresent()
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
# CheckRemoteDebuggerPresent()

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

# NtQueryInformationProcess()
Hàm ```NtQueryInformationProcess()``` có thể truy xuát nhiều loại thông tin khác nhau trong tiến trình. Nó chấp nhận parameter ProcessInformationClass, là thứ xác định loại thông tin bạn muốn có và định nghĩa lại đầu ra của ProcessInformation

# ProcessDebugPort 
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
    
    inc dword ptr [dwProcessDebugPort]
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess 
```
(Giải thích:  )
