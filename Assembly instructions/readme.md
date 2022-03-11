# Lệnh Assembly 

Phát hiện debugger dựa trên cách debugger hành động khi CPU xử lý các câu lệnh

# 1. INT 3

```INT 3``` là mã interupt biểu thị cho ```software breakpoint```, nếu không có debugger thì sẽ gọi exception handle và tạo ```EXCEPTION_BREAKPOINT (0x80000003)```, còn nếu có debugger thì sẽ không gọi đươc ```exception handle```

```C
bool IsDebugged()
{
    __try
    {
        __asm int 3;
        return true;        
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

opcode của ```INT 3```: 0xcc, còn 1 dạng nữa có opcode là CD 03

Khi có ```EXCEPTION_BREAKPOINT```, hệ thống sẽ giảm giá trị của thanh eip đến địa chỉ của opcode 0xcc và trao quyền kiểm soát cho exception handle. 

Trong dạng khác của INT 3, eip trỏ tới phần giữa của lệnh (0x03). Do đó eip có thể bị chuyển đổi bơi ```exception handle``` nếu chúng ta muốn tiếp tục sau lệnh int 3. Nếu không chúng ta có thể bỏ qua việc sửa đổi con trỏ lệnh.

```C
bool g_bDebugged = false;

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}

bool IsDebugged()
{
    __try
    {
        __asm __emit(0xCD);
        __asm __emit(0x03);
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
}
```

# INT 2D
Giống với ```INT 3```, Khi ```INT 2D``` đươc thực thi cũng gọi tới ```EXCEPTION_BREAKPOINT```, nhưng hệ thống kiểm tra thêm thanh eax (1, 3, 4 trên các phiên bản window), nếu chạy trên DBG, thì byte tiếp theo sau INT 2D có thể bị skip => lỗi crash

```C
bool IsDebugged()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;          // Byte tiếp theo bị skip nên nếu chạy trên debugger sẽ crash, nên thay vào lệnh nop vì chúng ta chỉ muốn ktra có chạy bằng debugger nào  không, nếu có, trả về true
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

# 3. ICE

Opcode: 0xF1, có thể phát hiện chương trình có đang bị trace không

Nếu ICE được thực thi, thì ```EXCEPTION_SINGLE_STEP``` (0x80000004) sẽ được tạo

Tuy nhiên nếu chương trình đã bị trace từ trước, thì debugger sẽ coi exception trên như 1 ```exception``` thông thường => không có ```exception handle``` và chương trình sẽ chạy bình thường sau lệnh ```ICE```

```C
bool IsDebugged()
{
    __try
    {
        __asm __emit 0xF1;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

# 4. Thanh ghi Stack Segment

Kĩ thuật này có thể phát hiện chương trình có đang bị trace không bằng cách sử dụng các lệnh:

```nasm
push ss 
pop ss 
pushf
```

Sau khi step vào đây thì [trap flag](https://en.wikipedia.org/wiki/Trap_flag) sẽ được set

```C
bool IsDebugged()
{
    bool bTraced = false;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr [esp+1], 1
        jz movss_not_being_debugged
    }

    bTraced = true;

movss_not_being_debugged:
    // restore stack
    __asm popf;

    return bTraced;
}
```

# 5.Đếm lệnh

Đặt hardware breakpoint theo một trình tự xác định, mỗi lần lệnh tiếp theo được gọi ta tăng exception và tăng bộ đếm, (ở đây là ```eax```)
Cuối cùng so sánh với độ dài của trình tự đã dã định trước, nếu khác => debugger

```C
#include "hwbrk.h"

static LONG WINAPI InstructionCountingExeptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        pExceptionInfo->ContextRecord->Eax += 1;
        pExceptionInfo->ContextRecord->Eip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(naked) DWORD WINAPI InstructionCountingFunc(LPVOID lpThreadParameter)
{
    __asm
    {
        xor eax, eax
        nop
        nop
        nop
        nop
        cmp al, 4
        jne being_debugged
    }

    ExitThread(FALSE);

being_debugged:
    ExitThread(TRUE);
}

bool IsDebugged()
{
    PVOID hVeh = nullptr;
    HANDLE hThread = nullptr;
    bool bDebugged = false;

    __try
    {
        hVeh = AddVectoredExceptionHandler(TRUE, InstructionCountingExeptionHandler);
        if (!hVeh)
            __leave;

        hThread = CreateThread(0, 0, InstructionCountingFunc, NULL, CREATE_SUSPENDED, 0);
        if (!hThread)
            __leave;

        PVOID pThreadAddr = &InstructionCountingFunc;
        // Fix thread entry address if it is a JMP stub (E9 XX XX XX XX)
        if (*(PBYTE)pThreadAddr == 0xE9)
            pThreadAddr = (PVOID)((DWORD)pThreadAddr + 5 + *(PDWORD)((PBYTE)pThreadAddr + 1));

        for (auto i = 0; i < m_nInstructionCount; i++)
            m_hHwBps[i] = SetHardwareBreakpoint(
                hThread, HWBRK_TYPE_CODE, HWBRK_SIZE_1, (PVOID)((DWORD)pThreadAddr + 2 + i));

        ResumeThread(hThread);
        WaitForSingleObject(hThread, INFINITE);

        DWORD dwThreadExitCode;
        if (TRUE == GetExitCodeThread(hThread, &dwThreadExitCode))
            bDebugged = (TRUE == dwThreadExitCode);
    }
    __finally
    {
        if (hThread)
            CloseHandle(hThread);

        for (int i = 0; i < 4; i++)
        {
            if (m_hHwBps[i])
                RemoveHardwareBreakpoint(m_hHwBps[i]);
        }

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);
    }

    return bDebugged;
}
```

# 6. POPF và Trap Flag

một kĩ thuật khác để phát hiện chương trình có đang bị trace không

nếu ```Trap Flag``` được set, thì exception ```SINGLE_STEP``` cũng được tạo ra theo.
Tuy nhiên nếu chạy bằng debugger thì ```Trap Flag``` sẽ bị xóa và sẽ không có exception

```C
bool IsDebugged()
{
    __try
    {
        __asm
        {
            pushfd
            mov dword ptr [esp], 0x100
            popfd
            nop
        }
        return true;
    }
    __except(GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}
```

# 7. Tiền tố của lệnh

Chỉ có tác dụng với 1 số debugger.

Nếu chúng ta step từng dòng code trong Olly, sau khi vào byte (0xF3), chúng ta sẽ nhảy đến cuối khối ```try``` ngay lập tức

Còn nếu không chạy bằng debugger nào thì chúng ta sẽ đến exception

```C
bool IsDebugged()
{
    __try
    {
        // 0xF3 0x64 disassembles as PREFIX REP:
        __asm __emit 0xF3
        __asm __emit 0x64
        // One byte INT 1
        __asm __emit 0xF1
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```

# Khắc phục
- patch chương trình bằng lệnh ```nop```
- nếu không muốn patch, có thể đặt bp trong các đoạn code theo dòng check này và chạy đến khi gặp breakpoint
