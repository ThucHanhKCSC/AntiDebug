# Timing

![download](https://user-images.githubusercontent.com/101321172/157797793-7f6bddf3-08b1-443c-afe6-65a15b86accd.svg)


So sánh thời gian chạy hàm trong chương trình giữa việc debug, không debug thì sẽ có khác biệt lớn, ví dụ hàm ktra mật khẩu của user có 100 lệnh asm thì mất khoảng 100 mils để chạy, nhưng khi debug thì sẽ mất nhiều hơn nhiều => Kiểm tra thời gian chạy hàm/ chạy chương trình để antiDebug

# 1. RDPMC/RDTSC (Read Performance Monitoring Counter/Read Time-Stamp Counter)

- Read Performance Monitoring Counter: 

```C
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
```

# 2. GetLocalTime() trả về cho parameter giá trị thời gian hiện tại
```C
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... some work
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```

# 3.3. GetSystemTime(): trả về cho parameter thời gian trong hệ thống.
```C
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetSystemTime(&stStart);
    // ... some work
    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```

# 4. GetTickCount() trả về số mili giây mà chương trình dùng để chạy
(Có thể khác nay tùy theo cấu hình máy)

```
bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = GetTickCount();
    // ... some work
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}
```

# 5. ZwGetTickCount() / KiGetTickCount()

tương tự như GetTickCount()

```C
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        int  2ah
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        int  2ah
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
```

# 6.QueryPerformanceCounter(): trả về thời gian chạy trong hàm

```C
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... some work
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}

# 7. timeGetTime() : trả về system time theo mili giây

```C
bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = timeGetTime();
    // ... some work
    return (timeGetTime() - dwStart) > dwNativeElapsed;
}
```


Khắc phục:
- Khi đang debug: thấy -> nop
- Các hàm thường sẽ kiểm tra thời gian >= thời gian cho phép => chuyển lệnh jump

VD: [link](https://hutaobestgirl.wordpress.com/2022/03/07/anti-debug-one-for-all/)

