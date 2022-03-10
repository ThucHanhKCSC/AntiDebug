# DEBUG FLAG

![svg](https://user-images.githubusercontent.com/101321172/157626299-b462065b-7290-4de7-a22c-247f4b4bb74f.svg)

Là một cờ trong bảng hệ thống, lưu trữ dữ liệu của tiến trình và được hệ điều hành đặt, có thể dùng để phát hiện một tiến trình đang chạy trên một phần mềm debug nào đó. Các trạng thái có thể được xác mình thông qua các hàm API hay kiểm tra trong bảng hệ thống

## Sử dụng winAPI
Sử dụng các hàm trong thư viện WinAPI hay NativeAPI có thể kiểm tra được cấu trúc của hệ thống trong dữ liệu của tiến trình để xác định tiến trình có đang chạy trên một debugger nào không

# IsDebuggerPresent()
