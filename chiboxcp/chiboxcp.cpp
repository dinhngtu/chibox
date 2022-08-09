#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <system_error>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    Sleep(5000);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!RevertToSelf()) {
        WriteFile(out, L"cannot revert\n", sizeof(L"cannot revert\n"), nullptr, nullptr);
        ExitProcess(1);
    }
    WriteFile(out, L"hello world\n", sizeof(L"hello world\n"), nullptr, nullptr);
    HANDLE f = CreateFile(L"E:/fuck.txt", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        auto desc = std::string(std::system_error(GetLastError(), std::system_category(), "CreateFile").what());
        auto wdesc = std::wstring(desc.begin(), desc.end());
        WriteFile(out, wdesc.data(), wdesc.size() * sizeof(wchar_t), nullptr, nullptr);
    }
    std::vector<wchar_t> buf(1024);
    DWORD r;
    while (ReadFile(f, buf.data(), buf.size() * sizeof(wchar_t), &r, nullptr) && r) {
        WriteFile(out, buf.data(), r, nullptr, nullptr);
    }
    CloseHandle(f);
    Sleep(30000);
    return 0;
}
