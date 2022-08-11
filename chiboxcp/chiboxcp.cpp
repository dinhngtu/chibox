#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <system_error>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <format>
#include <io.h>
#include <fcntl.h>

static void writestr(HANDLE h, const std::wstring& s) {
    /*
    if (!WriteFile(h, s.data(), s.size() * sizeof(wchar_t), nullptr, nullptr)) {
        ExitProcess(99);
    }
    */
    std::wcout << s;
}

static void throwmessage(HANDLE h, const std::string& msg, DWORD errcode = GetLastError(), DWORD exitcode = 1) {
    auto desc = std::string(std::system_error(errcode, std::system_category(), msg).what());
    auto wdesc = std::wstring(desc.begin(), desc.end());
    wdesc += L"\n";
    writestr(h, wdesc);
    //Sleep(INFINITE);
    ExitProcess(exitcode);
}

int main(int argc, char** argv) {
    setlocale(LC_ALL, ".1200");
    _setmode(_fileno(stdout), _O_WTEXT);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    std::wcout << std::unitbuf;

    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy{};
    policy.DisallowWin32kSystemCalls = 1;
    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &policy, sizeof(policy))) {
        throwmessage(out, "SetProcessMitigationPolicy");
    }

    //Sleep(30000);
    if (!RevertToSelf()) {
        throwmessage(out, "RevertToSelf");
    }
    writestr(out, L"hello world\n");
    HANDLE f = CreateFileW(L"E:/fuck.txt", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    writestr(out, std::format(L"out {:#x} f {:#x}\n", reinterpret_cast<size_t>(out), reinterpret_cast<size_t>(f)));
    if (f == INVALID_HANDLE_VALUE) {
        throwmessage(out, "CreateFileW");
    }
    std::vector<wchar_t> buf(1024);
    DWORD r;
    while (ReadFile(f, buf.data(), buf.size() * sizeof(wchar_t), &r, nullptr) && r) {
        if (!WriteFile(out, buf.data(), r, nullptr, nullptr)) {
            throwmessage(out, "WriteFile");
        }
    }
    //Sleep(30000);
    Sleep(INFINITE);
    CloseHandle(f);
    return 0;
}
