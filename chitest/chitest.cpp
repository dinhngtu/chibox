#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <sddl.h>

#include <cstdlib>
#include <system_error>
#include <vector>
#include <format>
#include <iostream>

int main() {
    // get my token and its token groups

    HANDLE pt;
    if (!OpenProcessToken(
        GetCurrentProcess(),
        //TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_WRITE,
        TOKEN_ALL_ACCESS,
        &pt)) {
        throw std::system_error(GetLastError(), std::system_category(), "OpenProcessToken");
    }

    DWORD tgs = 0;
    if (!GetTokenInformation(pt, TokenGroups, nullptr, 0, &tgs) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
    }
    auto tg = static_cast<PTOKEN_GROUPS>(calloc(1, tgs));
    if (!tg) {
        throw std::bad_alloc();
    }
    if (!GetTokenInformation(pt, TokenGroups, tg, tgs, &tgs)) {
        throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
    }

    // deny non-session enabled groups

    SID_AND_ATTRIBUTES usersSid{};
    DWORD userss = SECURITY_MAX_SID_SIZE;
    usersSid.Sid = calloc(1, userss);
    if (!usersSid.Sid) {
        throw std::bad_alloc();
    }
    if (!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, usersSid.Sid, &userss)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateWellKnownSid");
    }

    std::vector<SID_AND_ATTRIBUTES> deny{};
    for (DWORD i = 0; i < tg->GroupCount; i++) {
        auto& g = tg->Groups[i];
        LPWSTR sid = nullptr;
        if (!ConvertSidToStringSidW(g.Sid, &sid)) {
            throw std::system_error(GetLastError(), std::system_category(), "ConvertSidToStringSidW");
        }
        std::wcout << std::format(L"{} {:#x}", sid, g.Attributes);
        if ((g.Attributes & SE_GROUP_ENABLED) && !(g.Attributes & SE_GROUP_LOGON_ID)) {
            std::wcout << "*\n";
            deny.push_back(g);
        }
        else {
            std::wcout << "\n";
        }
    }

    // create restricted token

    SID_AND_ATTRIBUTES nullSid{};
    DWORD nss = SECURITY_MAX_SID_SIZE;
    nullSid.Sid = calloc(1, nss);
    if (!nullSid.Sid) {
        throw std::bad_alloc();
    }
    if (!CreateWellKnownSid(WinNullSid, nullptr, nullSid.Sid, &nss)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateWellKnownSid");
    }

    HANDLE rt;
    if (!CreateRestrictedToken(
        pt,
        DISABLE_MAX_PRIVILEGE,
        static_cast<DWORD>(deny.size()),
        deny.data(),
        0,
        nullptr,
        0,
        nullptr,
        &rt)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateRestrictedToken");
    }

    // create untrusted label

    TOKEN_MANDATORY_LABEL untrustedLabel{};
    DWORD uss = SECURITY_MAX_SID_SIZE;
    untrustedLabel.Label.Sid = calloc(1, uss);
    if (!untrustedLabel.Label.Sid) {
        throw std::bad_alloc();
    }
    if (!CreateWellKnownSid(WinUntrustedLabelSid, nullptr, untrustedLabel.Label.Sid, &uss)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateWellKnownSid");
    }

    if (!SetTokenInformation(
        rt,
        TokenIntegrityLevel,
        &untrustedLabel,
        sizeof(untrustedLabel))) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation");
    }

    // print group info of restricted token

    {
        std::wcout << "\n\nProcess token:\n";
        DWORD rtgs = 0;
        if (!GetTokenInformation(rt, TokenGroups, nullptr, 0, &rtgs) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }
        auto rtg = static_cast<PTOKEN_GROUPS>(calloc(1, rtgs));
        if (!rtg) {
            throw std::bad_alloc();
        }
        if (!GetTokenInformation(rt, TokenGroups, rtg, rtgs, &rtgs)) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }

        for (DWORD i = 0; i < rtg->GroupCount; i++) {
            auto& g = rtg->Groups[i];
            LPWSTR sid = nullptr;
            if (!ConvertSidToStringSidW(g.Sid, &sid)) {
                throw std::system_error(GetLastError(), std::system_category(), "ConvertSidToStringSidW");
            }
            std::wcout << std::format(L"{} {:#x}\n", sid, g.Attributes);
        }
    }

    // create the "unrestricted" token

    HANDLE ut;
    if (!CreateRestrictedToken(
        pt,
        0,
        0,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &ut)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateRestrictedToken");
    }

    if (!SetTokenInformation(
        ut,
        TokenIntegrityLevel,
        &untrustedLabel,
        sizeof(untrustedLabel))) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation");
    }

    // print

    {
        std::wcout << "\n\nInitial token:\n";
        DWORD utgs = 0;
        if (!GetTokenInformation(ut, TokenGroups, nullptr, 0, &utgs) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }
        auto utg = static_cast<PTOKEN_GROUPS>(calloc(1, utgs));
        if (!utg) {
            throw std::bad_alloc();
        }
        if (!GetTokenInformation(ut, TokenGroups, utg, utgs, &utgs)) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }

        for (DWORD i = 0; i < utg->GroupCount; i++) {
            auto& g = utg->Groups[i];
            LPWSTR sid = nullptr;
            if (!ConvertSidToStringSidW(g.Sid, &sid)) {
                throw std::system_error(GetLastError(), std::system_category(), "ConvertSidToStringSidW");
            }
            std::wcout << std::format(L"{} {:#x}\n", sid, g.Attributes);
        }
    }

    // setup ipc pipe

    PSECURITY_DESCRIPTOR psd;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        //L"O:S-1-5-21-3101083011-792334776-4041739814-1001G:WDD:(A;;GRGW;;;WD)S:(ML;;NRNW;;;S-1-16-0)",
        L"D:(A;;GRGW;;;WD)S:(ML;;NRNW;;;S-1-16-0)",
        SDDL_REVISION,
        &psd,
        nullptr)) {
        throw std::system_error(GetLastError(), std::system_category(), "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    }

    HANDLE mine, yours;
    SECURITY_ATTRIBUTES psa{};
    psa.nLength = sizeof(SECURITY_ATTRIBUTES);
    psa.lpSecurityDescriptor = psd;
    psa.bInheritHandle = TRUE;
    if (!CreatePipe(&mine, &yours, &psa, 0)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreatePipe");
    }

    // spawn

    STARTUPINFO si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = INVALID_HANDLE_VALUE;
    si.hStdOutput = yours;
    si.hStdError = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi{};
    auto cmdline = _wcsdup(L"\"chiboxcp.exe\"");
    if (!CreateProcessAsUserW(
        rt,
        nullptr,
        cmdline,
        nullptr,
        nullptr,
        TRUE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &pi)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreateProcessAsUserW");
    }
    free(cmdline);
    CloseHandle(yours);

    // set child thread to unrestricted token

    HANDLE it;
    if (!DuplicateTokenEx(
        ut,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &it)) {
        throw std::system_error(GetLastError(), std::system_category(), "DuplicateToken");
    }

    if (!SetThreadToken(&pi.hThread, it)) {
        throw std::system_error(GetLastError(), std::system_category(), "SetThreadToken");
    }
    CloseHandle(it);

    // resume and communicate

    if (!ResumeThread(pi.hThread)) {
        throw std::system_error(GetLastError(), std::system_category(), "ResumeThread");
    }

    std::vector<wchar_t> buf(1024, 0);
    DWORD r;
    while (ReadFile(mine, buf.data(), buf.size() * sizeof(wchar_t), &r, nullptr) && r) {
        std::wcout.write(buf.data(), r / sizeof(wchar_t));
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
