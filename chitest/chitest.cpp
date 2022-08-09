#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <sddl.h>
#include <atlsecurity.h>

#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <vector>
#include <format>
#include <iostream>

static void PrintToken(const CAccessToken& token) {
    CTokenGroups tg{};
    if (!token.GetGroups(&tg)) {
        throw std::system_error(GetLastError(), std::system_category(), "token.GetGroups");
    }
    CSid::CSidArray sids;
    CAcl::CAccessMaskArray attributes;
    tg.GetSidsAndAttributes(&sids, &attributes);
    for (DWORD i = 0; i < tg.GetCount(); i++) {
        std::wcout << std::format(L"{} {:#x}\n", sids[i].Sid(), attributes[i]);
    }
    CTokenPrivileges privs{};
    if (!token.GetPrivileges(&privs)) {
        throw std::system_error(GetLastError(), std::system_category(), "token.GetPrivileges");
    }
    CTokenPrivileges::CNames privNames{};
    privs.GetNamesAndAttributes(&privNames);
    std::wcout << "Privs: ";
    for (size_t i = 0; i < privNames.GetCount(); i++) {
        std::wcout << privNames[i].GetString() << " ";
    }
    std::wcout << "\n\n";
}

int main() {
    // get my token and its token groups
    CAccessToken myToken{};
    //TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_WRITE,
    if (!myToken.GetProcessToken(TOKEN_ALL_ACCESS)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.GetProcessToken");
    }

    std::wcout << L"myToken:\n";
    PrintToken(myToken);

    // deny non-session enabled groups and privs
    CTokenGroups myGroups{};
    if (!myToken.GetGroups(&myGroups)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.GetGroups");
    }
    CTokenGroups deny{};
    {
        CSid::CSidArray sids;
        CAcl::CAccessMaskArray attributes;
        myGroups.GetSidsAndAttributes(&sids, &attributes);
        for (DWORD i = 0; i < myGroups.GetCount(); i++) {
            if ((attributes[i] & SE_GROUP_ENABLED) && !(attributes[i] & SE_GROUP_LOGON_ID)) {
                deny.Add(sids[i], attributes[i]);
            }
        }
    }
    CTokenPrivileges denyPrivs{};
    myToken.GetPrivileges(&denyPrivs);

    CAccessToken lockdownToken{};
    if (!myToken.CreateRestrictedToken(&lockdownToken, deny, CTokenGroups{}, denyPrivs)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.CreateRestrictedToken lockdownToken");
    }

    // set lockdown token as untrusted
    CTokenGroups _untrusted;
    {
        CSid untrustedSid{ SID_IDENTIFIER_AUTHORITY SECURITY_MANDATORY_LABEL_AUTHORITY, 1, SECURITY_MANDATORY_UNTRUSTED_RID };
        _untrusted.Add(untrustedSid, 0);
    }
    TOKEN_MANDATORY_LABEL untrustedLabel{ _untrusted.GetPTOKEN_GROUPS()->Groups[0] };
    if (!SetTokenInformation(
        lockdownToken.GetHandle(),
        TokenIntegrityLevel,
        &untrustedLabel,
        sizeof(untrustedLabel))) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation lockdownToken");
    }

    std::wcout << L"lockdownToken:\n";
    PrintToken(lockdownToken);

    // create the initial token

    CAccessToken initialToken{};
    if (!myToken.CreateRestrictedToken(&initialToken, CTokenGroups{}, CTokenGroups{}, denyPrivs)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.CreateRestrictedToken initialToken");
    }
    if (!SetTokenInformation(
        initialToken.GetHandle(),
        TokenIntegrityLevel,
        &untrustedLabel,
        sizeof(untrustedLabel))) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation initialToken");
    }

    std::wcout << L"initialToken:\n";
    PrintToken(initialToken);

    // setup ipc pipe
    HANDLE _mine, _yours;
    CSecurityAttributes pipeAttr{};
    {
        CSecurityDesc pipeDesc{};
        if (!pipeDesc.FromString(L"D:(A;;GRGW;;;WD)S:(ML;;NRNW;;;S-1-16-0)")) {
            throw std::system_error(GetLastError(), std::system_category(), "pipeDesc.FromString");
        }
        pipeDesc.MakeSelfRelative();
        pipeAttr.Set(pipeDesc, true);
    }
    if (!CreatePipe(&_mine, &_yours, &pipeAttr, 0)) {
        throw std::system_error(GetLastError(), std::system_category(), "CreatePipe");
    }
    CHandle mine(_mine), yours(_yours);

    // spawn
    CHandle hProcess{}, hThread{};
    {
        LPVOID eb;
        if (!CreateEnvironmentBlock(&eb, nullptr, FALSE)) {
            throw std::system_error(GetLastError(), std::system_category(), "CreateEnvironmentBlock");
        }
        STARTUPINFO si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = INVALID_HANDLE_VALUE;
        si.hStdOutput = yours;
        si.hStdError = INVALID_HANDLE_VALUE;
        PROCESS_INFORMATION pi{};
        std::wstring cmdline(L"\"chiboxcp.exe\"");
        // we make our own env block so we need to use CPAU manually
        if (!CreateProcessAsUserW(
            lockdownToken.Detach(),
            nullptr,
            cmdline.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            eb,
            nullptr,
            &si,
            &pi)) {
            throw std::system_error(GetLastError(), std::system_category(), "lockdownToken.CreateProcessAsUserW");
        }
        DestroyEnvironmentBlock(eb);
        yours.Close();
        if (!pi.hProcess || !pi.hThread) {
            throw std::runtime_error("invalid process info handles");
        }
        hProcess.Attach(pi.hProcess);
        hThread.Attach(pi.hThread);
    }

    CAccessToken threadToken{};
    initialToken.CreateImpersonationToken(&threadToken);
    if (!threadToken.Impersonate(hThread)) {
        throw std::system_error(GetLastError(), std::system_category(), "initialToken.Impersonate");
    }

    // resume and communicate

    if (!ResumeThread(hThread)) {
        throw std::system_error(GetLastError(), std::system_category(), "ResumeThread");
    }

    std::vector<wchar_t> buf(1024, 0);
    DWORD r;
    while (ReadFile(mine, buf.data(), buf.size() * sizeof(wchar_t), &r, nullptr) && r) {
        std::wcout.write(buf.data(), r / sizeof(wchar_t));
    }
    WaitForSingleObject(hProcess, INFINITE);
    return 0;
}
