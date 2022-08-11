#include "stdafx.h"
#include "secutil.h"

static const chibox::TokenMandatoryLabel UntrustedLabel(MandatoryLevelUntrusted), LowLabel(MandatoryLevelLow);

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
    std::wcout << "\n";
    if (token.IsTokenRestricted()) {
        std::wcout << "Restricted:\n";
        DWORD rtgs;
        if (!GetTokenInformation(
            token.GetHandle(),
            TokenRestrictedSids,
            nullptr,
            0,
            &rtgs) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }
        auto rtg = static_cast<PTOKEN_GROUPS>(calloc(1, rtgs));
        if (!rtg) {
            throw std::bad_alloc{};
        }
        if (!GetTokenInformation(
            token.GetHandle(),
            TokenRestrictedSids,
            rtg,
            rtgs,
            &rtgs)) {
            throw std::system_error(GetLastError(), std::system_category(), "GetTokenInformation");
        }
        for (size_t i = 0; i < rtg->GroupCount; i++) {
            std::wcout << std::format(L"{} {:#x}\n", CSid(static_cast<SID*>(rtg->Groups[i].Sid)).Sid(), rtg->Groups[i].Attributes);
        }
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

    CSid myUserSid{};
    myToken.GetUser(&myUserSid);

    // deny non-session enabled groups and privs
    CTokenGroups myGroups{};
    if (!myToken.GetGroups(&myGroups)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.GetGroups");
    }
    CTokenGroups deny{};
    CSid myLogonSid{};
    {
        CSid::CSidArray sids;
        CAcl::CAccessMaskArray attributes;
        myGroups.GetSidsAndAttributes(&sids, &attributes);
        for (DWORD i = 0; i < myGroups.GetCount(); i++) {
            if (!(attributes[i] & SE_GROUP_ENABLED)) {
                continue;
            }
            if (attributes[i] & SE_GROUP_LOGON_ID) {
                myLogonSid = sids[i];
            }
            else {
                deny.Add(sids[i], attributes[i]);
            }
        }
    }
    if (!myLogonSid.IsValid()) {
        throw std::runtime_error("cannot find logon session sid");
    }
    CTokenPrivileges denyPrivs{};
    myToken.GetPrivileges(&denyPrivs);

    CTokenGroups restricts{};
    restricts.Add(Sids::Null(), 0);

    CAccessToken lockdownToken{};
    if (!myToken.CreateRestrictedToken(&lockdownToken, deny, restricts, denyPrivs)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.CreateRestrictedToken lockdownToken");
    }

    // set lockdown token as untrusted
    if (!UntrustedLabel.assign(lockdownToken)) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation lockdownToken");
    }

    std::wcout << L"lockdownToken:\n";
    PrintToken(lockdownToken);

    // create the initial token

    CTokenGroups initialRestricts{};
    //initialRestricts.Add(Sids::Users(), 0);
    initialRestricts.Add(Sids::World(), 0);
    //initialRestricts.Add(Sids::Interactive(), 0);
    //initialRestricts.Add(Sids::AuthenticatedUser(), 0);
    initialRestricts.Add(Sids::RestrictedCode(), 0);
    //initialRestricts.Add(myUserSid, 0);
    //initialRestricts.Add(myLogonSid, 0);

    CAccessToken initialToken{};
    if (!myToken.CreateRestrictedToken(&initialToken, CTokenGroups{}, initialRestricts, denyPrivs)) {
        throw std::system_error(GetLastError(), std::system_category(), "myToken.CreateRestrictedToken initialToken");
    }
    if (!UntrustedLabel.assign(initialToken)) {
        throw std::system_error(GetLastError(), std::system_category(), "SetTokenInformation initialToken");
    }

    std::wcout << L"initialToken:\n";
    PrintToken(initialToken);

    // setup ipc pipe
    CHandle mine{}, yours{};
    {
        HANDLE _mine, _yours;
        CSecurityDesc pipeDesc{};
        CDacl pipeDacl{};
        pipeDacl.AddAllowedAce(myLogonSid, GENERIC_READ | GENERIC_WRITE);
        pipeDesc.SetDacl(pipeDacl);
        CSecurityAttributes pipeAttr{ pipeDesc, true };
        if (!CreatePipe(&_mine, &_yours, &pipeAttr, 0)) {
            throw std::system_error(GetLastError(), std::system_category(), "CreatePipe");
        }
        mine.Attach(_mine);
        yours.Attach(_yours);
    }
    std::wcout << std::format(
        L"mine {:#x} yours {:#x} (closing)\n",
        reinterpret_cast<size_t>((HANDLE)mine),
        reinterpret_cast<size_t>((HANDLE)yours));

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
        si.hStdError = yours;
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
    DWORD cpx;
    if (!GetExitCodeProcess(hProcess, &cpx)) {
        throw std::system_error(GetLastError(), std::system_category(), "GetExitCodeProcess");
    }
    std::wcout << std::format(L"cp exited {}", cpx);
    return 0;
}
