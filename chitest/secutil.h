#pragma once

#include "stdafx.h"

namespace chibox {
    class TokenMandatoryLabel {
    public:
        explicit TokenMandatoryLabel(MANDATORY_LEVEL level) {
            SID_IDENTIFIER_AUTHORITY ml SECURITY_MANDATORY_LABEL_AUTHORITY;
            PSID psid;
            if (!AllocateAndInitializeSid(
                &ml,
                1,
                MANDATORY_LEVEL_TO_MANDATORY_RID(level),
                0, 0, 0, 0, 0, 0, 0,
                &psid)) {
                throw std::system_error(GetLastError(), std::system_category(), "AllocateAndInitializeSid");
            }
            sid = sid_pointer(psid, &FreeSid);
            label = std::make_unique<TOKEN_MANDATORY_LABEL>();
            *label = TOKEN_MANDATORY_LABEL{ {psid, 0} };
        }
        TokenMandatoryLabel(const TokenMandatoryLabel&) = delete;
        TokenMandatoryLabel& operator=(const TokenMandatoryLabel&) = delete;
        TokenMandatoryLabel(TokenMandatoryLabel&&) = default;
        TokenMandatoryLabel& operator=(TokenMandatoryLabel&&) = default;

        PTOKEN_MANDATORY_LABEL get() const {
            return label.get();
        }

        BOOL assign(const CAccessToken& token) const {
            return SetTokenInformation(
                token.GetHandle(),
                TokenIntegrityLevel,
                get(),
                sizeof(TOKEN_MANDATORY_LABEL));
        }

    private:
        using sid_pointer = std::unique_ptr<std::remove_pointer_t<PSID>, decltype(&FreeSid)>;

        sid_pointer sid{ nullptr, &FreeSid };
        std::unique_ptr<TOKEN_MANDATORY_LABEL> label{};
    };
};
