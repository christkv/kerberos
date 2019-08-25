#include <cwchar>
#include <cstdio>
#include "kerberos_sspi.h"

static sspi_result* sspi_success_result(INT ret);
static sspi_result* sspi_error_result(DWORD errCode, const SEC_CHAR* msg);
static sspi_result* sspi_error_result_with_message(const char* message);
static SEC_CHAR* base64_encode(const SEC_CHAR* value, DWORD vlen);
static SEC_CHAR* base64_decode(const SEC_CHAR* value, DWORD* rlen);
static CHAR* wide_to_utf8(WCHAR* value);

sspi_client_state* sspi_client_state_new() {
    sspi_client_state* state = (sspi_client_state*)malloc(sizeof(sspi_client_state));
    state->spn = NULL;
    state->response = NULL;
    state->username = NULL;
    state->responseConf = 0;
    state->context_complete = FALSE;
    return state;
}

sspi_server_state* sspi_server_state_new() {
    sspi_server_state* state = (sspi_server_state*)malloc(sizeof(sspi_server_state));
    SecInvalidateHandle(&state->ctx);
    SecInvalidateHandle(&state->cred);
    state->response = NULL;
    state->username = NULL;
    state->context_complete = FALSE;
    state->targetname = NULL;
    return state;
}

VOID
auth_sspi_client_clean(sspi_client_state* state) {
    if (state->haveCtx) {
        DeleteSecurityContext(&state->ctx);
        state->haveCtx = 0;
    }
    if (state->haveCred) {
        FreeCredentialsHandle(&state->cred);
        state->haveCred = 0;
    }
    if (state->spn != NULL) {
        free(state->spn);
        state->spn = NULL;
    }
    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }
    if (state->username != NULL) {
        free(state->username);
        state->username = NULL;
    }
}

VOID
auth_sspi_server_clean(sspi_server_state* state) {
    if (SecIsValidHandle(&state->ctx)) {
        DeleteSecurityContext(&state->ctx);
        SecInvalidateHandle(&state->ctx);
    }
    if (SecIsValidHandle(&state->cred)) {
        FreeCredentialsHandle(&state->cred);
        SecInvalidateHandle(&state->cred);
    }
    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }
    if (state->username != NULL) {
        free(state->username);
        state->username = NULL;
    }
    if (state->targetname != NULL) {
        free(state->targetname);
        state->targetname = NULL;
    }
}

sspi_result*
auth_sspi_client_init(WCHAR* service,
                      ULONG flags,
                      WCHAR* user,
                      ULONG ulen,
                      WCHAR* domain,
                      ULONG dlen,
                      WCHAR* password,
                      ULONG plen,
                      WCHAR* mechoid,
                      sspi_client_state* state) {
    SECURITY_STATUS status;
    SEC_WINNT_AUTH_IDENTITY_W authIdentity;
    TimeStamp ignored;

    state->response = NULL;
    state->username = NULL;
    state->qop = SECQOP_WRAP_NO_ENCRYPT;
    state->flags = flags;
    state->haveCred = 0;
    state->haveCtx = 0;
    state->spn = _wcsdup(service);
    if (state->spn == NULL) {
        return sspi_error_result_with_message("Ran out of memory assigning service");
    }

    if (*user) {
        authIdentity.User = (unsigned short*)user;
        authIdentity.UserLength = ulen;

        if (*password) {
            authIdentity.Password = (unsigned short*)password;
            authIdentity.PasswordLength = plen;
        }

        if (*domain) {
            authIdentity.Domain = (unsigned short*)domain;
            authIdentity.DomainLength = dlen;
        }

        authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    /* Note that the first parameter, pszPrincipal, appears to be
     * completely ignored in the Kerberos SSP. For more details see
     * https://github.com/mongodb-labs/winkerberos/issues/11.
     * */
    status = AcquireCredentialsHandleW(/* Principal */
                                       NULL,
                                       /* Security package name */
                                       mechoid,
                                       /* Credentials Use */
                                       SECPKG_CRED_OUTBOUND,
                                       /* LogonID (We don't use this) */
                                       NULL,
                                       /* AuthData */
                                       *user ? &authIdentity : NULL,
                                       /* Always NULL */
                                       NULL,
                                       /* Always NULL */
                                       NULL,
                                       /* CredHandle */
                                       &state->cred,
                                       /* Expiry (Required but unused by us) */
                                       &ignored);
    if (status != SEC_E_OK) {
        return sspi_error_result(status, "AcquireCredentialsHandle");
    }

    state->haveCred = 1;
    return sspi_success_result(AUTH_GSS_COMPLETE);
}

sspi_result*
auth_sspi_server_init(WCHAR* service,
                      sspi_server_state* state) {
    auth_sspi_server_clean(state);
    TimeStamp ignored;
    SECURITY_STATUS status = AcquireCredentialsHandleW(NULL,
                                                       L"Negotiate",
                                                       SECPKG_CRED_INBOUND,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       &state->cred,
                                                       &ignored);
    if (status != SEC_E_OK) {
        return sspi_error_result(status, "AcquireCredentialsHandle");
    }

    return sspi_success_result(AUTH_GSS_COMPLETE);
}

sspi_result*
auth_sspi_client_step(sspi_client_state* state, SEC_CHAR* challenge, SecPkgContext_Bindings* sec_pkg_context_bindings) {
    SecBufferDesc inbuf;
    SecBuffer inBufs[2];
    SecBufferDesc outbuf;
    SecBuffer outBufs[1];
    ULONG ignored;
    SECURITY_STATUS status = AUTH_GSS_CONTINUE;
    DWORD len;
    BOOL haveToken = FALSE;
    INT tokenBufferIndex = 0;
    sspi_result* result;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    inbuf.ulVersion = SECBUFFER_VERSION;
    inbuf.pBuffers = inBufs;
    inbuf.cBuffers = 0;

    if (sec_pkg_context_bindings != NULL) {
        inBufs[inbuf.cBuffers].BufferType = SECBUFFER_CHANNEL_BINDINGS;
        inBufs[inbuf.cBuffers].pvBuffer = sec_pkg_context_bindings->Bindings;
        inBufs[inbuf.cBuffers].cbBuffer = sec_pkg_context_bindings->BindingsLength;
        inbuf.cBuffers++;
    }

    tokenBufferIndex = inbuf.cBuffers;
    if (state->haveCtx) {
        haveToken = TRUE;
        inBufs[tokenBufferIndex].BufferType = SECBUFFER_TOKEN;
        inBufs[tokenBufferIndex].pvBuffer = base64_decode(challenge, &len);
        if (!inBufs[tokenBufferIndex].pvBuffer) {
           return sspi_error_result_with_message("Unable to base64 decode pvBuffer");
        }

        inBufs[tokenBufferIndex].cbBuffer = len;
        inbuf.cBuffers++;
    }

    outbuf.ulVersion = SECBUFFER_VERSION;
    outbuf.cBuffers = 1;
    outbuf.pBuffers = outBufs;
    outBufs[0].pvBuffer = NULL;
    outBufs[0].cbBuffer = 0;
    outBufs[0].BufferType = SECBUFFER_TOKEN;

    status = InitializeSecurityContextW(/* CredHandle */
                                        &state->cred,
                                        /* CtxtHandle (NULL on first call) */
                                        state->haveCtx ? &state->ctx : NULL,
                                        /* Service Principal Name */
                                        state->spn,
                                        /* Flags */
                                        ISC_REQ_ALLOCATE_MEMORY | state->flags,
                                        /* Always 0 */
                                        0,
                                        /* Target data representation */
                                        SECURITY_NETWORK_DREP,
                                        /* Challenge (Set to NULL if no buffers are set) */
                                        inbuf.cBuffers > 0 ? &inbuf : NULL,
                                        /* Always 0 */
                                        0,
                                        /* CtxtHandle (Set on first call) */
                                        &state->ctx,
                                        /* Output */
                                        &outbuf,
                                        /* Context attributes */
                                        &ignored,
                                        /* Expiry (We don't use this) */
                                        NULL);

    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
        result = sspi_error_result(status, "InitializeSecurityContext");
        goto done;
    }

    state->haveCtx = 1;
    state->context_complete = TRUE;
    if (outBufs[0].cbBuffer) {
        state->response = base64_encode((const SEC_CHAR*)outBufs[0].pvBuffer, outBufs[0].cbBuffer);
        if (!state->response) {
            status = AUTH_GSS_ERROR;
            goto done;
        }
    }

    if (status == SEC_E_OK) {
        /* Get authenticated username. */
        SecPkgContext_NamesW names;
        status = QueryContextAttributesW(
            &state->ctx, SECPKG_ATTR_NAMES, &names);

        if (status != SEC_E_OK) {
            result = sspi_error_result(status, "QueryContextAttributesW");
            goto done;
        }

        state->username = wide_to_utf8(names.sUserName);
        if (state->username == NULL) {
            result = sspi_error_result_with_message("Unable to allocate memory for username");
            goto done;
        }

        FreeContextBuffer(names.sUserName);
        result = sspi_success_result(AUTH_GSS_COMPLETE);
    } else {
        result = sspi_success_result(AUTH_GSS_CONTINUE);
    }
done:
    if (haveToken) {
        free(inBufs[tokenBufferIndex].pvBuffer);
    }
    if (outBufs[0].pvBuffer) {
        FreeContextBuffer(outBufs[0].pvBuffer);
    }

    return result;
}

sspi_result*
auth_sspi_server_step(sspi_server_state* state, const char* challenge)
{
    sspi_result* ret = NULL;
    ULONG Attribs = 0;
    SecBufferDesc OutBuffDesc;
    SecBuffer OutSecBuff;
    SecBufferDesc InBuffDesc;
    SecBuffer InSecBuff;
    TimeStamp Lifetime;

    // Clear the context if it is a new request
    if (state->context_complete) {
        if (SecIsValidHandle(&state->ctx)) {
            DeleteSecurityContext(&state->ctx);
            SecInvalidateHandle(&state->ctx);
        }
        if (state->username != NULL) {
            free(state->username);
            state->username = NULL;
        }
        state->context_complete = FALSE;
    }

    // Always clear the old response
    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    // If there is a challenge (data from the client) we need to give it to SSPI
    if (challenge && *challenge) {
        // Prepare input buffer
        DWORD len;
        InSecBuff.pvBuffer = base64_decode(challenge, &len);
        if (!InSecBuff.pvBuffer) {
            return sspi_error_result_with_message("Unable to base64 decode challenge");
        }
        InSecBuff.cbBuffer = len;
        InSecBuff.BufferType = SECBUFFER_TOKEN;

        InBuffDesc.ulVersion = SECBUFFER_VERSION;
        InBuffDesc.cBuffers = 1;
        InBuffDesc.pBuffers = &InSecBuff;
    } else {
        return sspi_error_result_with_message("No challenge parameter in request from client");
    }

    PSecPkgInfoW pkgInfo;
    if (QuerySecurityPackageInfoW(L"Negotiate", &pkgInfo) != SEC_E_OK) {
        ret = sspi_error_result_with_message("Unable to get max token size for output buffer");
        goto end;
    }

    // Prepare output buffer
    OutSecBuff.cbBuffer = pkgInfo->cbMaxToken;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = malloc(pkgInfo->cbMaxToken);
    if (OutSecBuff.pvBuffer == NULL) {
        ret = sspi_error_result_with_message("Unable to allocate memory for output buffer");
        goto end;
    }

    OutBuffDesc.ulVersion = SECBUFFER_VERSION;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    SECURITY_STATUS ss = AcceptSecurityContext(&state->cred,
                                               SecIsValidHandle(&state->ctx) ? &state->ctx : NULL,
                                               &InBuffDesc,
                                               Attribs,
                                               SECURITY_NATIVE_DREP,
                                               &state->ctx,
                                               &OutBuffDesc,
                                               &Attribs,
                                               &Lifetime);

    // Check if ready.
    if (ss == SEC_E_OK) {
        state->context_complete = TRUE;
        ret = sspi_success_result(AUTH_GSS_COMPLETE);

        // Get authenticated username.
        SecPkgContext_NativeNamesW names;
        SECURITY_STATUS ss = QueryContextAttributesW(&state->ctx, SECPKG_ATTR_NATIVE_NAMES, &names);

        if (ss == SEC_E_OK) {
            state->username = wide_to_utf8(names.sClientName);
            FreeContextBuffer(names.sClientName);
            if (state->username == NULL) {
                ret = sspi_error_result_with_message("Unable to allocate memory for username");
                goto end;
            }
            goto end;
        }

        // Impersonate the client (only if native names failed).
        ss = ImpersonateSecurityContext(&state->ctx);
        if (ss == SEC_E_OK) {
            // Get username
            DWORD cbUserName = 0;
            GetUserName(NULL, &cbUserName);
            state->username = (PCHAR)malloc(cbUserName);
            if (state->username == NULL) {
                ret = sspi_error_result_with_message("Unable to allocate memory for username");
                goto end;
            }

            if (!GetUserName(state->username, &cbUserName)) {
                ret = sspi_error_result_with_message("Unable to obtain username");
                goto end;
            }

            RevertSecurityContext(&state->ctx);
        } else {
            ret = sspi_error_result_with_message("Unable to obtain username");
            goto end;
        }

        goto end;
    }

    // Continue if applicable.
    if (ss == SEC_I_CONTINUE_NEEDED) {
        state->response = base64_encode((const SEC_CHAR*)OutSecBuff.pvBuffer, OutSecBuff.cbBuffer);
        if (!state->response) {
            ret = sspi_error_result_with_message("Unable to base64 encode response message");
        } else {
            ret = sspi_success_result(AUTH_GSS_CONTINUE);
        }

        goto end;
    }

    // Clear the context when reached an invalid/error state that cannot be handled
    if (ss != SEC_E_OK) {
        ret = sspi_error_result(ss, "AcceptSecurityContext failed");
        if (SecIsValidHandle(&state->ctx)) {
            DeleteSecurityContext(&state->ctx);
            SecInvalidateHandle(&state->ctx);
        }
        goto end;
    }

end:
    if (InSecBuff.pvBuffer)
        free(InSecBuff.pvBuffer);
    if (OutSecBuff.pvBuffer)
        free(OutSecBuff.pvBuffer);

    return ret;
}

sspi_result*
auth_sspi_client_unwrap(sspi_client_state* state, SEC_CHAR* challenge) {
    sspi_result* result;
    SECURITY_STATUS status;
    DWORD len;
    SecBuffer wrapBufs[2];
    SecBufferDesc wrapBufDesc;
    wrapBufDesc.ulVersion = SECBUFFER_VERSION;
    wrapBufDesc.cBuffers = 2;
    wrapBufDesc.pBuffers = wrapBufs;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
        state->qop = SECQOP_WRAP_NO_ENCRYPT;
    }

    if (!state->haveCtx) {
        return sspi_error_result_with_message("Uninitialized security context. You must use authGSSClientStep to initialize the security context before calling this function.");
    }

    wrapBufs[0].pvBuffer = base64_decode(challenge, &len);
    if (!wrapBufs[0].pvBuffer) {
        return sspi_error_result_with_message("Unable to decode base64 response");
    }

    wrapBufs[0].cbBuffer = len;
    wrapBufs[0].BufferType = SECBUFFER_STREAM;

    wrapBufs[1].pvBuffer = NULL;
    wrapBufs[1].cbBuffer = 0;
    wrapBufs[1].BufferType = SECBUFFER_DATA;

    status = DecryptMessage(&state->ctx, &wrapBufDesc, 0, &state->qop);
    if (status != SEC_E_OK) {
        result = sspi_error_result(status, "DecryptMessage");
        goto done;
    }

    if (wrapBufs[1].cbBuffer) {
        state->response = base64_encode((const SEC_CHAR*)wrapBufs[1].pvBuffer, wrapBufs[1].cbBuffer);
        if (!state->response) {
            result = sspi_error_result_with_message("Unable to base64 encode decrypted message");
            goto done;
        }
    }

    result = sspi_success_result(AUTH_GSS_COMPLETE);
done:
    if (wrapBufs[0].pvBuffer) {
        free(wrapBufs[0].pvBuffer);
    }

    return result;
}

sspi_result*
auth_sspi_client_wrap(sspi_client_state* state,
                      SEC_CHAR* data,
                      SEC_CHAR* user,
                      ULONG ulen,
                      INT protect) {
    SECURITY_STATUS status;
    SecPkgContext_Sizes sizes;
    SecBuffer wrapBufs[3];
    SecBufferDesc wrapBufDesc;
    SEC_CHAR* decodedData = NULL;
    SEC_CHAR* inbuf;
    SIZE_T inbufSize;
    SEC_CHAR* outbuf;
    DWORD outbufSize;
    SEC_CHAR* plaintextMessage;
    ULONG plaintextMessageSize;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    if (!state->haveCtx) {
        return sspi_error_result_with_message("Uninitialized security context. You must use authGSSClientStep to initialize the security context before calling this function.");
    }

    status = QueryContextAttributes(&state->ctx, SECPKG_ATTR_SIZES, &sizes);
    if (status != SEC_E_OK) {
        return sspi_error_result(status, "QueryContextAttributes");
    }

    if (*user) {
        /* Length of user + 4 bytes for security layer (see below). */
        plaintextMessageSize = ulen + 4;
    } else {
        decodedData = base64_decode(data, &plaintextMessageSize);
        if (!decodedData) {
            return sspi_error_result_with_message("Unable to base64 decode message");
        }
    }

    inbufSize =
        sizes.cbSecurityTrailer + plaintextMessageSize + sizes.cbBlockSize;
    inbuf = (SEC_CHAR*)malloc(inbufSize);
    if (inbuf == NULL) {
        free(decodedData);
        return sspi_error_result_with_message("Unable to allocate memory for buffer");
    }

    plaintextMessage = inbuf + sizes.cbSecurityTrailer;
    if (*user) {
        /* Authenticate the provided user. Unlike pykerberos, we don't
         * need any information from "data" to do that.
         */
        plaintextMessage[0] = 1; /* No security layer */
        plaintextMessage[1] = 0;
        plaintextMessage[2] = 0;
        plaintextMessage[3] = 0;
        memcpy_s(
            plaintextMessage + 4,
            inbufSize - sizes.cbSecurityTrailer - 4,
            user,
            strlen(user));
    } else {
        /* No user provided. Just rewrap data. */
        memcpy_s(
            plaintextMessage,
            inbufSize - sizes.cbSecurityTrailer,
            decodedData,
            plaintextMessageSize);
        free(decodedData);
    }

    wrapBufDesc.cBuffers = 3;
    wrapBufDesc.pBuffers = wrapBufs;
    wrapBufDesc.ulVersion = SECBUFFER_VERSION;

    wrapBufs[0].cbBuffer = sizes.cbSecurityTrailer;
    wrapBufs[0].BufferType = SECBUFFER_TOKEN;
    wrapBufs[0].pvBuffer = inbuf;

    wrapBufs[1].cbBuffer = (ULONG)plaintextMessageSize;
    wrapBufs[1].BufferType = SECBUFFER_DATA;
    wrapBufs[1].pvBuffer = inbuf + sizes.cbSecurityTrailer;

    wrapBufs[2].cbBuffer = sizes.cbBlockSize;
    wrapBufs[2].BufferType = SECBUFFER_PADDING;
    wrapBufs[2].pvBuffer =
        inbuf + (sizes.cbSecurityTrailer + plaintextMessageSize);

    status = EncryptMessage(
        &state->ctx,
        protect ? 0 : SECQOP_WRAP_NO_ENCRYPT,
        &wrapBufDesc,
        0);
    if (status != SEC_E_OK) {
        free(inbuf);
        return sspi_error_result(status, "EncryptMessage");
    }

    outbufSize =
        wrapBufs[0].cbBuffer + wrapBufs[1].cbBuffer + wrapBufs[2].cbBuffer;
    outbuf = (SEC_CHAR*)malloc(sizeof(SEC_CHAR) * outbufSize);
    if (outbuf == NULL) {
        free(inbuf);
        return sspi_error_result_with_message("Unable to allocate memory for out buffer");
    }

    memcpy_s(outbuf,
             outbufSize,
             wrapBufs[0].pvBuffer,
             wrapBufs[0].cbBuffer);
    memcpy_s(outbuf + wrapBufs[0].cbBuffer,
             outbufSize - wrapBufs[0].cbBuffer,
             wrapBufs[1].pvBuffer,
             wrapBufs[1].cbBuffer);
    memcpy_s(outbuf + wrapBufs[0].cbBuffer + wrapBufs[1].cbBuffer,
             outbufSize - wrapBufs[0].cbBuffer - wrapBufs[1].cbBuffer,
             wrapBufs[2].pvBuffer,
             wrapBufs[2].cbBuffer);
    state->response = base64_encode(outbuf, outbufSize);

    sspi_result* result;
    if (!state->response) {
        result = sspi_error_result_with_message("Unable to base64 decode outbuf");
    } else {
        result = sspi_success_result(AUTH_GSS_COMPLETE);
    }

    free(inbuf);
    free(outbuf);
    return result;
}

static sspi_result* sspi_success_result(INT ret) {
    sspi_result* result = (sspi_result*)malloc(sizeof(sspi_result));
    result->code = ret;
    result->message = NULL;
    return result;
}

static sspi_result* sspi_error_result(DWORD errCode, const SEC_CHAR* msg) {
    SEC_CHAR* err;
    DWORD status;
    DWORD flags = (FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS);

    status = FormatMessageA(flags,
                            NULL,
                            errCode,
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                            (LPSTR)&err,
                            0,
                            NULL);

    sspi_result* result = (sspi_result*)malloc(sizeof(sspi_result));
    result->code = AUTH_GSS_ERROR;
    result->message = (char*)malloc(sizeof(char) * 1024 + 2);
    if (status) {
        sprintf(result->message, "%s: %s", msg, err);
    } else {
        sprintf(result->message, "%s", msg);
    }

    return result;
}

static sspi_result* sspi_error_result_with_message(const char* message) {
    sspi_result* result = (sspi_result*)malloc(sizeof(sspi_result));
    result->code = AUTH_GSS_ERROR;
    result->message = strdup(message);
    return result;
}

static SEC_CHAR*
base64_encode(const SEC_CHAR* value, DWORD vlen) {
    SEC_CHAR* out = NULL;
    DWORD len;
    /* Get the correct size for the out buffer. */
    if (CryptBinaryToStringA((BYTE*)value,
                             vlen,
                             CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                             NULL,
                             &len)) {
        out = (SEC_CHAR*)malloc(sizeof(SEC_CHAR) * len);
        if (out) {
            /* Encode to the out buffer. */
            if (CryptBinaryToStringA((BYTE*)value,
                                     vlen,
                                     CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                                     out,
                                     &len)) {
                return out;
            } else {
                free(out);
            }
        }
    }

    return NULL;
}

static SEC_CHAR*
base64_decode(const SEC_CHAR* value, DWORD* rlen) {
    SEC_CHAR* out = NULL;
    /* Get the correct size for the out buffer. */
    if (CryptStringToBinaryA(value,
                             0,
                             CRYPT_STRING_BASE64,
                             NULL,
                             rlen,
                             NULL,
                             NULL)) {
        out = (SEC_CHAR*)malloc(sizeof(SEC_CHAR) * *rlen);
        if (out) {
            /* Decode to the out buffer. */
            if (CryptStringToBinaryA(value,
                                     0,
                                     CRYPT_STRING_BASE64,
                                     (BYTE*)out,
                                     rlen,
                                     NULL,
                                     NULL)) {
                return out;
            } else {
                free(out);
            }
        }
    }

    return NULL;
}

static CHAR*
wide_to_utf8(WCHAR* value) {
    CHAR* out;
    INT len = WideCharToMultiByte(CP_UTF8,
                                  0,
                                  value,
                                  -1,
                                  NULL,
                                  0,
                                  NULL,
                                  NULL);
    if (len) {
        out = (CHAR*)malloc(sizeof(CHAR) * len);
        if (!out) {
            return NULL;
        }

        if (WideCharToMultiByte(CP_UTF8,
                                0,
                                value,
                                -1,
                                out,
                                len,
                                NULL,
                                NULL)) {
            return out;
        } else {
            free(out);
        }
    }

    return NULL;
}
