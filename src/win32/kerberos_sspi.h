/*
 * Copyright 2016 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define SECURITY_WIN32 1 /* Required for SSPI */

#include <windows.h>
#include <sspi.h>

#define AUTH_GSS_ERROR -1
#define AUTH_GSS_COMPLETE 1
#define AUTH_GSS_CONTINUE 0

typedef struct {
    int code;
    char* message;
    char* data;
} sspi_result;

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    WCHAR* spn;
    SEC_CHAR* response;
    SEC_CHAR* username;
    ULONG flags;
    UCHAR haveCred;
    UCHAR haveCtx;
    ULONG qop;

    INT responseConf;
    BOOL context_complete;
} sspi_client_state;

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    SEC_CHAR* response;
    SEC_CHAR* username;
    BOOL context_complete;
    char* targetname;
} sspi_server_state;

sspi_client_state* sspi_client_state_new();
sspi_server_state* sspi_server_state_new();

VOID auth_sspi_client_clean(sspi_client_state* state);
VOID auth_sspi_server_clean(sspi_server_state* state);

sspi_result* auth_sspi_client_init(WCHAR* service,
                                   ULONG flags,
                                   WCHAR* user,
                                   ULONG ulen,
                                   WCHAR* domain,
                                   ULONG dlen,
                                   WCHAR* password,
                                   ULONG plen,
                                   WCHAR* mechoid,
                                   sspi_client_state* state);

sspi_result* auth_sspi_server_init(WCHAR* service,
                                   sspi_server_state* state);

sspi_result* auth_sspi_client_step(sspi_client_state* state, SEC_CHAR* challenge, SecPkgContext_Bindings* sec_pkg_context_bindings);
sspi_result* auth_sspi_server_step(sspi_server_state* state, const char* challenge);
sspi_result* auth_sspi_client_unwrap(sspi_client_state* state, SEC_CHAR* challenge);
sspi_result* auth_sspi_client_wrap(sspi_client_state* state, SEC_CHAR* data, SEC_CHAR* user, ULONG ulen, INT protect);
