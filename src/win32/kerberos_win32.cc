#include <memory>

#include "../kerberos.h"
#include "../kerberos_worker.h"

#define GSS_MECH_OID_KRB5 9
#define GSS_MECH_OID_SPNEGO 6
#define GSS_MECH_OID_KRB5_STR L"Kerberos"
#define GSS_MECH_OID_SPNEGO_STR L"Negotiate"

#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_SEQUENCE_FLAG 8

const wchar_t* to_wstring(const char *bytes) {
    unsigned int sizeOfStr = MultiByteToWideChar(CP_UTF8, 0, bytes, -1, NULL, 0);
    wchar_t *output = new wchar_t[sizeOfStr];
    MultiByteToWideChar(CP_UTF8, 0, bytes, -1, output, sizeOfStr);
    return output;
}

NAN_INLINE std::wstring WStringOptionValue(v8::Local<v8::Object> options, const char* _key) {
    Nan::HandleScope scope;
    v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
    if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
      return std::wstring();
    }

    v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
    if (!value->IsString()) {
      return std::wstring();
    }

    return std::wstring(to_wstring(*(Nan::Utf8String(value))));
}

/// KerberosClient
KerberosClient::~KerberosClient() {
    if (_state != NULL) {
        auth_sspi_client_clean(_state);
        _state = NULL;
    }
}

NAN_METHOD(KerberosClient::Step) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    std::string challenge(*Nan::Utf8String(info[0]));
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[1]).ToLocalChecked());

    KerberosWorker::Run(callback, "kerberos:ClientStep", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        std::shared_ptr<sspi_result> result(
            auth_sspi_client_step(client->state(), (SEC_CHAR*)challenge.c_str(), NULL), ResultDeleter);

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> response = Nan::Null();
            if (client->state()->response != NULL) {
                response = Nan::New(client->state()->response).ToLocalChecked();
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), response};
            worker->Call(2, argv);
        });
    });
}

NAN_METHOD(KerberosClient::UnwrapData) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    std::string challenge(*Nan::Utf8String(info[0]));
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[1]).ToLocalChecked());

    KerberosWorker::Run(callback, "kerberos:ClientUnwrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        std::shared_ptr<sspi_result> result(
            auth_sspi_client_unwrap(client->state(), (SEC_CHAR*)challenge.c_str()), ResultDeleter);

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), Nan::New(client->state()->response).ToLocalChecked()};
            worker->Call(2, argv);
        });
    });
}

NAN_METHOD(KerberosClient::WrapData) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    std::string challenge(*Nan::Utf8String(info[0]));
    v8::Local<v8::Object> options = Nan::To<v8::Object>(info[1]).ToLocalChecked();
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[2]).ToLocalChecked());
    std::string user = StringOptionValue(options, "user");
    int protect = 0; // NOTE: this should be an option

    KerberosWorker::Run(callback, "kerberos:ClientWrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        std::shared_ptr<sspi_result> result(auth_sspi_client_wrap(
            client->state(), (SEC_CHAR*)challenge.c_str(), (SEC_CHAR*)user.c_str(), user.length(), protect), ResultDeleter);

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;

            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), Nan::New(client->state()->response).ToLocalChecked()};
            worker->Call(2, argv);
        });
    });
}

/// KerberosServer
KerberosServer::~KerberosServer() {
    if (_state != NULL) {
        auth_sspi_server_clean(_state);
        _state = NULL;
    }
}

NAN_METHOD(KerberosServer::Step) {
    KerberosServer* server = Nan::ObjectWrap::Unwrap<KerberosServer>(info.This());
    std::string challenge(*Nan::Utf8String(info[0]));
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[1]).ToLocalChecked());

    KerberosWorker::Run(callback, "kerberos:ServerStep", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        std::shared_ptr<sspi_result> result(
            auth_sspi_server_step(server->state(), challenge.c_str()), ResultDeleter);

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> response = Nan::Null();
            if (server->state()->response != NULL) {
                response = Nan::New(server->state()->response).ToLocalChecked();
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), response};
            worker->Call(2, argv);
        });
    });
}

/// Global Methods
NAN_METHOD(InitializeClient) {
    std::wstring service(to_wstring(*(Nan::Utf8String(info[0]))));
    v8::Local<v8::Object> options = Nan::To<v8::Object>(info[1]).ToLocalChecked();
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[2]).ToLocalChecked());

    std::wstring user = WStringOptionValue(options, "user");
    std::wstring domain = WStringOptionValue(options, "domain");
    std::wstring password = WStringOptionValue(options, "password");
    ULONG gss_flags = (ULONG)UInt32OptionValue(options, "flags", GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG);
    uint32_t mech_oid_int = UInt32OptionValue(options, "mechOID", 0);
    std::wstring mech_oid = GSS_MECH_OID_KRB5_STR;
    if (mech_oid_int == GSS_MECH_OID_SPNEGO) {
        mech_oid = GSS_MECH_OID_SPNEGO_STR;
    }

    KerberosWorker::Run(callback, "kerberos:InitializeClient", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_client_state* client_state = sspi_client_state_new();
        std::shared_ptr<sspi_result> result(auth_sspi_client_init(
            (WCHAR*)service.c_str(), gss_flags, (WCHAR*)user.c_str(), user.length(),
            (WCHAR*)domain.c_str(), domain.length(), (WCHAR*)password.c_str(), password.length(),
            (WCHAR*)mech_oid.c_str(), client_state), ResultDeleter);

        // must clean up state if we won't be using it, smart pointers won't help here unfortunately
        // because we can't `release` a shared pointer.
        if (result->code == AUTH_GSS_ERROR) {
            free(client_state);
        }

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), KerberosClient::NewInstance(client_state)};
            worker->Call(2, argv);
        });
    });
}

NAN_METHOD(InitializeServer) {
    std::wstring service(to_wstring(v8::String::Utf8Value(info[0]->ToString())));
    Nan::Callback* callback = new Nan::Callback(Nan::To<v8::Function>(info[1]).ToLocalChecked());

    KerberosWorker::Run(callback, "kerberos:InitializeServer", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        sspi_server_state* server_state = sspi_server_state_new();
        std::shared_ptr<sspi_result> result(auth_sspi_server_init(
            (WCHAR*)service.c_str(), server_state), ResultDeleter);

        // must clean up state if we won't be using it, smart pointers won't help here unfortunately
        // because we can't `release` a shared pointer.
        if (result->code == AUTH_GSS_ERROR) {
            free(server_state);
        }

        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (result->code == AUTH_GSS_ERROR) {
                v8::Local<v8::Value> argv[] = {Nan::Error(result->message), Nan::Null()};
                worker->Call(2, argv);
                return;
            }

            v8::Local<v8::Value> argv[] = {Nan::Null(), KerberosServer::NewInstance(server_state)};
            worker->Call(2, argv);
        });
    });
}

NAN_METHOD(PrincipalDetails) {
    Nan::ThrowError("`principalDetails` is not implemented yet for windows");
}

NAN_METHOD(CheckPassword) {
    Nan::ThrowError("`checkPassword` is not implemented yet for windows");
}
