#ifndef COMMON_H
#define COMMON_H

#include <nan.h>

#if defined(__linux__) || defined(__APPLE__) || defined(__MVS__)
#include "unix/kerberos_gss.h"

typedef gss_client_state krb_client_state;
typedef gss_server_state krb_server_state;
typedef gss_result krb_result;
#else
#include "win32/kerberos_sspi.h"

typedef sspi_client_state krb_client_state;
typedef sspi_server_state krb_server_state;
typedef sspi_result krb_result;
#endif

// Provide a default custom delter for the `gss_result` type
inline void ResultDeleter(krb_result* result) {
  free(result);
}

// Useful methods for optional value handling
NAN_INLINE std::string StringOptionValue(v8::Local<v8::Object> options, const char* _key) {
    Nan::HandleScope scope;
    v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
    if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
      return std::string();
    }

    v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
    if (!value->IsString()) {
      return std::string();
    }

    return std::string(*(Nan::Utf8String(value)));
}

NAN_INLINE uint32_t UInt32OptionValue(v8::Local<v8::Object> options,
                                      const char* _key,
                                      uint32_t def) {
    Nan::HandleScope scope;
    v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
    if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
      return def;
    }

    v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
    if (!value->IsNumber()) {
      return def;
    }

    return value->Uint32Value(Nan::GetCurrentContext()).FromJust();
}

#endif
