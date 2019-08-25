#include "kerberos.h"
#include "kerberos_worker.h"

/// KerberosClient
Nan::Persistent<v8::Function> KerberosClient::constructor;
NAN_MODULE_INIT(KerberosClient::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>();
    tpl->SetClassName(Nan::New("KerberosClient").ToLocalChecked());
    Nan::SetPrototypeMethod(tpl, "step", Step);
    Nan::SetPrototypeMethod(tpl, "wrap", WrapData);
    Nan::SetPrototypeMethod(tpl, "unwrap", UnwrapData);

    v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
    itpl->SetInternalFieldCount(1);

    Nan::SetAccessor(itpl, Nan::New("username").ToLocalChecked(), KerberosClient::UserNameGetter);
    Nan::SetAccessor(itpl, Nan::New("response").ToLocalChecked(), KerberosClient::ResponseGetter);
    Nan::SetAccessor(
        itpl, Nan::New("responseConf").ToLocalChecked(), KerberosClient::ResponseConfGetter);
    Nan::SetAccessor(
        itpl, Nan::New("contextComplete").ToLocalChecked(), KerberosClient::ContextCompleteGetter);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(target,
             Nan::New("KerberosClient").ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
}

v8::Local<v8::Object> KerberosClient::NewInstance(krb_client_state* state) {
    Nan::EscapableHandleScope scope;
    v8::Local<v8::Function> ctor = Nan::New<v8::Function>(KerberosClient::constructor);
    v8::Local<v8::Object> object = Nan::NewInstance(ctor).ToLocalChecked();
    KerberosClient* class_instance = new KerberosClient(state);
    class_instance->Wrap(object);
    return scope.Escape(object);
}

KerberosClient::KerberosClient(krb_client_state* state) : _state(state) {}

krb_client_state* KerberosClient::state() const {
    return _state;
}

NAN_GETTER(KerberosClient::UserNameGetter) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    (client->state()->username == NULL)
        ? info.GetReturnValue().Set(Nan::Null())
        : info.GetReturnValue().Set(Nan::New(client->state()->username).ToLocalChecked());
}

NAN_GETTER(KerberosClient::ResponseGetter) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    (client->state()->response == NULL)
        ? info.GetReturnValue().Set(Nan::Null())
        : info.GetReturnValue().Set(Nan::New(client->state()->response).ToLocalChecked());
}

NAN_GETTER(KerberosClient::ResponseConfGetter) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    info.GetReturnValue().Set(Nan::New(client->state()->responseConf));
}

NAN_GETTER(KerberosClient::ContextCompleteGetter) {
    KerberosClient* client = Nan::ObjectWrap::Unwrap<KerberosClient>(info.This());
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(client->state()->context_complete));
}

/// KerberosServer
Nan::Persistent<v8::Function> KerberosServer::constructor;
NAN_MODULE_INIT(KerberosServer::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>();
    tpl->SetClassName(Nan::New("KerberosServer").ToLocalChecked());
    Nan::SetPrototypeMethod(tpl, "step", Step);

    v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
    itpl->SetInternalFieldCount(1);

    Nan::SetAccessor(itpl, Nan::New("username").ToLocalChecked(), KerberosServer::UserNameGetter);
    Nan::SetAccessor(itpl, Nan::New("response").ToLocalChecked(), KerberosServer::ResponseGetter);
    Nan::SetAccessor(
        itpl, Nan::New("targetName").ToLocalChecked(), KerberosServer::TargetNameGetter);
    Nan::SetAccessor(
        itpl, Nan::New("contextComplete").ToLocalChecked(), KerberosServer::ContextCompleteGetter);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(target,
             Nan::New("KerberosServer").ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
}

v8::Local<v8::Object> KerberosServer::NewInstance(krb_server_state* state) {
    Nan::EscapableHandleScope scope;
    v8::Local<v8::Function> ctor = Nan::New<v8::Function>(KerberosServer::constructor);
    v8::Local<v8::Object> object = Nan::NewInstance(ctor).ToLocalChecked();
    KerberosServer* class_instance = new KerberosServer(state);
    class_instance->Wrap(object);
    return scope.Escape(object);
}

KerberosServer::KerberosServer(krb_server_state* state) : _state(state) {}

krb_server_state* KerberosServer::state() const {
    return _state;
}

NAN_GETTER(KerberosServer::UserNameGetter) {
    KerberosServer* server = Nan::ObjectWrap::Unwrap<KerberosServer>(info.This());
    (server->state()->username == NULL)
        ? info.GetReturnValue().Set(Nan::Null())
        : info.GetReturnValue().Set(Nan::New(server->state()->username).ToLocalChecked());
}

NAN_GETTER(KerberosServer::ResponseGetter) {
    KerberosServer* server = Nan::ObjectWrap::Unwrap<KerberosServer>(info.This());
    (server->state()->response == NULL)
        ? info.GetReturnValue().Set(Nan::Null())
        : info.GetReturnValue().Set(Nan::New(server->state()->response).ToLocalChecked());
}

NAN_GETTER(KerberosServer::TargetNameGetter) {
    KerberosServer* server = Nan::ObjectWrap::Unwrap<KerberosServer>(info.This());
    (server->state()->targetname == NULL)
        ? info.GetReturnValue().Set(Nan::Null())
        : info.GetReturnValue().Set(Nan::New(server->state()->targetname).ToLocalChecked());
}

NAN_GETTER(KerberosServer::ContextCompleteGetter) {
    KerberosServer* server = Nan::ObjectWrap::Unwrap<KerberosServer>(info.This());
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(server->state()->context_complete));
}

NAN_METHOD(TestMethod) {
    std::string string(*Nan::Utf8String(info[0]));
    bool shouldError = Nan::To<bool>(info[1]).FromJust();

    std::string optionalString;
    Nan::Callback* callback;
    if (info[2]->IsFunction()) {
        callback = new Nan::Callback(Nan::To<v8::Function>(info[2]).ToLocalChecked());
    } else {
        optionalString = *Nan::Utf8String(info[2]);
        callback = new Nan::Callback(Nan::To<v8::Function>(info[3]).ToLocalChecked());
    }

    KerberosWorker::Run(callback, "kerberos:TestMethod", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        return onFinished([=](KerberosWorker* worker) {
            Nan::HandleScope scope;
            if (shouldError) {
                v8::Local<v8::Value> argv[] = {Nan::Error("an error occurred"), Nan::Null()};
                worker->Call(2, argv);
            } else {
                v8::Local<v8::Value> argv[] = {Nan::Null(), Nan::New(optionalString.c_str()).ToLocalChecked()};
                worker->Call(2, argv);
            }
        });
    });
}

NAN_MODULE_INIT(Init) {
    // Custom types
    KerberosClient::Init(target);
    KerberosServer::Init(target);

    Nan::Set(target,
             Nan::New("initializeClient").ToLocalChecked(),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(InitializeClient)).ToLocalChecked());
    Nan::Set(target,
             Nan::New("initializeServer").ToLocalChecked(),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(InitializeServer)).ToLocalChecked());
    Nan::Set(target,
             Nan::New("principalDetails").ToLocalChecked(),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(PrincipalDetails)).ToLocalChecked());
    Nan::Set(target,
             Nan::New("checkPassword").ToLocalChecked(),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(CheckPassword)).ToLocalChecked());
    Nan::Set(target,
             Nan::New("_testMethod").ToLocalChecked(),
             Nan::GetFunction(Nan::New<v8::FunctionTemplate>(TestMethod)).ToLocalChecked());
}

NODE_MODULE(kerberos, Init)
