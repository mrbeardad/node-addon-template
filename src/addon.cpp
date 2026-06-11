#include <napi.h>

Napi::Value Hello(const Napi::CallbackInfo& info)
{
    return Napi::String::New(info.Env(), "Hello, world!");
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports["hello"] = Napi::Function::New<Hello>(env);
    return exports;
}

NODE_API_MODULE(my_addon, Init)
