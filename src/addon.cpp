#include "napi.h"
using namespace Napi;

Value Test(const CallbackInfo& info)
{
	Env env = info.Env();
	// ...
	return env.Undefined();
}

Object Init(Env env, Object exports)
{
	exports["test"] = Function::New<Test>(env);

	return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
