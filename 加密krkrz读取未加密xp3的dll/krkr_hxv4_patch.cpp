#include <cstdio>
#include <cstdint>
#include <string>
#include <windows.h>

#ifndef FASTCALL
#define FASTCALL __fastcall
#endif

#include "tp_stub.h"

#define WINHOOK_IMPLEMENTATION
#define WINHOOK_NOINLINE
#define WINHOOK_STATIC 
#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC

#ifdef USECOMPAT
#include "winhook_v350.h"
#include "winversion_v100.h"
#include "stb_minhook_v1332.h"
#else
#include "winhook.h"
#include "winversion.h"
#include "stb_minhook.h"
#endif

static HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter);
static tTJSBinaryStream* FASTCALL TVPCreateStream_hook(ttstr* name, tjs_uint32 flags);
static FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName);

#define DEFINE_HOOK(name) \
    static decltype(name##_hook) *name##_org = nullptr; \
    static void *name##_old = nullptr;

DEFINE_HOOK(TVPCreateStream);
DEFINE_HOOK(V2Link);
DEFINE_HOOK(GetProcAddress);

#define BIND_HOOK(name) \
    MH_CreateHook(name##_old, (LPVOID)name##_hook, (LPVOID*)&name##_org); \
    MH_EnableHook(name##_old)

#define UNBIND_HOOK(name) \
    if(name##_old) { MH_DisableHook(name##_old); }

const wchar_t* TARGET_XP3 = L"patch.xp3"; 
iTVPFunctionExporter *g_exporter = nullptr;

const char* TVPCreateStream_sig = "55 8b ec 6a ff 68 ? ? ? ? 64 a1 ? ? ? ? 50 83 ec 5c 53 56 57 a1 ? ? ? ? 33 c5 50 8d 45 f4 64 a3 ? ? ? ? 89 65 f0 89 4d ec c7 45 ? ? ? ? ? e8 ? ? ? ? 8b 4d f4 64 89 0d ? ? ? ? 59 5f 5e 5b 8b e5 5d c3";

HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter)
{
    TVPInitImportStub(exporter); 
    g_exporter = exporter;
    UNBIND_HOOK(V2Link);
    return V2Link_org(exporter);
}

tTJSBinaryStream* FASTCALL TVPCreateStream_hook(ttstr* name, tjs_uint32 flags)
{
    if(!g_exporter || flags != 0) return TVPCreateStream_org(name, flags);
    
    const wchar_t *inpath = name->c_str();
    const wchar_t *inname = nullptr;

    if(wcsstr(inpath, L"arc://")) {
        inname = inpath + 6;
        if(wcsncmp(inname, L"./", 2) == 0) inname += 2;
    } 
    else {
        const wchar_t* p = wcsstr(inpath, L".xp3/");
        if(p) inname = p + 5;
    }

    if(inname) {
        ttstr name_redirect = ttstr(TARGET_XP3) + ttstr(L">") + ttstr(inname);
        ttstr name_full = TVPGetAppPath() + L"/" + name_redirect;

        if (TVPIsExistentStorageNoSearchNoNormalize(name_full)) {
            return TVPCreateStream_org(&name_full, flags);
        }
    }

    return TVPCreateStream_org(name, flags);
}

FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName)
{
    auto res = GetProcAddress_org(hModule, lpProcName);
    if(lpProcName && ((uintptr_t)lpProcName > 0xFFFF) && strcmp(lpProcName, "V2Link") == 0) {
        V2Link_old = (void*)res;
        BIND_HOOK(V2Link);
        UNBIND_HOOK(GetProcAddress);
    }
    return res;
}

static void init_patch()
{  
    if(MH_Initialize() != MH_OK) return;

    GetProcAddress_old = (void*)GetProcAddress;
    BIND_HOOK(GetProcAddress);

    size_t imagebase = winhook_getimagebase(GetCurrentProcess());
    size_t imagesize = winhook_getimagesize(GetCurrentProcess(), (HMODULE)imagebase);
    TVPCreateStream_old = winhook_searchmemory((void*)imagebase, imagesize, TVPCreateStream_sig, NULL);
    
    if(TVPCreateStream_old) {
        BIND_HOOK(TVPCreateStream);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            winversion_init();
            init_patch();
            break;
        case DLL_PROCESS_DETACH:
            MH_Uninitialize();
            break;
    }
    return TRUE;
}
