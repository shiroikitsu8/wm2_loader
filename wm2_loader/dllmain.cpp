#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <MinHook.h>
#include <vector>

void __stdcall jmp_SetNetworkMode(int mode) {
    (void)mode; // 1 = recv 2 = send
}

_declspec(naked) void jmp_SendNetworkPackets(/*void* a1, uint8_t* data*/) {
    __asm {
        ret 0x04
    }
}

_declspec(naked) void jmp_RecvNetworkPackets(/*void* a1, uint8_t* data, uint8_t a3*/) {
    __asm {
        mov eax, 1 // Report as invalid checksum (for now)
        ret 0x08
    }
}

void Patch(void* address, std::vector<uint8_t> data)
{
    memcpy(address, data.data(), data.size());
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        if (*(uint32_t*)0x55c80 != 69485707) // simple check if v322
            break;

        MH_Initialize();

        // Network
        MH_CreateHook((void*)0x55c80, jmp_SetNetworkMode, NULL);
        MH_CreateHook((void*)0x55ca0, jmp_SendNetworkPackets, NULL);
        MH_CreateHook((void*)0x55d50, jmp_RecvNetworkPackets, NULL);

        // Disable mediaboard type 3 check
        Patch((void*)0x11edb8, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
        Patch((void*)0x11edda, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });

        MH_EnableHook(NULL);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

