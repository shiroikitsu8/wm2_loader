#include <winsock.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include "include/MinHook.h"
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include "include/toml.hpp"
#include <cstdlib>

#pragma comment(lib, "ws2_32.lib")

void Patch(void* address, std::vector<uint8_t> data) { memcpy(address, data.data(), data.size()); }

sockaddr_in sendAddr = { 0 };
SOCKET sendSocket = INVALID_SOCKET;

std::unordered_map<uint32_t, std::vector<uint8_t>> recvBuffer = {};
std::mutex recvBufferMutex;

void networkThread(std::string address) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    sendAddr.sin_family = AF_INET;
    sendAddr.sin_addr.s_addr = inet_addr("225.0.0.1");
    sendAddr.sin_port = htons(50765);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        printf("Can't create network socket, LastError: %d\n", WSAGetLastError());
        return;
    }

    sockaddr_in bindAddr{ 0 };
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = inet_addr(address.c_str());
    bindAddr.sin_port = htons(50765);
    if (bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr)) != 0) {
        printf("Failed to bind socket, LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    int broadcast = 1;
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast)) != 0) {
        printf("Can't set broadcast LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) != 0) {
        printf("Can't set reuse address LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    int ttl = 255;
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) != 0) {
        printf("Can't change multicast ttl, LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    ip_mreq mreq{ 0 };
    mreq.imr_multiaddr.s_addr = inet_addr("225.0.0.1");
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(s, IPPROTO_IP, 12 /*IP_ADD_MEMBERSHIP*/, (char*)&mreq, sizeof(mreq)) != 0) {
        printf("Failed to add membership, LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    u_long nonBlock = 1;  // 1 to enable non-blocking socket
    if (ioctlsocket(s, FIONBIO, &nonBlock) != 0) {
        printf("Failed to set non blocking, LastError: %d\n", WSAGetLastError());

        closesocket(s);
        return;
    }

    sendSocket = s;

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        if (select(0, &readfds, NULL, NULL, NULL) < 0)
            continue;

        char buf[2048] = { 0 };
        int size = recv(s, (char*)buf, sizeof(buf), 0);
        if (size < 5)
            continue;
        uint32_t address = *(uint32_t*)buf;

        std::vector<uint8_t> data = {};
        data.resize(size - sizeof(uint32_t));
        memcpy(data.data(), buf + sizeof(uint32_t), data.size());

        recvBufferMutex.lock();
        recvBuffer[address] = data;
        recvBufferMutex.unlock();
    }
}

void __stdcall jmp_MbSendPacket(void* data, uint32_t address, int length) {
    if (sendSocket == INVALID_SOCKET)
        return;
    std::vector<uint8_t> packet = {};
    packet.resize(sizeof(uint32_t) + length);
    memcpy(packet.data(), &address, sizeof(uint32_t));
    memcpy(packet.data() + sizeof(uint32_t), data, length);
    sendto(sendSocket, (char*)packet.data(), packet.size(), 0, (sockaddr*)&sendAddr, sizeof(sendAddr));
}

int __stdcall jmp_MbRecvPacket(uint32_t address, void* data, int length) {
    if (sendSocket == INVALID_SOCKET)
        return 0;
    recvBufferMutex.lock();
    if (recvBuffer.find(address) == recvBuffer.end()) {
        recvBufferMutex.unlock();
        return 0;
    }
    std::vector<uint8_t> packet = recvBuffer[address];
    recvBuffer.erase(address);
    recvBufferMutex.unlock();
    memcpy(data, packet.data(), packet.size() > length ? length : packet.size());
    return 0;
}

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

// Probably doesn't even work at all lmao
extern "C" {
    // NVIDIA Optimus
    __declspec(dllexport) DWORD NvOptimusEnablement = 0x00000001;

    // AMD Switchable Graphics
    __declspec(dllexport) int AmdPowerXpressRequestHighPerformance = 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {

        MH_Initialize();

        // Read Config
        toml::table config;
        try
        {
            config = toml::parse_file("config.toml");
            printf("[0x6969] DEBUG: INIT    Config Loaded\n");
        }
        catch (const toml::parse_error& err)
        {
            printf("Error parsing config.toml: %s\n", err.what());
        }

        // Network
        if (config["network"].is_table())
        {
            auto configNetwork = config["network"];
            if (configNetwork["enabled"].is_boolean() && configNetwork["enabled"].as_boolean()->get() && configNetwork["local_ip"].is_string())
            {
                std::thread net(networkThread, configNetwork["local_ip"].as_string()->get());
                net.detach();
            }
        }

        // CPU Affinity
        if (config["affinity"].is_table())
        {
            HANDLE process = GetCurrentProcess();

            auto configAffinity = config["affinity"];
            if (configAffinity["enabled"].is_boolean() && configAffinity["enabled"].as_boolean()->get())
            {
                // Set CPU Affinity to CPU 0 and 1 (binary: 00000011)
                DWORD_PTR affinityMask = 0b11;

                if (SetProcessAffinityMask(process, affinityMask))
                {
                    printf("[0x6969] DEBUG: INIT    CPU Affinity set to CPU 0 and CPU 1\n");
                }
            }
            else
            {
                // Set affinity to use all available processors
                DWORD_PTR processAffinityMask;
                DWORD_PTR systemAffinityMask;

                if (GetProcessAffinityMask(process, &processAffinityMask, &systemAffinityMask))
                {
                    if (SetProcessAffinityMask(process, systemAffinityMask))
                    {
                        printf("[0x6969] DEBUG: INIT    CPU Affinity set to all available processors (0x%llX)\n", systemAffinityMask);
                    }
                }
            }
        }

        // simple check if v322 ver b
        if (*(uint32_t*)0x55C80 == 69485707)
        {
            printf("[0x6969] DEBUG: INIT    V322 ");

            // Network
            Patch((void*)0x55C80, { 0xc2, 0x04, 0x00 }); // ret 4

            // Link OK
            Patch((void*)0x5672A, { 0xB8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
            Patch((void*)0x5673C, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, 0

            // v322 exp ver b
            if (*(uint32_t*)0x11A9C0 == 2366172291)
            {
                printf("EXP Ver. B Detected!\n");

                // Network
                MH_CreateHook((void*)0x11A9C0, jmp_MbSendPacket, NULL);
                MH_CreateHook((void*)0x11A8B0, jmp_MbRecvPacket, NULL);

                // Link OK
                Patch((void*)0x11ABD0, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12

                // Disable mediaboard type 3 check
                Patch((void*)0x11EDB8, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
                Patch((void*)0x11EDDA, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            }
            // v322 jp ver b
            else if (*(uint32_t*)0x11AAB0 == 2366172291)
            {
                printf("JPN Ver. B Detected!\n");

                // Network
                MH_CreateHook((void*)0x11AAB0, jmp_MbSendPacket, NULL);
                MH_CreateHook((void*)0x11A9A0, jmp_MbRecvPacket, NULL);

                // Link OK
                Patch((void*)0x11ACC0, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12

                // Disable mediaboard type 3 check
                Patch((void*)0x11EEA8, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
                Patch((void*)0x11EECA, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            }
        }
        // simple check if v322 ver a
        else if (*(uint32_t*)0x55C10 == 69485707)
        {
            printf("[0x6969] DEBUG: INIT    V322 ");
            
            // Network
            Patch((void*)0x55C10, { 0xc2, 0x04, 0x00 }); // ret 4

            // Link OK
            Patch((void*)0x566BA, { 0xB8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
            Patch((void*)0x566CC, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, 0

            // v322 exp ver a
            if (*(uint32_t*)0x11A950 == 2366172291)
            {
                printf("EXP Ver. A Detected!\n");

                // Network
                MH_CreateHook((void*)0x11A950, jmp_MbSendPacket, NULL);
                MH_CreateHook((void*)0x11A840, jmp_MbRecvPacket, NULL);

                // Link OK
                Patch((void*)0x11AB50, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12

                // Disable mediaboard type 3 check
                Patch((void*)0x11ED38, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
                Patch((void*)0x11ED5A, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            }
            // v322 jp ver a
            else if (*(uint32_t*)0x11AB20 == 2366172291)
            {
                printf("JPN Ver. A Detected!\n");

                // Network
                MH_CreateHook((void*)0x11AB20, jmp_MbSendPacket, NULL);
                MH_CreateHook((void*)0x11AA10, jmp_MbRecvPacket, NULL);

                // Link OK
                Patch((void*)0x11AD20, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12

                // Disable mediaboard type 3 check
                Patch((void*)0x11EF08, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
                Patch((void*)0x11EF2A, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            }
        }
        // simple check if v307 exp ver a
        else if (*(uint32_t*)0x6F280 == 69485707)
        {
            printf("[0x6969] DEBUG: INIT    V307 ");
            printf("EXP Ver. A Detected!\n");

            // Network
            Patch((void*)0x6F280, { 0xc2, 0x04, 0x00 });
            MH_CreateHook((void*)0xB2B80, jmp_MbSendPacket, NULL);
            MH_CreateHook((void*)0xB2BD0, jmp_MbRecvPacket, NULL);
            /*MH_CreateHook((void*)0x6F280, jmp_SetNetworkMode, NULL);
            MH_CreateHook((void*)0x6F2A0, jmp_SendNetworkPackets, NULL);
            MH_CreateHook((void*)0x6F320, jmp_RecvNetworkPackets, NULL);*/

            // Link OK
            Patch((void*)0xB2D80, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12
            //Patch((void*)0x, { 0xB8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
            //Patch((void*)0x, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, 0

            // Disable mediaboard type 3 check
            Patch((void*)0xB6F98, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            Patch((void*)0xB6FBA, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
        }
        // simple check if v307 jp ver a
        else if (*(uint32_t*)0x6F2B0 == 69485707)
        {
            printf("[0x6969] DEBUG: INIT    V307 ");
            printf("JPN Ver. A Detected!\n");

            // Network
            Patch((void*)0x6F2B0, { 0xc2, 0x04, 0x00 });
            MH_CreateHook((void*)0xB2BB0, jmp_MbSendPacket, NULL);
            MH_CreateHook((void*)0xB2C00, jmp_MbRecvPacket, NULL);
            /*MH_CreateHook((void*)0x6F2B0, jmp_SetNetworkMode, NULL);
            MH_CreateHook((void*)0x6F2D0, jmp_SendNetworkPackets, NULL);
            MH_CreateHook((void*)0x6F350, jmp_RecvNetworkPackets, NULL);*/

            // Link OK
            Patch((void*)0xB2DB0, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12
            //Patch((void*)0x, { 0xB8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
            //Patch((void*)0x, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, 0

            // Disable mediaboard type 3 check
            Patch((void*)0xB6FC8, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
            Patch((void*)0xB6FEA, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
        }
        // unknown version
        else
        {
            printf("[0x6969] DEBUG: INIT    Unknown Version\n");
        }

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

