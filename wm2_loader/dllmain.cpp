#include <winsock.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <MinHook.h>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <toml.hpp>

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
        while (true) {
            char buf[2048] = { 0 };
            int size = recv(s, (char*)buf, sizeof(buf), 0);
            if (size < 0)
                break;
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

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        if (*(uint32_t*)0x55c80 != 69485707) // simple check if v322
            break;

        toml::table config;
        try
        {
            config = toml::parse_file("config.toml");
        }
        catch (const toml::parse_error& err)
        {
            printf("Error parsing config.toml: %s\n", err.what());
        }

        if (config["network"].is_table())
        {
            auto configNetwork = config["network"];
            if (configNetwork["enabled"].is_boolean() && configNetwork["enabled"].as_boolean()->get() && configNetwork["local_ip"].is_string()) {
                std::thread net(networkThread, configNetwork["local_ip"].as_string()->get());
                net.detach();
            }
        }

        MH_Initialize();

        // Network
        Patch((void*)0x55c80, { 0xc2, 0x04, 0x00 }); // ret 4
        MH_CreateHook((void*)0x11a9c0, jmp_MbSendPacket, NULL);
        MH_CreateHook((void*)0x11a8b0, jmp_MbRecvPacket, NULL);

        // Link OK
        Patch((void*)0x11abd0, { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 }); // mov eax, 1 - ret 12
        Patch((void*)0x5672a, { 0xB8, 0x01, 0x00, 0x00, 0x00 }); // mov eax, 1
        Patch((void*)0x5673c, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // mov eax, 0

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

