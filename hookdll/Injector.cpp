#include "pch.h"
#include <windows.h>
#include <iostream>
#include "hooking.h"

#pragma comment(lib, "Ws2_32.lib")

SOCKET g_SocketHandle = INVALID_SOCKET;  // 전역 변수로 소켓 핸들을 저장

// 원래 send 및 WSARecv 함수 포인터 초기화
int (WINAPI* RealSend)(SOCKET s, const char* buf, int len, int flags) = send;
int (WINAPI* RealWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecv;

// 후킹된 send 함수
int WINAPI HookedSend(SOCKET s, const char* buf, int len, int flags) {
    std::cout << "후킹된 send() 호출됨: ";
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << (unsigned int)(unsigned char)buf[i] << " ";
    }
    std::cout << std::endl;
    return RealSend(s, buf, len, flags);  // 원래 send 함수 호출
}

// 후킹된 WSARecv 함수
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (g_SocketHandle == INVALID_SOCKET) {
        g_SocketHandle = s;  // 첫 번째 패킷 수신 시 소켓 핸들 저장
        std::cout << "소켓 핸들 저장: " << g_SocketHandle << std::endl;
    }

    // 원래의 WSARecv 호출
    int result = RealWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

    
    std::cout << "후킹된 WSARecv() 호출됨: ";
    for (DWORD i = 0; i < *lpNumberOfBytesRecvd; ++i)
    {
        std::cout << std::hex << (unsigned int)(unsigned char)lpBuffers[0].buf[i] << " ";
    }
    std::cout << std::endl;
    
    return result;
}
// 소켓 핸들을 반환하는 함수 (이미 후킹된 소켓을 반환)
extern "C" __declspec(dllexport) SOCKET GetSocketHandle() {
    return g_SocketHandle;  // g_SocketHandle은 후킹된 WSARecv에서 설정된 소켓 핸들
}

    extern "C" __declspec(dllexport) void HandlePacketFromCSharp(const char* packet, int length, bool isSend) {
        SOCKET socket = GetSocketHandle();  // 후킹된 WSARecv에서 얻은 소켓 핸들을 사용
        std::cout << "C#에서 호출됨: 패킷 데이터 = ";
        for (int i = 0; i < length; ++i) {
            std::cout << std::hex << (unsigned int)(unsigned char)packet[i] << " ";
        }
        std::cout << std::endl;

        if (isSend) {
            std::cout << "send()로 패킷 전송..." << std::endl;
            HookedSend(socket, packet, length, 0);  // 가상 소켓을 사용하여 패킷 전송
        }
        else {
            std::cout << "WSARecv()로 패킷 수신..." << std::endl;
            WSABUF buffer;
            buffer.buf = (char*)packet;
            buffer.len = length;
            DWORD numberOfBytesReceived = length;
            DWORD flags = 0;
            HookedWSARecv(socket, &buffer, 1, &numberOfBytesReceived, &flags, nullptr, nullptr);  // 가상 소켓을 사용하여 패킷 수신
        }
    }

// 후킹 설정 함수
void EnsureHooking() {
    std::cout << "후킹 설정 중..." << std::endl;

    // Detour Attachments 설정
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)RealSend, HookedSend);
    DetourAttach(&(PVOID&)RealWSARecv, HookedWSARecv);

    DetourTransactionCommit();
    std::cout << "후킹 설정 완료." << std::endl;
}

// DllMain: DLL이 로드될 때 호출되는 진입점 함수
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AllocConsole();  // 콘솔 창 활성화
        FILE* filePtr;
        freopen_s(&filePtr, "CONOUT$", "w", stdout);  // 파일 포인터 변수를 사용하여 경고 해결
        std::cout << "DLL이 로드되었습니다. 후킹을 시작합니다." << std::endl;

        EnsureHooking();  // 후킹 설정
        break;

    case DLL_PROCESS_DETACH:
        std::cout << "DLL이 해제되었습니다." << std::endl;
        break;

    default:
        break;
    }
    return TRUE;  // DLL이 성공적으로 로드됨
}
