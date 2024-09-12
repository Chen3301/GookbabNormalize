#ifndef HOOKING_H
#define HOOKING_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

// 원래 send 및 WSARecv 함수 포인터
extern int (WINAPI* RealSend)(SOCKET s, const char* buf, int len, int flags);
extern int (WINAPI* RealWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// 후킹된 send 및 WSARecv 함수 선언
int WINAPI HookedSend(SOCKET s, const char* buf, int len, int flags);
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// 후킹 설정 함수
void EnsureHooking();

// 외부에서 호출되는 함수
extern "C" __declspec(dllexport) void HandlePacketFromCSharp(const char* packet, int length, bool isSend);
extern "C" __declspec(dllexport) SOCKET GetSocketHandle();

#endif // HOOKING_H