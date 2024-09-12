#ifndef HOOKING_H
#define HOOKING_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

// ���� send �� WSARecv �Լ� ������
extern int (WINAPI* RealSend)(SOCKET s, const char* buf, int len, int flags);
extern int (WINAPI* RealWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// ��ŷ�� send �� WSARecv �Լ� ����
int WINAPI HookedSend(SOCKET s, const char* buf, int len, int flags);
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// ��ŷ ���� �Լ�
void EnsureHooking();

// �ܺο��� ȣ��Ǵ� �Լ�
extern "C" __declspec(dllexport) void HandlePacketFromCSharp(const char* packet, int length, bool isSend);
extern "C" __declspec(dllexport) SOCKET GetSocketHandle();

#endif // HOOKING_H