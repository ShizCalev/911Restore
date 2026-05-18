#pragma once
#include "pch.h"
#include <assert.h>
#include <stdint.h>
#include <vector>

inline HMODULE baseModule = GetModuleHandle(NULL);
inline bool bIsLauncher = false;

namespace Memory
{
    template<typename T>
    void Write(uintptr_t writeAddress, T value)
    {
        DWORD oldProtect;
        VirtualProtect((LPVOID)(writeAddress), sizeof(T), PAGE_EXECUTE_WRITECOPY, &oldProtect);
        *(reinterpret_cast<T*>(writeAddress)) = value;
        VirtualProtect((LPVOID)(writeAddress), sizeof(T), oldProtect, &oldProtect);
    }

    void PatchBytes(uintptr_t address, const char* pattern, unsigned int numBytes);

    static HMODULE GetThisDllHandle();

    std::uint8_t* PatternScan(void* module, const char* signature);

    uintptr_t GetAbsolute(uintptr_t address) noexcept;

    uintptr_t GetRelativeOffset(uint8_t* addr) noexcept;

    BOOL HookIAT(HMODULE callerModule, char const* targetModule, const void* targetFunction, void* detourFunction);

    void* ReadIAT(HMODULE callerModule, const char* targetModule, const char* targetFunction);
    BOOL WriteIAT(HMODULE callerModule, const char* targetModule, const char* targetFunction, void* detourFunction);
}