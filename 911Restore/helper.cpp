#include "pch.h"
#include "helper.hpp"

// from MGSHDFix

namespace Memory
{
    void PatchBytes(uintptr_t address, const char* pattern, unsigned int numBytes)
    {
        DWORD oldProtect;
        VirtualProtect((LPVOID)address, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((LPVOID)address, pattern, numBytes);
        VirtualProtect((LPVOID)address, numBytes, oldProtect, &oldProtect);
    }

    static HMODULE GetThisDllHandle()
    {
        MEMORY_BASIC_INFORMATION info;
        size_t len = VirtualQueryEx(GetCurrentProcess(), (void*)GetThisDllHandle, &info, sizeof(info));
        assert(len == sizeof(info));
        return len ? (HMODULE)info.AllocationBase : NULL;
    }

    // CSGOSimple's pattern scan
    // https://github.com/OneshotGH/CSGOSimple-master/blob/master/CSGOSimple/helpers/utils.cpp
    std::uint8_t* PatternScan(void* module, const char* signature)
    {
        static auto pattern_to_byte = [](const char* pattern) {
            auto bytes = std::vector<int>{};
            auto start = const_cast<char*>(pattern);
            auto end = const_cast<char*>(pattern) + strlen(pattern);

            for (auto current = start; current < end; ++current) {
                if (*current == '?') {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }
            return bytes;
            };

        auto dosHeader = (PIMAGE_DOS_HEADER)module;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

        auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto patternBytes = pattern_to_byte(signature);
        auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

        auto s = patternBytes.size();
        auto d = patternBytes.data();

        for (auto i = 0ul; i < sizeOfImage - s; ++i) {
            bool found = true;
            for (auto j = 0ul; j < s; ++j) {
                if (scanBytes[i + j] != d[j] && d[j] != -1) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return &scanBytes[i];
            }
        }
        return nullptr;
    }

    uintptr_t GetAbsolute(uintptr_t address) noexcept
    {
        return (address + 4 + *reinterpret_cast<std::int32_t*>(address));
    }

    uintptr_t GetRelativeOffset(uint8_t* addr) noexcept
    {
        return reinterpret_cast<uintptr_t>(addr) + 4 + *reinterpret_cast<int32_t*>(addr);
    }

    BOOL HookIAT(HMODULE callerModule, char const* targetModule, const void* targetFunction, void* detourFunction)
    {
        auto* base = (uint8_t*)callerModule;
        const auto* dos_header = (IMAGE_DOS_HEADER*)base;
        const auto nt_headers = (IMAGE_NT_HEADERS*)(base + dos_header->e_lfanew);
        const auto* imports = (IMAGE_IMPORT_DESCRIPTOR*)(base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (int i = 0; imports[i].Characteristics; i++)
        {
            const char* name = (const char*)(base + imports[i].Name);
            if (lstrcmpiA(name, targetModule) != 0)
                continue;

            void** thunk = (void**)(base + imports[i].FirstThunk);

            for (; *thunk; thunk++)
            {
                const void* import = *thunk;

                if (import != targetFunction)
                    continue;

                DWORD oldState;
                if (!VirtualProtect(thunk, sizeof(void*), PAGE_READWRITE, &oldState))
                    return FALSE;

                *thunk = detourFunction;

                VirtualProtect(thunk, sizeof(void*), oldState, &oldState);

                return TRUE;
            }
        }
        return FALSE;
    }
    // Read the current IAT entry (without changing it)
    void* ReadIAT(HMODULE callerModule, const char* targetModule, const char* targetFunction)
    {
        uint8_t* base = reinterpret_cast<uint8_t*>(callerModule);
        auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
        auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (int i = 0; imports[i].Characteristics; ++i)
        {
            const char* dllName = reinterpret_cast<const char*>(base + imports[i].Name);
            if (_stricmp(dllName, targetModule) != 0)
                continue;

            auto origFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports[i].OriginalFirstThunk);
            auto firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports[i].FirstThunk);

            for (; origFirstThunk->u1.AddressOfData; ++origFirstThunk, ++firstThunk)
            {
                auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origFirstThunk->u1.AddressOfData);
                if (strcmp(reinterpret_cast<const char*>(importByName->Name), targetFunction) != 0)
                    continue;

                return reinterpret_cast<void*>(firstThunk->u1.Function);
            }
        }

        return nullptr;
    }

    // Write a new pointer into the IAT entry (unconditionally)
    BOOL WriteIAT(HMODULE callerModule, const char* targetModule, const char* targetFunction, void* detourFunction)
    {
        uint8_t* base = reinterpret_cast<uint8_t*>(callerModule);
        auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
        auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (int i = 0; imports[i].Characteristics; ++i)
        {
            const char* dllName = reinterpret_cast<const char*>(base + imports[i].Name);
            if (_stricmp(dllName, targetModule) != 0)
                continue;

            auto origFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports[i].OriginalFirstThunk);
            auto firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports[i].FirstThunk);

            for (; origFirstThunk->u1.AddressOfData; ++origFirstThunk, ++firstThunk)
            {
                auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origFirstThunk->u1.AddressOfData);
                if (strcmp(reinterpret_cast<const char*>(importByName->Name), targetFunction) != 0)
                    continue;

                DWORD oldProtect;
                if (!VirtualProtect(&firstThunk->u1.Function, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect))
                    return FALSE;

                firstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(detourFunction);

                VirtualProtect(&firstThunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);

                return TRUE;
            }
        }

        return FALSE;
    }

}
