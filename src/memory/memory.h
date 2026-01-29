#pragma once
#include <string>
#include <cstdint>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

namespace reblox::memory {
	using PE32 = PROCESSENTRY32W;
	using ME32 = MODULEENTRY32W;

	struct {
		HANDLE proc;
		std::int32_t pid;
		std::uint64_t process_base;
	} inline state;

	inline auto get_processes( void ) -> std::vector<PE32> {
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		std::vector<PE32> ret;

		PE32 process_entry{};
		process_entry.dwSize = sizeof(PE32);

		if (!Process32First(snapshot, &process_entry)) goto cleanup;
		do {
			ret.push_back(process_entry);
		} while (Process32Next(snapshot, &process_entry));

	cleanup:
		CloseHandle(snapshot);
		return ret;
	}

	inline auto get_pid( std::wstring str ) -> std::int32_t {
		for (auto& process : get_processes()) {
			if (str == process.szExeFile) {
				return static_cast<std::int32_t>(process.th32ProcessID);
			}
		}

		return 0;
	}

	inline auto open_process( std::int32_t pid ) -> HANDLE {
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, static_cast<DWORD>(pid));
	}


	inline auto get_module_base(std::wstring mod) -> std::uint64_t {
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, state.pid);
		std::uint64_t ret = 0;

		MODULEENTRY32W module_entry{};
		module_entry.dwSize = sizeof(MODULEENTRY32W);

		if (!Module32First(snapshot, &module_entry)) goto cleanup;
		do {
			if (mod == module_entry.szModule) {
				ret = reinterpret_cast<std::uint64_t>(module_entry.modBaseAddr);
				goto cleanup;
			}
		} while (Module32Next(snapshot, &module_entry));

	cleanup:
		CloseHandle(snapshot);
		return ret;
	}

	inline auto attach_to_process(std::wstring process_name) -> bool {
		DWORD pid = get_pid(process_name);
		state.pid = static_cast<std::int32_t>(pid);
		state.proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (state.proc == nullptr) return false;

		state.process_base = get_module_base(process_name);
		return state.process_base != 0;
	}

	// UD Trust
	std::string WStringToString(const std::wstring& wstr) {
		if (wstr.empty()) return std::string();
		int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
		std::string strTo(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
		return strTo;
	}
}
