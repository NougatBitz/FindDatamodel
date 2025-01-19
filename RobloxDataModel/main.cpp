#include <Windows.h>
#include <DbgHelp.h>

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <filesystem>
#include <regex>

#pragma comment(lib, "dbghelp.lib")

#include <wincpp/process.hpp>

using namespace wincpp;

struct RTTICompleteObjectLocator {
	DWORD signature;
	DWORD offset;
	DWORD cdOffset;
	DWORD typeDescriptor;
	DWORD classDescriptor;
	DWORD baseOffset;
};

struct TypeDescriptor {
	void* vtable;
	uint64_t ptr;
	char name[255];
};

static std::optional<std::string> getLatestLogFile(const std::string& folderPath) {
	std::optional<std::string> latestFile;
	std::filesystem::file_time_type latestTime;

	try {
		for (const auto& entry : std::filesystem::directory_iterator(folderPath)) {
			if (entry.is_regular_file() && entry.path().extension() == ".log") {
				auto currentFileTime = std::filesystem::last_write_time(entry);

				if (!latestFile || currentFileTime > latestTime) {
					latestFile = entry.path().string();
					latestTime = currentFileTime;
				}
			}
		}
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return std::nullopt;
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return std::nullopt;
	}

	return latestFile;
}

static std::string readFile(const std::string& filePath) {
	std::ifstream file(filePath);
	if (!file) {
		std::cerr << "Error opening file: " << filePath << std::endl;
		return "";
	}

	std::ostringstream oss;
	oss << file.rdbuf();
	return oss.str();
}

static uintptr_t locateTid(const std::string& content) {
	std::regex pattern(R"(::replaceDataModel: \(stage:\d+, window = 0x[a-zA-Z\d]+\) \[tid:(0x[a-zA-Z\d]+)\])");

	std::smatch matches;
	std::string::const_iterator searchStart(content.cbegin());

	uintptr_t result = 0;
	while (std::regex_search(searchStart, content.cend(), matches, pattern)) {
		std::cout << "Found match: " << matches[0] << std::endl;
		result = std::stoull(matches[1], nullptr, 16);
		searchStart = matches.suffix().first;
	}

	return result;
}

static std::string demangleSymbol(const std::string& kMangledName) {
	std::string demangledName = std::string(1024, '\0');
	std::string mangledName = kMangledName;

	if (mangledName.starts_with(".?AV")) {
		mangledName = "?" + mangledName.substr(4);
	}

	DWORD Length = UnDecorateSymbolName(mangledName.c_str(), demangledName.data(), demangledName.capacity(), UNDNAME_COMPLETE);
	if (!Length) {
		return mangledName;
	}
	demangledName.resize(Length);

	if (demangledName.starts_with(" ??")) {
		demangledName = demangledName.substr(4);
	}

	return demangledName;
}

static uintptr_t getModuleContaining(std::unique_ptr<process_t>& process, uintptr_t address) {
	for (auto& module : process->module_factory.modules()) {
		if (module->contains(address)) {
			return module->address();
		}
	}
	return 0;
}

static bool isValidAddress(std::unique_ptr<process_t>& process, uintptr_t address) {
	auto buffer = process->memory_factory.read(address, 0x1);
	if (buffer == nullptr) {
		return false;
	}
	return true;
}

static std::optional<std::string> getRTTIName(std::unique_ptr<process_t>& process, uintptr_t objectAddress) {
	uintptr_t vtableAddress = process->memory_factory.read<uintptr_t>(objectAddress);
	if (!vtableAddress) {
		return std::nullopt;
	}

	if (!isValidAddress(process, vtableAddress - sizeof(uintptr_t))) {
		return std::nullopt;
	}

	uintptr_t colAddress = process->memory_factory.read<uintptr_t>(vtableAddress - sizeof(uintptr_t));
	if (!colAddress) {
		return std::nullopt;
	}

	if (!isValidAddress(process, colAddress)) {
		return std::nullopt;
	}

	RTTICompleteObjectLocator col = process->memory_factory.read<RTTICompleteObjectLocator>(colAddress);
	uintptr_t TypeInfoAddress = 0;
	TypeInfoAddress = col.typeDescriptor;
	TypeInfoAddress += getModuleContaining(process, colAddress);


	if (!isValidAddress(process, TypeInfoAddress)) {
		return std::nullopt;
	}

	TypeDescriptor typeInfo = process->memory_factory.read<TypeDescriptor>(TypeInfoAddress);
	return demangleSymbol(typeInfo.name);
}

static void disableWorkingSetDetection(std::unique_ptr<process_t>& process) {
	std::optional<std::uintptr_t> watched_memory_pool;

	do
	{
		for (const auto& region : process->memory_factory.regions())
		{
			// Skip regions that aren't private or committed.
			if (region.type() != memory::region_t::type_t::private_t || region.state() != memory::region_t::state_t::commit_t)
				continue;

			// The watched memory pool has read & write protections and a fixed size.
			if (region.protection() == memory::protection_flags_t::readwrite && region.size() == 0x200000) {
				std::printf("[info] Found watched memory pool 0x%llx, %d bytes\n", region.address(), region.size());
				watched_memory_pool = region.address();
				break;
			}
		}

		if (!watched_memory_pool)
			std::this_thread::sleep_for(std::chrono::milliseconds(100));

	} while (!watched_memory_pool);


	process->memory_factory.write<std::uintptr_t>(*watched_memory_pool + 0x208, 0x20);
}

static void recursivePointerWalk(std::unique_ptr<process_t>& process, uintptr_t address, size_t maxOffset, std::function<bool(uintptr_t, uintptr_t)> callback, std::optional<std::unordered_set<uintptr_t>> _cache, uintptr_t depth = 0) {
	std::unordered_set<uintptr_t> cache = _cache.value_or(std::unordered_set<uintptr_t>());
	
	if (cache.contains(address)) {
		return;
	}

	for (size_t offset = 0; offset < maxOffset; offset += 8) {
		if (!isValidAddress(process, address + offset)) {
			continue;
		}

		uintptr_t pointer = process->memory_factory.read<uintptr_t>(address + offset);

		if (!isValidAddress(process, pointer)) {
			continue;
		}

		if (!callback(pointer, depth)) {
			return;
		}

		recursivePointerWalk(process, pointer, 0x200, callback, cache, depth + 1);

		cache.emplace(pointer);
	}
}

static uintptr_t getFirstAncestor(std::unique_ptr<process_t>& process, uintptr_t address) {
	uintptr_t previousObject = 0;
	uintptr_t currentObject = process->memory_factory.read<uintptr_t>(address + 0x50);

	while (currentObject != 0) {
		previousObject = currentObject;
		currentObject = process->memory_factory.read<uintptr_t>(currentObject + 0x50);
	}

	return previousObject;
}

static uintptr_t findDatamodelPointer(std::unique_ptr<process_t>& process, uintptr_t tid) {
	uintptr_t dataModel = 0;

	recursivePointerWalk(process, tid, 22160, [&](uintptr_t address, uintptr_t depth) -> bool {
		if (dataModel) {
			// i cba to make this use a global state or anything
			return false;
		}

		auto rttiName = getRTTIName(process, address);
		if (rttiName.has_value()) {
			std::string& name = rttiName.value();

			if (name == "RBX::ModuleScript" || name == "RBX::LocalScript" || name == "RBX::Folder") {
				uintptr_t ancestor = getFirstAncestor(process, address);

				auto ancestorRtti = getRTTIName(process, ancestor);
				if (!ancestorRtti.has_value()) {
					return true;
				}

				printf("%s %s\n", name.c_str(), ancestorRtti.value().c_str());
				if (ancestorRtti.value() == "RBX::DataModel") {
					dataModel = ancestor;
					return false;
				}
			}
		}

		return (depth <= 5);
	}, std::nullopt);

	if (!dataModel) {
		return findDatamodelPointer(process, tid);
	}

	return dataModel;
}

static std::string logPath = std::string(getenv("LOCALAPPDATA")) + "\\Roblox\\logs";

int main() {
	std::unique_ptr<process_t> process = nullptr;
	do {
		process = process_t::open("RobloxPlayerBeta.exe");

		if (!process) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	} while (!process);

	std::optional<std::string> logFile = getLatestLogFile(logPath);
	if (!logFile.has_value()) {
		std::cerr << "Coudln't find latest log file" << std::endl;
		return 1;
	}

	uintptr_t tid = locateTid(readFile(logFile.value()));
	if (!tid) {
		std::cerr << "Coudln't find tid" << std::endl;
		return 1;
	}

	disableWorkingSetDetection(process);

	uintptr_t datamodelPointer = findDatamodelPointer(process, tid);
	printf("datamodel: %llx\n", datamodelPointer);

	return 0;
} 
