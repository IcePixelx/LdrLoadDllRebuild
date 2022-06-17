#include <iostream>
#include <vector>
#include "Windows.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

std::uint8_t* PatternScan(void* module, const char* signature)
{
	static auto PatternToBytes = [](const std::string pattern)
	{
		char* pattern_start = const_cast<char*>(pattern.c_str()); // Cast const away and get start of pattern.
		char* pattern_end = pattern_start + std::strlen(pattern.c_str()); // Get end of pattern.

		std::vector<std::int32_t> bytes = std::vector<std::int32_t>{ }; // Initialize byte vector.

		for (char* current_byte = pattern_start; current_byte < pattern_end; ++current_byte)
		{
			if (*current_byte == '?') // Is current char(byte) a wildcard?
			{
				++current_byte; // Skip 1 character.

				if (*current_byte == '?') // Is it a double wildcard pattern?
					++current_byte; // If so skip the next space that will come up so we can reach the next byte.

				bytes.push_back(-1); // Push the byte back as invalid.
			}
			else
			{
				// https://stackoverflow.com/a/43860875/12541255
				// Here we convert our string to a unsigned long integer. We pass our string then we use 16 as the base because we want it as hexadecimal.
				// Afterwards we push the byte into our bytes vector.
				bytes.push_back(std::strtoul(current_byte, &current_byte, 16));
			}
		}
		return bytes;
	};

	const IMAGE_DOS_HEADER* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(module); // Get dos header.
	const IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(module) + dos_headers->e_lfanew);

	const DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	const std::vector<std::int32_t> bytes_to_scan = PatternToBytes(signature);
	std::uint8_t* start_of_code_section = reinterpret_cast<std::uint8_t*>(module);

	const std::size_t bytes_size = bytes_to_scan.size();
	const std::int32_t* bytes_data = bytes_to_scan.data();

	for (DWORD i = 0; i < size_of_image - bytes_size; ++i)
	{
		bool found_address = true;

		for (auto j = 0ul; j < bytes_size; ++j) {
			if (start_of_code_section[i + j] != bytes_data[j] && bytes_data[j] != -1)
			{
				found_address = false;
				break;
			}
		}
		if (found_address)
		{
			return &start_of_code_section[i];
		}
	}
	return nullptr;
}

typedef NTSTATUS(__fastcall* fnLdrpLoadDll)(UNICODE_STRING*, DWORD*, int, DWORD*);
typedef void(__stdcall* fnRtlInitUnicodeString)(UNICODE_STRING*, PCWSTR);

NTSTATUS LdrpLoadDll(ULONG flags, UNICODE_STRING* module_file_name, PHANDLE ptr_handle)
{
#define LoaderWorker 0x2000
#define STATUS_INVALID_THREAD 0xC000071C
#define STATUS_BUG -1

	DWORD weird_struct = NULL; // Tried reversing this but its an array for some reason.
	DWORD ldr_data_table_entry = NULL; // Loader Data Table Entry.
	NTSTATUS result = STATUS_BUG; // Return value.

	if ((*(WORD*)(__readfsdword(0x18) + 0x0FCA) & LoaderWorker) != NULL) // Is this a loaderworker thread?
	{
		result = STATUS_INVALID_THREAD; // Invalid thread status.
		return result; // Return NTSTATUS.
	}

	HMODULE nt_dll = GetModuleHandleA("ntdll.dll"); // Get ntdll module handle.
	LPVOID ldrp_load_dll = reinterpret_cast<LPVOID>(PatternScan(nt_dll, "89 84 24 ? ? ? ? 53 8B 5D 0C 56") - 0x15); // Scanning location for LdrpLoadDLL.

	result = reinterpret_cast<fnLdrpLoadDll>(ldrp_load_dll)(module_file_name, &weird_struct, flags, &ldr_data_table_entry); // Calling LdrpLoadDLL

	*ptr_handle = reinterpret_cast<HANDLE>(reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(ldr_data_table_entry)->DllBase); // For some unknown reason if you normally call this without casting it gives you ntdll.dll base address??

	return result; // Return NTSTATUS.
}

int main()
{
	HMODULE nt_dll = GetModuleHandleA("ntdll.dll"); // Get ntdll module handle.
	if (!nt_dll)
		return -1;

	fnRtlInitUnicodeString rtl_init_unicode_string = reinterpret_cast<fnRtlInitUnicodeString>(GetProcAddress(nt_dll, "RtlInitUnicodeString")); // Get RtlInitUnicodeString export from ntdll.
	if (!rtl_init_unicode_string)
		return -1;

	UNICODE_STRING dll_path; // Init UNICODE_STRING struct.
	rtl_init_unicode_string(&dll_path, L"D:\\Projects\\LdrLoadDllRebuild\\Debug\\TestDLL.dll"); // set dll path here.

	HANDLE dll_handle = INVALID_HANDLE_VALUE; // Init handle.
	NTSTATUS ldrp_load_dll_status = LdrpLoadDll(0, &dll_path, &dll_handle); // Call dummy function.

	std::cout << std::endl << "LdrpLoadDLL returned: " << ldrp_load_dll_status << std::endl << "DLL Handle is at: 0x" << std::hex << dll_handle << std::endl;

	system("pause");
	return 0;
}


