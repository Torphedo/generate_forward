#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <string.h>
#include <sys/stat.h>

#include <Windows.h>
#include <winnt.h>

uint32_t filesize(const char* filename) {
	struct stat st = {0};
	stat(filename, &st);
	return st.st_size;
}

uint8_t* read_entire_file(const char* filename) {
	uint32_t size = filesize(filename);
	// Early exit if the file doesn't exist or is 0 bytes.
	if (size == 0) {
		return NULL;
	}

	// Try to open the file.
	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		printf("Unable to open %s\n", filename);
		return NULL;
	}

	// Allocate space.
	uint8_t* file_data = calloc(1, size);
	if (file_data == NULL) {
		fclose(file);
		printf("Unable to allocate %d bytes for %s\n", size, filename);
		return NULL;
	}

	// Read data, close file, return ptr.
	fread(file_data, size, 1, file);
	fclose(file);

	printf("Read %d bytes in from %s\n", size, filename);

	return file_data;
}

void get_module_from_path(const char* filepath, char* out_name) {
	uint32_t len = strlen(filepath);
	uint32_t filename_first_char = 0;
	uint32_t filename_last_char = 0;

	// Loop backwards through the string and set ourselves up to copy from the
	// character after the first slash to the character before the first '.' 

	// For example, turn this:
	// "C:\\storage\\dev\\git\\dll_forward\\out\\MinSizeRel\\dll_forward.dll"
	// into this:
	// "dll_forward"
	for (uint32_t i = len; i > 0; i--) {
		char c = filepath[i];
		if (c == '.') {
			filename_last_char = i;
		}
		if (c == '\\' || c == '/') {
			filename_first_char = i + 1;
			break;
		}
	}

	uint32_t out_len = filename_last_char - filename_first_char;
	memcpy(out_name, filepath + filename_first_char, out_len);
}

IMAGE_SECTION_HEADER get_section_header(const char* name, uint8_t* dll_data) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)dll_data;
	IMAGE_NT_HEADERS* nt_header =  (IMAGE_NT_HEADERS*)(dll_data + dos_header->e_lfanew);
	uint32_t section_header_rva = dos_header->e_lfanew + sizeof(*nt_header);

	IMAGE_SECTION_HEADER* headers = (IMAGE_SECTION_HEADER*)(dll_data + section_header_rva);

	for (uint32_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		unsigned char* cur_name = &headers[i].Name[0];
		if (memcmp(name, cur_name, strlen(name))) {
			return headers[i];
		}
	}

	IMAGE_SECTION_HEADER failure = {0};
	return failure;
}

int main(int argc, char** argv) {
	// Parse arguments and give them variable names.
	if (argc < 3) {
		printf("Not enough arguments provided.\n");
		printf("Usage: generate_forward [output header name] [input DLL]");
		return 1;
	}
	char* output_file = argv[1];
	char* dll_path = argv[2];

	// We need our DLL name without the DLL extension or folders.
	char module[MAX_PATH] = {0};
	get_module_from_path(dll_path, module);

	// Load the DLL file into a buffer.
	uint8_t* dll = read_entire_file(dll_path);
	if (dll == NULL) {
		printf("Failed to load DLL %s\n", dll_path);
	}

	FILE* output_handle = fopen(output_file, "wb");
	if (output_handle == NULL) {
		free(dll);
		return 1;
	}

	// Basic PE header structures
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)dll;
	IMAGE_NT_HEADERS* nt_header =  (IMAGE_NT_HEADERS*)(dll + dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* data_dir = nt_header->OptionalHeader.DataDirectory;

	IMAGE_DATA_DIRECTORY* export_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (export_dir->Size == 0) {
		printf("No export section to clone, exiting.\n");
		free(dll);
		return 1;
	}
	uint32_t rva_export = export_dir->VirtualAddress;

	// Get info about text section so we can get export directory info.
	IMAGE_SECTION_HEADER text_section = get_section_header(".text", dll);
	int32_t text_offset = text_section.PointerToRawData - text_section.VirtualAddress;

	// Export directory RVA is relative to .text, so we add this offset to make
	// it relative to the image base.
	char* text_base = (char*)(dll + text_offset);

	IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(text_base + rva_export);
	uint32_t* name_off_table = (uint32_t*)(text_base + exports->AddressOfNames);
	uint32_t count = exports->NumberOfNames;

	// Loop through all the exported names.
	for (uint32_t i = 0; i < count; i++) {
		char* name = (char*)(text_base + name_off_table[i]);
		fprintf(output_handle, "#pragma comment(linker,\"/export:%s=%s.%s\")\n", name, module, name);
	}

	fclose(output_handle);
	free(dll);
	printf("Done. Generated forward exports for %d functions in module \"%s\"\n", count, module);
}

