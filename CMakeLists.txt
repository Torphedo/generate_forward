cmake_minimum_required(VERSION 3.16)
project(generate_forward
	VERSION 1.0.0
	LANGUAGES C
)

set(CMAKE_C_STANDARD 99) # Our code is C99
set(CMAKE_SHARED_LIBRARY_PREFIX "") # Remove "lib" prefix from the output filename
# if (MSVC)
#	 # Statically link C runtime.
#	 set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# endif()

add_executable(generate_forward
	"src/main.c"
)
