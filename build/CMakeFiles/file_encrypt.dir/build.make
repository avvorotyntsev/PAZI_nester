# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/vboxuser/nester

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/vboxuser/nester/build

# Include any dependencies generated for this target.
include CMakeFiles/file_encrypt.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/file_encrypt.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/file_encrypt.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/file_encrypt.dir/flags.make

CMakeFiles/file_encrypt.dir/main.cpp.o: CMakeFiles/file_encrypt.dir/flags.make
CMakeFiles/file_encrypt.dir/main.cpp.o: /home/vboxuser/nester/main.cpp
CMakeFiles/file_encrypt.dir/main.cpp.o: CMakeFiles/file_encrypt.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/vboxuser/nester/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/file_encrypt.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/file_encrypt.dir/main.cpp.o -MF CMakeFiles/file_encrypt.dir/main.cpp.o.d -o CMakeFiles/file_encrypt.dir/main.cpp.o -c /home/vboxuser/nester/main.cpp

CMakeFiles/file_encrypt.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/file_encrypt.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vboxuser/nester/main.cpp > CMakeFiles/file_encrypt.dir/main.cpp.i

CMakeFiles/file_encrypt.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/file_encrypt.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vboxuser/nester/main.cpp -o CMakeFiles/file_encrypt.dir/main.cpp.s

# Object files for target file_encrypt
file_encrypt_OBJECTS = \
"CMakeFiles/file_encrypt.dir/main.cpp.o"

# External object files for target file_encrypt
file_encrypt_EXTERNAL_OBJECTS =

file_encrypt: CMakeFiles/file_encrypt.dir/main.cpp.o
file_encrypt: CMakeFiles/file_encrypt.dir/build.make
file_encrypt: /usr/lib/x86_64-linux-gnu/libcrypto.so
file_encrypt: CMakeFiles/file_encrypt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/vboxuser/nester/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable file_encrypt"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/file_encrypt.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/file_encrypt.dir/build: file_encrypt
.PHONY : CMakeFiles/file_encrypt.dir/build

CMakeFiles/file_encrypt.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/file_encrypt.dir/cmake_clean.cmake
.PHONY : CMakeFiles/file_encrypt.dir/clean

CMakeFiles/file_encrypt.dir/depend:
	cd /home/vboxuser/nester/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/vboxuser/nester /home/vboxuser/nester /home/vboxuser/nester/build /home/vboxuser/nester/build /home/vboxuser/nester/build/CMakeFiles/file_encrypt.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/file_encrypt.dir/depend

