# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/software/software/CMake/3.16.4-GCCcore-9.3.0/bin/cmake

# The command to remove a file.
RM = /opt/software/software/CMake/3.16.4-GCCcore-9.3.0/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /homes/mschwinn/OSProject3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /homes/mschwinn/OSProject3/build

# Include any dependencies generated for this target.
include CMakeFiles/block_store.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/block_store.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/block_store.dir/flags.make

CMakeFiles/block_store.dir/src/block_store.c.o: CMakeFiles/block_store.dir/flags.make
CMakeFiles/block_store.dir/src/block_store.c.o: ../src/block_store.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/homes/mschwinn/OSProject3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/block_store.dir/src/block_store.c.o"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/block_store.dir/src/block_store.c.o   -c /homes/mschwinn/OSProject3/src/block_store.c

CMakeFiles/block_store.dir/src/block_store.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/block_store.dir/src/block_store.c.i"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /homes/mschwinn/OSProject3/src/block_store.c > CMakeFiles/block_store.dir/src/block_store.c.i

CMakeFiles/block_store.dir/src/block_store.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/block_store.dir/src/block_store.c.s"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /homes/mschwinn/OSProject3/src/block_store.c -o CMakeFiles/block_store.dir/src/block_store.c.s

CMakeFiles/block_store.dir/src/bitmap.c.o: CMakeFiles/block_store.dir/flags.make
CMakeFiles/block_store.dir/src/bitmap.c.o: ../src/bitmap.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/homes/mschwinn/OSProject3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/block_store.dir/src/bitmap.c.o"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/block_store.dir/src/bitmap.c.o   -c /homes/mschwinn/OSProject3/src/bitmap.c

CMakeFiles/block_store.dir/src/bitmap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/block_store.dir/src/bitmap.c.i"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /homes/mschwinn/OSProject3/src/bitmap.c > CMakeFiles/block_store.dir/src/bitmap.c.i

CMakeFiles/block_store.dir/src/bitmap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/block_store.dir/src/bitmap.c.s"
	/opt/software/software/GCCcore/9.3.0/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /homes/mschwinn/OSProject3/src/bitmap.c -o CMakeFiles/block_store.dir/src/bitmap.c.s

# Object files for target block_store
block_store_OBJECTS = \
"CMakeFiles/block_store.dir/src/block_store.c.o" \
"CMakeFiles/block_store.dir/src/bitmap.c.o"

# External object files for target block_store
block_store_EXTERNAL_OBJECTS =

libblock_store.so: CMakeFiles/block_store.dir/src/block_store.c.o
libblock_store.so: CMakeFiles/block_store.dir/src/bitmap.c.o
libblock_store.so: CMakeFiles/block_store.dir/build.make
libblock_store.so: CMakeFiles/block_store.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/homes/mschwinn/OSProject3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C shared library libblock_store.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/block_store.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/block_store.dir/build: libblock_store.so

.PHONY : CMakeFiles/block_store.dir/build

CMakeFiles/block_store.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/block_store.dir/cmake_clean.cmake
.PHONY : CMakeFiles/block_store.dir/clean

CMakeFiles/block_store.dir/depend:
	cd /homes/mschwinn/OSProject3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /homes/mschwinn/OSProject3 /homes/mschwinn/OSProject3 /homes/mschwinn/OSProject3/build /homes/mschwinn/OSProject3/build /homes/mschwinn/OSProject3/build/CMakeFiles/block_store.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/block_store.dir/depend

