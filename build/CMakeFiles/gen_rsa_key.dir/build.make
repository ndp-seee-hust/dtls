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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ndp/Documents/dtls

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ndp/Documents/dtls/build

# Include any dependencies generated for this target.
include CMakeFiles/gen_rsa_key.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/gen_rsa_key.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/gen_rsa_key.dir/flags.make

CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o: CMakeFiles/gen_rsa_key.dir/flags.make
CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o: ../test/gen_rsa_key.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ndp/Documents/dtls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o   -c /home/ndp/Documents/dtls/test/gen_rsa_key.c

CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ndp/Documents/dtls/test/gen_rsa_key.c > CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.i

CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ndp/Documents/dtls/test/gen_rsa_key.c -o CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.s

# Object files for target gen_rsa_key
gen_rsa_key_OBJECTS = \
"CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o"

# External object files for target gen_rsa_key
gen_rsa_key_EXTERNAL_OBJECTS =

gen_rsa_key: CMakeFiles/gen_rsa_key.dir/test/gen_rsa_key.c.o
gen_rsa_key: CMakeFiles/gen_rsa_key.dir/build.make
gen_rsa_key: ../libmbedtls/libmbedx509.a
gen_rsa_key: ../libmbedtls/libmbedtls.a
gen_rsa_key: ../libmbedtls/libmbedcrypto.a
gen_rsa_key: CMakeFiles/gen_rsa_key.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ndp/Documents/dtls/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable gen_rsa_key"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gen_rsa_key.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/gen_rsa_key.dir/build: gen_rsa_key

.PHONY : CMakeFiles/gen_rsa_key.dir/build

CMakeFiles/gen_rsa_key.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/gen_rsa_key.dir/cmake_clean.cmake
.PHONY : CMakeFiles/gen_rsa_key.dir/clean

CMakeFiles/gen_rsa_key.dir/depend:
	cd /home/ndp/Documents/dtls/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ndp/Documents/dtls /home/ndp/Documents/dtls /home/ndp/Documents/dtls/build /home/ndp/Documents/dtls/build /home/ndp/Documents/dtls/build/CMakeFiles/gen_rsa_key.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/gen_rsa_key.dir/depend

