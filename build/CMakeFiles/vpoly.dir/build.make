# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_SOURCE_DIR = /home/ashlynsun/vhss-to-fnn

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ashlynsun/vhss-to-fnn/build

# Include any dependencies generated for this target.
include CMakeFiles/vpoly.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/vpoly.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/vpoly.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/vpoly.dir/flags.make

CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o: CMakeFiles/vpoly.dir/flags.make
CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o: ../src/poly_vri/vpoly.c
CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o: CMakeFiles/vpoly.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ashlynsun/vhss-to-fnn/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o -MF CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o.d -o CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o -c /home/ashlynsun/vhss-to-fnn/src/poly_vri/vpoly.c

CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ashlynsun/vhss-to-fnn/src/poly_vri/vpoly.c > CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.i

CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ashlynsun/vhss-to-fnn/src/poly_vri/vpoly.c -o CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.s

# Object files for target vpoly
vpoly_OBJECTS = \
"CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o"

# External object files for target vpoly
vpoly_EXTERNAL_OBJECTS =

libvpoly.a: CMakeFiles/vpoly.dir/src/poly_vri/vpoly.c.o
libvpoly.a: CMakeFiles/vpoly.dir/build.make
libvpoly.a: CMakeFiles/vpoly.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ashlynsun/vhss-to-fnn/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libvpoly.a"
	$(CMAKE_COMMAND) -P CMakeFiles/vpoly.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/vpoly.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/vpoly.dir/build: libvpoly.a
.PHONY : CMakeFiles/vpoly.dir/build

CMakeFiles/vpoly.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/vpoly.dir/cmake_clean.cmake
.PHONY : CMakeFiles/vpoly.dir/clean

CMakeFiles/vpoly.dir/depend:
	cd /home/ashlynsun/vhss-to-fnn/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ashlynsun/vhss-to-fnn /home/ashlynsun/vhss-to-fnn /home/ashlynsun/vhss-to-fnn/build /home/ashlynsun/vhss-to-fnn/build /home/ashlynsun/vhss-to-fnn/build/CMakeFiles/vpoly.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/vpoly.dir/depend

