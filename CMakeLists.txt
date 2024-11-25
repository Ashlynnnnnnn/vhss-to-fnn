cmake_minimum_required(VERSION 3.13)
project(2k_power_residue_symbols C)

set(CMAKE_C_STANDARD 99)


# Headers dir
include_directories(src/include)

# Demo
add_executable(
        2k-prs-demo
        # sources
        src/demo.c

        # utils
        src/utils/lib-mesg.c
        src/utils/lib-timing.c
        src/utils/lib-misc.c

        # lib sources
        src/lib/lib-2k-prs.c)


# Linking libraries
# - GMP
# - Math
# - Pbc
target_link_libraries(2k-prs gmp m pbc)
target_link_libraries(2k-prs-test gmp m pbc)
target_link_libraries(2k-prs-demo gmp m pbc)