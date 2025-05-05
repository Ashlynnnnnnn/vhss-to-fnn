cmake_minimum_required(VERSION 3.13)
project(vhss-to-fnn C)

set(CMAKE_C_STANDARD 99)

find_package(RELIC REQUIRED)

# Headers dir
include_directories(src/include)

# LMS18 Demo
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

# Original Model
add_executable(
        original
        # sources
        src/process/original.c

        # utils
        src/utils/lib-mesg.c
        src/utils/lib-timing.c
        src/utils/lib-misc.c

        # lib sources
        src/lib/lib-2k-prs.c)

# Basic Part
add_executable(
        fnn
        # sources
        src/process/main.c

        # utils
        src/utils/lib-mesg.c
        src/utils/lib-timing.c
        src/utils/lib-misc.c

        # lib sources
        src/lib/lib-2k-prs.c)

# Adding linear vhss
add_executable(
        linear-vhss-to-fnn
        # sources
        src/process/linear.c

        # utils
        src/utils/lib-mesg.c
        src/utils/lib-timing.c
        src/utils/lib-misc.c

        # lib sources
        src/lib/lib-2k-prs.c)

# Final scheme
add_executable(
        vhss-to-fnn
        # sources
        src/process/final.c

        # utils
        src/utils/lib-mesg.c
        src/utils/lib-timing.c
        src/utils/lib-misc.c

        # lib sources
        src/lib/lib-2k-prs.c)

add_library(demo src/demo.c)
target_compile_definitions(demo PRIVATE BUILD_AS_LIBRARY)
add_library(fri src/poly_vri/fri.c)
add_library(acef src/prf/acef.c)
add_library(vpoly src/poly_vri/vpoly.c)

# Linking libraries
target_link_libraries(2k-prs-demo gmp m pbc)
target_link_libraries(original gmp m pbc)
target_link_libraries(fnn gmp m pbc)
target_link_libraries(linear-vhss-to-fnn gmp m pbc)
target_link_libraries(vhss-to-fnn vpoly demo fri acef gmp m pbc relic)
target_include_directories(vhss-to-fnn PRIVATE ${RELIC_INCLUDE_DIRS})