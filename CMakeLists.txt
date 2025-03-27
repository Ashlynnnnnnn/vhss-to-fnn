cmake_minimum_required(VERSION 3.13)
project(vhss-to-fnn C)

set(CMAKE_C_STANDARD 99)


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

# Linking libraries
# - GMP
# - Math
# - Pbc
target_link_libraries(2k-prs-demo gmp m pbc)
target_link_libraries(fnn gmp m pbc)
target_link_libraries(linear-vhss-to-fnn gmp m pbc)
target_link_libraries(vhss-to-fnn demo gmp m pbc)