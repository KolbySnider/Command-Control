cmake_minimum_required(VERSION 3.25)
project(Command_Control C)

set(CMAKE_C_STANDARD 11)

# Add linker flags for MinGW
if (MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "-lws2_32")
endif()

add_executable(Command_Control Agent/src/main.c
                Agent/include/commands.h
                Agent/include/network.h
                Agent/src/commands.c
                Agent/src/network.c
        Agent/src/exploit.cpp
)

# Link against Winsock2
target_link_libraries(Command_Control ws2_32 wininet advapi32)

