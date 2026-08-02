cmake_minimum_required(VERSION 3.20)
project(tlou2_hook)

set(CMAKE_CXX_STANDARD 20)

file(GLOB MINHOOK_SOURCES "minhook/src/*.c")

add_library(tlou2_hook SHARED dllmain.cpp ${MINHOOK_SOURCES})

target_include_directories(tlou2_hook PRIVATE minhook/include)

target_link_libraries(tlou2_hook user32)
target_link_options(tlou2_hook PRIVATE -static -static-libgcc -static-libstdc++)
target_link_libraries(tlou2_hook user32 psapi)

target_link_libraries(tlou2_hook user32 psapi ws2_32)

add_custom_command(TARGET tlou2_hook POST_BUILD
        COMMAND powershell -Command
        "Copy-Item '$<TARGET_FILE:tlou2_hook>' -Destination 'C:/Games/The Last of Us - Part II Remastered/tlou2_hook.asi' -Force"
        COMMENT "Deploy -> jeu"
)