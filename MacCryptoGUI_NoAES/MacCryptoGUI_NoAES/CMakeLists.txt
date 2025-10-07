cmake_minimum_required(VERSION 3.18)
project(MacCryptoGUI_NoAES LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Find Crypto++
find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h PATHS /opt/homebrew/include /usr/local/include /usr/include)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp PATHS /opt/homebrew/lib /usr/local/lib /usr/lib)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ not found. Install with: brew install cryptopp")
endif()

include_directories(${CRYPTOPP_INCLUDE_DIR})

add_executable(MacCryptoGUI_NoAES
    src/main.cpp
)

target_link_libraries(MacCryptoGUI_NoAES
    Qt6::Widgets
    ${CRYPTOPP_LIBRARY}
)
