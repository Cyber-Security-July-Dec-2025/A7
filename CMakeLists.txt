cmake_minimum_required(VERSION 3.18)
project(MacCryptoGUI LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt
find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Find Crypto++ (via pkg-config or standard locations)
find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h PATHS /opt/homebrew/include /usr/local/include /usr/include)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp PATHS /opt/homebrew/lib /usr/local/lib /usr/lib)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ not found. Please install it (e.g., 'brew install cryptopp').")
endif()

include_directories(${CRYPTOPP_INCLUDE_DIR})

add_executable(MacCryptoGUI
    src/main.cpp
)

target_link_libraries(MacCryptoGUI
    Qt6::Widgets
    ${CRYPTOPP_LIBRARY}
)
