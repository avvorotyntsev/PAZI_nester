cmake_minimum_required(VERSION 3.10)

# @file CMakeLists.txt
# @brief CMake configuration file for building the File Encryption Tool project.
# @details This file sets up the project configuration, specifies compiler options,
# adds sources, and links the required cryptographic libraries based on the build options.

# @brief Project name definition
project(FileEncryptionTool)

# @brief Set the C++ standard to C++11
set(CMAKE_CXX_STANDARD 11)

# @brief Define build options for selecting the cryptographic library
# @details USE_OPENSSL is ON by default, while USE_LIBAKRYPT can be enabled as an alternative.
option(USE_OPENSSL "Use OpenSSL for encryption" ON)
option(USE_LIBAKRYPT "Use Libakrypt for encryption" OFF)

# @brief Add the source file main.cpp as the executable target
add_executable(file_encrypt main.cpp)

# @brief Link the appropriate cryptographic library based on the selected build option
# @details If USE_OPENSSL is enabled, OpenSSL is linked. If USE_LIBAKRYPT is enabled, libakrypt is linked.
if(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    if(WIN32)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        include_directories(${OPENSSL_INCLUDE_DIR})
        target_link_libraries(file_encrypt ${OPENSSL_CRYPTO_LIBRARY})
    else()
        target_link_libraries(file_encrypt OpenSSL::Crypto)
    endif()
elseif(USE_LIBAKRYPT)
    find_library(AKRYPT_LIBRARY akrypt REQUIRED)
    target_link_libraries(file_encrypt ${AKRYPT_LIBRARY})
endif()

# @brief Include source directory paths for header files
include_directories(${CMAKE_SOURCE_DIR})
