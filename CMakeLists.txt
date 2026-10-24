cmake_minimum_required(VERSION 3.20)
project(CustomMfaCredentialProvider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    include
)

# Core IPC Client library (Step 1)
add_library(MfaIpc STATIC
    src/MfaIpcClient.cpp
    include/IpcProtocol.h
    include/MfaIpcClient.h
)

# Credential Provider & Tile library (Steps 2, 3, & 4)
set(PROVIDER_SOURCES
    src/dllmain.cpp
    src/ClassFactory.cpp
    src/MfaCredentialProvider.cpp
    src/MfaCredential.cpp
    src/LsaHelper.cpp
    res/MfaProvider.def
)

# Final 64-bit Windows Credential Provider DLL (Step 5)
add_library(CustomMfaCredentialProvider SHARED
    ${PROVIDER_SOURCES}
)
target_link_libraries(CustomMfaCredentialProvider PRIVATE MfaIpc)

if(WIN32)
    target_link_libraries(CustomMfaCredentialProvider PRIVATE
        Secur32
        Ole32
        Advapi32
        Shlwapi
    )

    # Mock Background MFA Service (simulating the other developer's service)
    add_executable(MockMfaService
        tools/MockMfaService.cpp
        include/IpcProtocol.h
    )

    # Standalone Test Client to test IPC communication
    add_executable(TestIpcClient
        tools/TestIpcClient.cpp
    )
    target_link_libraries(TestIpcClient PRIVATE MfaIpc)

    # Safe Desktop Test Harness (Step 6) using CredUI
    add_executable(MfaTestHarness
        tools/TestHarness.cpp
        src/LsaHelper.cpp
        include/guid.h
        include/IpcProtocol.h
    )
    target_link_libraries(MfaTestHarness PRIVATE
        MfaIpc
        Credui
        Secur32
        Ole32
        Advapi32
        User32
        Gdi32
        Comctl32
    )

    # Enable Unicode & disable deprecation warnings for Windows strings
    target_compile_definitions(MfaIpc PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(CustomMfaCredentialProvider PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(MockMfaService PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(TestIpcClient PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(MfaTestHarness PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
endif()
