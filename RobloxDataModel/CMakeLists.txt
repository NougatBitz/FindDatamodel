cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(RobloxDataModel)

add_executable (RobloxDataModel "main.cpp")

include (FetchContent)

FetchContent_Declare (wincpp URL https://github.com/atrexus/wincpp/releases/latest/download/wincpp-src.zip)
FetchContent_MakeAvailable (wincpp)

target_link_libraries(RobloxDataModel PRIVATE wincpp)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET RobloxDataModel PROPERTY CXX_STANDARD 23)
endif()