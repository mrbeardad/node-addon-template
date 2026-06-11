cmake_minimum_required(VERSION 3.15)
project(my_addon)

# Node-API
add_compile_definitions(NAPI_VERSION=9)

# Sources
file(GLOB SOURCE_FILES "src/*.cpp")

# Build shared library → .node
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# C++ standard
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

# cmake-js provided paths
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})

# delayimp.lib needed for /DELAYLOAD:NODE.EXE on Windows
if(MSVC)
    target_link_libraries(${PROJECT_NAME} PRIVATE delayimp)
endif()

# node.lib for Windows
if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
    execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

# Windows Unicode + Release defines
if(WIN32)
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
endif()
