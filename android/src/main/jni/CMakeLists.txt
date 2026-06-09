cmake_minimum_required(VERSION 3.13)
project(okint)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# React Native ships JSI as a prefab consumed via find_package + buildFeatures.prefab.
find_package(ReactAndroid REQUIRED CONFIG)

add_library(
  okint
  SHARED
  OkintJNI.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../cpp/OkintJSI.cpp
)

target_include_directories(okint PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../cpp)

target_link_libraries(
  okint
  ReactAndroid::jsi
  android
  log
)
