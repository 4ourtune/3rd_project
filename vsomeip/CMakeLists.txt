cmake_minimum_required (VERSION 3.10)

project (RaspiSomeipClient)

# C++11 이상 필요
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED True)

# vsomeip 라이브러리 찾기
find_package(vsomeip3 REQUIRED)

# Boost 라이브러리 찾기 (vsomeip 의존성)
find_package(Boost 1.55 COMPONENTS system thread log REQUIRED)

include_directories(
    ${Boost_INCLUDE_DIR}
    ${VSOMEIP_INCLUDE_DIRS}
)

# 실행 파일 정의
add_executable(rpi_client_app rpi_client_app.cpp)

# 라이브러리 링크
target_link_libraries(rpi_client_app
    vsomeip3
    ${Boost_LIBRARIES}
)
