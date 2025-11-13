# cmake_minimum_required(VERSION 3.10)
# project(vc_realtime)

# # ----------------------------
# # 공통 설정
# # ----------------------------
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# add_compile_options(-O2 -Wall -Wextra -Wpedantic)

# # ----------------------------
# # vsomeip3 + Boost 찾기
# # ----------------------------
# find_package(vsomeip3 REQUIRED)
# find_package(Boost 1.55 COMPONENTS system thread log REQUIRED)

# include_directories(
#     ${Boost_INCLUDE_DIRS}
#     ${VSOMEIP_INCLUDE_DIRS}
# )

# # ----------------------------
# # 실행 파일 정의
# # ----------------------------
# add_executable(vc_realtime
#     main.cpp
#     sensor_thread.cpp
#     comm_thread.cpp
#     control_thread.cpp
#     vsomeip_manager.cpp
#     shared.cpp
# )

# # ----------------------------
# # 링크 라이브러리
# # ----------------------------
# target_link_libraries(vc_realtime
#     vsomeip3
#     ${Boost_LIBRARIES}
#     pthread
# )

cmake_minimum_required(VERSION 3.10)
project(VSomeIP_SensorTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(vsomeip3 REQUIRED)
find_package(Boost 1.55 COMPONENTS system thread log REQUIRED)

include_directories(
    ${Boost_INCLUDE_DIRS}
    ${VSOMEIP_INCLUDE_DIRS}
)

add_executable(sensor_comm_test
    main.cpp
    sensor_thread.cpp
    control_thread.cpp
    comm_thread.cpp
    vsomeip_manager.cpp
    shared.cpp    # 전역 공유 객체 정의 포함
    joystick_thread.cpp
    ipc_server.cpp
    lkas_thread.cpp
)

target_link_libraries(sensor_comm_test
    vsomeip3
    ${Boost_LIBRARIES}
    pthread
)
