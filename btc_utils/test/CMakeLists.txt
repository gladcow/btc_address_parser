add_executable(btc_utils_test main.cpp)
target_link_libraries (btc_utils_test PUBLIC pthread btc_utils ${OPENSSL_LIBRARIES})
