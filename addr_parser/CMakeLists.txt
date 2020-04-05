add_executable(addr_parser main.cpp)
target_link_libraries (addr_parser PUBLIC pthread btc_utils ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
