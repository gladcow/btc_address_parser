add_library(btc_utils address.cpp block.cpp chainparams.cpp crypto.cpp script.cpp transaction.cpp)
target_include_directories(btc_utils PUBLIC include)
target_include_directories(btc_utils INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
