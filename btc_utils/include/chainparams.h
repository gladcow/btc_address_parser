#ifndef BTC_UTILS_CHAINPARAMS_H__
#define BTC_UTILS_CHAINPARAMS_H__

namespace btc_utils
{

enum network_t
{
   mainnet,
   testnet,
   regtest
};

extern network_t g_network;
/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
extern const unsigned int MAX_BLOCK_SERIALIZED_SIZE;
constexpr unsigned int MESSAGE_START_SIZE = 4;

typedef unsigned char start_marker_t[MESSAGE_START_SIZE];

const start_marker_t& message_start();
}

#endif // BTC_UTILS_CHAINPARAMS_H__
