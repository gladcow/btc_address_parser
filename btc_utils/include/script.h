#ifndef BTC_UTILS_SCRIPT_H__
#define BTC_UTILS_SCRIPT_H__

#include <crypto.h>
#include <vector>

namespace btc_utils
{

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA, //!< unspendable OP_RETURN script that carries data
    TX_WITNESS_V0_SCRIPTHASH,
    TX_WITNESS_V0_KEYHASH,
    TX_WITNESS_UNKNOWN, //!< Only for Witness versions not already defined above
};

txnouttype solver(const std::vector<unsigned char>& script,
                  std::vector<std::vector<unsigned char>>& solutions);

}

#endif //BTC_UTILS_SCRIPT_H__
