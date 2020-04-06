#ifndef BTC_UTILS_ADDRESS_H__
#define BTC_UTILS_ADDRESS_H__

#include "crypto.h"

#include <string>
#include <vector>

namespace btc_utils
{

/**
 * A txout script template with a specific destination. It is either:
 *  * no_destination_t: no destination set
 *  * pk_hash_tx_destination_t: TX_PUBKEYHASH destination (P2PKH)
 *  * script_hash_tx_destination_t: TX_SCRIPTHASH destination (P2SH)
 *  * witness_v0_script_hash_tx_destination_t: TX_WITNESS_V0_SCRIPTHASH destination (P2WSH)
 *  * witness_v0_key_hash_tx_destination_t: TX_WITNESS_V0_KEYHASH destination (P2WPKH)
 *  * witness_unknown_tx_destination_t: TX_WITNESS_UNKNOWN destination (P2W???)
 */
struct no_destination_t
{
};

struct pk_hash_tx_destination_t
{
   uint160_t data_;
   explicit pk_hash_tx_destination_t(const uint160_t& hash) : data_(hash) {}
   explicit pk_hash_tx_destination_t(const pub_key_t& pubkey) : data_(pubkey.get_id()) {}
};

struct script_hash_tx_destination_t
{
   uint160_t data_;
   explicit script_hash_tx_destination_t(const uint160_t& hash) : data_(hash) {}
   explicit script_hash_tx_destination_t(const std::vector<unsigned char>& script) : data_(hash_ripemd160(script)) {}
};

struct witness_v0_key_hash_tx_destination_t
{
   uint160_t data_;
   explicit witness_v0_key_hash_tx_destination_t(const uint160_t& hash) : data_(hash) {}
};

struct witness_v0_script_hash_tx_destination_t
{
   uint256_t data_;
   explicit witness_v0_script_hash_tx_destination_t(const uint256_t& hash) : data_(hash) {}
};

struct witness_unknown_tx_destination_t
{
   unsigned int version_;
   unsigned int length_;
   std::array<unsigned char, 40> program_;
};

std::string encode_destination(const no_destination_t& dest);
std::string encode_destination(const pk_hash_tx_destination_t& dest);
std::string encode_destination(const script_hash_tx_destination_t& dest);
std::string encode_destination(const witness_v0_key_hash_tx_destination_t& dest);
std::string encode_destination(const witness_v0_script_hash_tx_destination_t& dest);
std::string encode_destination(const witness_unknown_tx_destination_t& dest);

}

#endif // BTC_UTILS_ADDRESS_H__
