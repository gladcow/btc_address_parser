#include "address.h"

namespace btc_utils
{

address_t::address_t(const key_id_t &keyid)
{
   data_.push_back(76); // mainnet,  pubkey address
   data_.insert(data_.end(), keyid.begin(), keyid.end());
}

address_t::address_t(const std::vector<unsigned char> &script_pub_key)
{

}

std::string address_t::to_string() const
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(data_);
    uint256_t tmp = hash_sha256(vch);
    uint256_t h = hash_sha256(std::vector<unsigned char>(tmp.begin(), tmp.end()));
    vch.insert(vch.end(), &h[0], &h[0] + 4);
    return encode_base58(vch);
}

}
