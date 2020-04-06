#include <address.h>
#include <chainparams.h>
#include <bech32.h>

namespace btc_utils
{

std::string encode_destination(const no_destination_t&)
{
   return {};
}

std::string encode_destination(const pk_hash_tx_destination_t& dest)
{
   std::vector<unsigned char> data = base_58_pubkey_address_prefix();
   data.insert(data.end(), dest.data_.begin(), dest.data_.end());
   return encode_base58_check(data);
}

std::string encode_destination(const script_hash_tx_destination_t& dest)
{
   std::vector<unsigned char> data = base_58_pubkey_address_prefix();
   data.insert(data.end(), dest.data_.begin(), dest.data_.end());
   return encode_base58_check(data);
}

std::string encode_destination(const witness_v0_key_hash_tx_destination_t& dest)
{
   std::vector<unsigned char> data = {0};
   data.reserve(33);
   ConvertBits<8, 5, true>(
            [&data](unsigned char c){ data.push_back(c); },
            dest.data_.begin(), dest.data_.end()
   );
   return bech32::Encode(bech32_hrp(), data);
}

std::string encode_destination(const witness_v0_script_hash_tx_destination_t& dest)
{
   std::vector<unsigned char> data = {0};
   data.reserve(53);
   ConvertBits<8, 5, true>(
            [&data](unsigned char c) { data.push_back(c); },
            dest.data_.begin(), dest.data_.end());
   return bech32::Encode(bech32_hrp(), data);
}

std::string encode_destination(const witness_unknown_tx_destination_t& dest)
{
   if (dest.version_ < 1 || dest.version_ > 16 || dest.length_ < 2 || dest.length_ > 40) {
       return {};
   }
   std::vector<unsigned char> data = {(unsigned char)dest.version_};
   data.reserve(1 + (dest.length_ * 8 + 4) / 5);
   ConvertBits<8, 5, true>(
            [&data](unsigned char c) { data.push_back(c); },
            dest.program_.data(), dest.program_.data() + dest.length_);
   return bech32::Encode(bech32_hrp(), data);
}

}
