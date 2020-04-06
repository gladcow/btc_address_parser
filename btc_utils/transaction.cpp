#include <transaction.h>
#include <address.h>
#include <crypto.h>
#include <script.h>

namespace btc_utils {

std::vector<std::string> tx_out_t::addresses() const
{
   std::vector<std::vector<unsigned char>> keys;
   txnouttype out_type = solver(scriptPubKey, keys);
   std::vector<std::string> res;

   if (out_type == TX_PUBKEY) {
       pub_key_t pubkey(keys[0].begin(), keys[0].end());
       res.push_back(encode_destination(pk_hash_tx_destination_t(pubkey.get_id())));
   }
   else if (out_type == TX_PUBKEYHASH)
   {
       uint160_t pk_hash;
       std::copy(keys[0].begin(), keys[0].end(), pk_hash.begin());
       res.push_back(encode_destination(pk_hash_tx_destination_t(pk_hash)));
   }
   else if (out_type == TX_SCRIPTHASH)
   {
       uint160_t script_hash;
       std::copy(keys[0].begin(), keys[0].end(), script_hash.begin());
       res.push_back(encode_destination(script_hash_tx_destination_t(script_hash)));
   }
   else if (out_type == TX_WITNESS_V0_KEYHASH)
   {
       uint160_t key_hash;
       std::copy(keys[0].begin(), keys[0].end(), key_hash.begin());
       res.push_back(encode_destination(witness_v0_key_hash_tx_destination_t(key_hash)));
   } else if (out_type == TX_WITNESS_V0_SCRIPTHASH) {
       uint256_t script_hash;
       std::copy(keys[0].begin(), keys[0].end(), script_hash.begin());
       res.push_back(encode_destination(witness_v0_script_hash_tx_destination_t(script_hash)));
   } else if (out_type == TX_WITNESS_UNKNOWN) {
       witness_unknown_tx_destination_t unk;
       unk.version_ = keys[0][0];
       std::copy(keys[1].begin(), keys[1].end(), unk.program_.begin());
       unk.length_ = keys[1].size();
       res.push_back(encode_destination(unk));
   }

   return res;
}

bool transaction_t::has_witness() const
{
   for (size_t i = 0; i < vin.size(); i++) {
       if (!vin[i].scriptWitness.empty()) {
           return true;
       }
   }
   return false;
}

}
