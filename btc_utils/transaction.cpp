#include <transaction.h>
#include <script.h>
#include <crypto.h>

namespace btc_utils {

std::vector<std::string> tx_out_t::addresses() const
{
   std::vector<std::vector<unsigned char>> keys;
   txnouttype out_type = solver(scriptPubKey, keys);
   std::vector<std::string> res;

   /*
   if (out_type == TX_PUBKEY) {
       res.push_back(PKHash(keys[0]));
   }
   else if (out_type == TX_PUBKEYHASH)
   {
       res.push_back(PKHash(keys[0].get_id()));
   }
   else if (out_type == TX_SCRIPTHASH)
   {
       res.push_back(ScriptHash(keys[0]));
   }
   else if (out_type == TX_WITNESS_V0_KEYHASH)
   {
       WitnessV0KeyHash hash;
       std::copy(keys[0].begin(), keys[0].end(), hash.begin());
       res.push_back(hash);
   } else if (out_type == TX_WITNESS_V0_SCRIPTHASH) {
       WitnessV0ScriptHash hash;
       std::copy(keys[0].begin(), keys[0].end(), hash.begin());
       res.push_back(hash);
   } else if (out_type == TX_WITNESS_UNKNOWN) {
       WitnessUnknown unk;
       unk.version = vSolutions[0][0];
       std::copy(vSolutions[1].begin(), vSolutions[1].end(), unk.program);
       unk.length = vSolutions[1].size();
       res.push_back(unk);
   }
   */

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
