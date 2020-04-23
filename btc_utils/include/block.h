// Copyright (c) 2020 gladcow
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTC_UTILS_BLOCK_H__
#define BTC_UTILS_BLOCK_H__

#include <crypto.h>
#include <transaction.h>

#include <vector>

namespace btc_utils
{

class block_t
{
public:
   uint32_t version_;
   uint256_t prev_block_hash_;
   uint256_t merkle_root_;
   uint32_t time_;
   uint32_t bits_;
   uint32_t nonce_;

   std::vector<transaction_t> txes_;

   template<typename T>
   void unserialize(T& data_source)
   {
      data_source.unserialize(version_);
      data_source.unserialize(prev_block_hash_);
      data_source.unserialize(merkle_root_);
      data_source.unserialize(time_);
      data_source.unserialize(bits_);
      data_source.unserialize(nonce_);
      data_source.unserialize(txes_);
   }

};

}

#endif // BTC_UTILS_BLOCK_H__

