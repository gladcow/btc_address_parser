// Copyright (c) 2020 gladcow
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTC_UTILS_TRANSACTION_H__
#define BTC_UTILS_TRANSACTION_H__

#include <crypto.h>
#include <vector>

namespace btc_utils
{

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class out_point_t
{
public:
    uint256_t hash;
    uint32_t n;

    template<typename T>
    void unserialize(T& data_source)
    {
       data_source.unserialize(hash);
       data_source.unserialize(n);
    }
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class tx_in_t
{
public:
   out_point_t prevout;
   std::vector<unsigned char> scriptSig;
   uint32_t nSequence;
   std::vector<std::vector<unsigned char> > scriptWitness; //!< Only serialized through CTransaction

   template<typename T>
   void unserialize(T& data_source)
   {
      prevout.unserialize(data_source);
      data_source.unserialize(scriptSig);
      data_source.unserialize(nSequence);
   }
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class tx_out_t
{
public:
   uint64_t nValue;
   std::vector<unsigned char> scriptPubKey;

   template<typename T>
   void unserialize(T& data_source)
   {
      data_source.unserialize(nValue);
      data_source.unserialize(scriptPubKey);
   }

   std::vector<std::string> addresses() const;
};

class transaction_t
{
public:
   std::vector<tx_in_t> vin;
   std::vector<tx_out_t> vout;
   uint32_t nVersion;
   uint32_t nLockTime;

   template<typename T>
   void unserialize(T& data_source)
   {
      data_source.unserialize(nVersion);
      unsigned char flags = 0;
      vin.clear();
      vout.clear();
      /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
      data_source.unserialize(vin);
      if (vin.size() == 0) {
          /* We read a dummy or an empty vin. */
          data_source.unserialize(flags);
          if (flags != 0) {
              data_source.unserialize(vin);
              data_source.unserialize(vout);
          }
      } else {
          /* We read a non-empty vin. Assume a normal vout follows. */
          data_source.unserialize(vout);
      }
      if ((flags & 1)) {
          /* The witness flag is present, and we support witnesses. */
          flags ^= 1;
          for (size_t i = 0; i < vin.size(); i++) {
              data_source.unserialize(vin[i].scriptWitness);
          }
          if (!has_witness()) {
              /* It's illegal to encode witnesses when all witness stacks are empty. */
              throw std::runtime_error("Superfluous witness record");
          }
      }
      if (flags) {
          /* Unknown flag in the serialization */
          throw std::runtime_error("Unknown transaction optional data");
      }
      data_source.unserialize(nLockTime);
   }

   bool has_witness() const;
};

}
#endif // BTC_UTILS_TRANSACTION_H__
