// Copyright (c) 2020 gladcow
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <memory>
#include <algorithm>

namespace btc_utils
{

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string encode_base58(const std::vector<unsigned char>& data)
{
    // Skip & count leading zeroes.
    auto pbegin = std::find_if(data.begin(), data.end(),
                               [](unsigned char c) { return c != 0u; });
    size_t zeroes = size_t(pbegin - data.begin());
    // Allocate enough space in big-endian base58 representation.
    size_t size = (data.size() - zeroes) * 138u / 100u + 1u; // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
    size_t length = 0;
    // Process the bytes.
    while (pbegin != data.end()) {
        unsigned carry = *pbegin;
        unsigned i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (auto it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256u * (*it);
            *it = static_cast<unsigned char>(carry % 58u);
            carry /= 58u;
        }

        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    auto it = std::next(b58.begin(), static_cast<long int>(size - length));
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + static_cast<size_t>(b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string encode_base58_check(const std::vector<unsigned char> &data)
{
   // add 4-byte hash check to the end
   std::vector<unsigned char> vch(data);
   uint256_t tmp = hash_sha256(vch);
   uint256_t h = hash_sha256(std::vector<unsigned char>(tmp.begin(), tmp.end()));
   vch.insert(vch.end(), &h[0], &h[0] + 4);
   return encode_base58(vch);
}

uint256_t hash_sha256(const std::vector<unsigned char> &data)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    uint256_t res;
    SHA256_Final(&res[0], &sha256);
    return res;
}

uint160_t hash_ripemd160(const std::vector<unsigned char> &data)
{
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, data.data(), data.size());
    uint160_t res;
    RIPEMD160_Final(&res[0], &ripemd);
    return res;
}

const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
    return p_util_hexdigit[static_cast<unsigned char>(c)];
}

std::vector<unsigned char> from_hex(const std::string& hex)
{
    if(hex.length() % 2 != 0)
        throw std::runtime_error("Invalid hex string size");
    std::vector<unsigned char> res;
    res.resize(hex.length() / 2);
    auto it = hex.begin();
    size_t count = 0;
    static signed char failed = static_cast<signed char>(-1);
    while (it != hex.end())
    {
        signed char c = HexDigit(*it++);
        if (c == failed)
            throw std::runtime_error("Invalid symbol in hex string");
        unsigned char n = static_cast<unsigned char>(c << 4);
        c = HexDigit(*it++);
        if (c == failed)
            throw std::runtime_error("Invalid symbol in hex string");
        n = static_cast<unsigned char>(n | c);
        res[count++] = n;
    }
    return res;
}

std::string to_hex(const std::vector<unsigned char>& v)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve(v.size() * 2);
    for(auto c = v.rend(); c != v.rbegin(); c++)
    {
        unsigned char val = *c;
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }
    return rv;
}

uint256_t uint256_from_hex(const std::string& hex)
{
    if(hex.length() != 64u)
        throw std::runtime_error("Invalid hex string size for uint256");
    uint256_t res;
    auto it = hex.begin();
    size_t count = 0;
    static signed char failed = static_cast<signed char>(-1);
    while (it != hex.end())
    {
        signed char c = HexDigit(*it++);
        if (c == failed)
            throw std::runtime_error("Invalid symbol in hex string");
        unsigned char n = static_cast<unsigned char>(c << 4);
        c = HexDigit(*it++);
        if (c == failed)
            throw std::runtime_error("Invalid symbol in hex string");
        n = static_cast<unsigned char>(n | c);
        res[count++] = n;
    }
    return res;
}

std::string uint256_to_hex(const uint256_t& v)
{
   std::string rv;
   static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
   rv.reserve(v.size() * 2);
   for(auto c = v.rend(); c != v.rbegin(); c++)
   {
       unsigned char val = *c;
       rv.push_back(hexmap[val>>4]);
       rv.push_back(hexmap[val&15]);
   }
   return rv;
}

pub_key_t priv_key_t::get_pub_key() const
{
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(
                BN_CTX_new(),
                &BN_CTX_free
                );
    if(!ctx)
        throw std::runtime_error("Failed to create BN_CTX");
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> curve(
                EC_GROUP_new_by_curve_name(NID_secp256k1),
                &EC_GROUP_free
                );
    if(!curve)
        throw std::runtime_error("Failed to get secp256k1 group");
    std::unique_ptr<BIGNUM, decltype(&BN_free)> prv(
                BN_bin2bn(data_.data(), static_cast<int>(data_.size()), nullptr),
                &BN_free
                );
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> pub(
                EC_POINT_new(curve.get()),
                &EC_POINT_free
                );
    if (1 != EC_POINT_mul(curve.get(), pub.get(), prv.get(), NULL, NULL,
                          ctx.get()))
        throw std::runtime_error("Failed to calc public key");
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(
                EC_KEY_new_by_curve_name(NID_secp256k1),
                &EC_KEY_free
                );
    if(!key)
        throw std::runtime_error("Failed to generate EC_KEY");
    if(1 != EC_KEY_set_private_key(key.get(), prv.get()))
        throw std::runtime_error("Failed to set private key in EC_KEY");
    if(1 != EC_KEY_set_public_key(key.get(), pub.get()))
        throw std::runtime_error("Failed to set public key in EC_KEY");
    point_conversion_form_t form = compressed_ ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    unsigned char* tmp = nullptr;
    size_t len = EC_KEY_key2buf(key.get(), form, &tmp, ctx.get());
    std::unique_ptr<unsigned char, decltype(&free)> autofree(tmp, &free);
    pub_key_t result;
    result.set(tmp,  tmp + len);
    return result;
}

}
