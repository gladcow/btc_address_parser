// Copyright (c) 2020 gladcow
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTC_UTILS_CRYPTO_H__
#define BTC_UTILS_CRYPTO_H__

#include <array>
#include <vector>

namespace btc_utils
{

typedef std::array<unsigned char,  20> uint160_t;
typedef std::array<unsigned char,  32> uint256_t;

std::vector<unsigned char> from_hex(const std::string& hex);
std::string to_hex(const std::vector<unsigned char>& v);

uint256_t uint256_from_hex(const std::string& hex);
std::string uint256_to_hex(const uint256_t& v);

uint256_t hash_sha256(const std::vector<unsigned char>& data);
uint160_t hash_ripemd160(const std::vector<unsigned char>& data);

std::string encode_base58(const std::vector<unsigned char>& data);
std::string encode_base58_check(const std::vector<unsigned char>& data);

class key_id_t: public uint160_t
{
public:
    key_id_t() : uint160_t() {}
    key_id_t(const uint160_t& in) : uint160_t(in) {}
};

class pub_key_t
{
public:
   static constexpr unsigned int SIZE                   = 65;
   static constexpr unsigned int COMPRESSED_SIZE        = 33;
   static constexpr unsigned int SIGNATURE_SIZE         = 72;
   static constexpr unsigned int COMPACT_SIGNATURE_SIZE = 65;

private:
    std::array<unsigned char, 65> data_;

    static unsigned int get_len(unsigned char c)
    {
        if(c == 2 || c == 3)
            return 33;
        if(c == 4 || c == 6 || c == 7)
            return 65;
        return 0;
    }

    void invalidate()
    {
        data_[0] = 0xff;
    }
public:
    bool static valid_size(const std::vector<unsigned char> &vch) {
      return vch.size() > 0 && get_len(vch[0]) == vch.size();
    }

    pub_key_t()
    {
        invalidate();
    }

    template <typename T>
    void set(const T pbegin, const T pend)
    {
        size_t len = pend == pbegin ? 0 : get_len(pbegin[0]);
        if (len && len == static_cast<size_t>(pend - pbegin))
            std::copy(pbegin, pend, data_.begin());
        else
            invalidate();
    }

    template <typename T>
    pub_key_t(const T pbegin, const T pend)
    {
        set(pbegin, pend);
    }

    key_id_t get_id() const
    {
        std::vector<unsigned char> tmp(data_.begin(), data_.begin() + get_len(data_[0]));
        uint256_t h = hash_sha256(tmp);
        return hash_ripemd160(std::vector<unsigned char>(h.begin(), h.end()));
    }
};

class priv_key_t
{
private:
    bool valid_;
    bool compressed_;
    std::array<unsigned char, 32> data_;

public:
    priv_key_t(): valid_(false), compressed_(false) {}

    template <typename T>
    void set(const T pbegin, const T pend, bool compressed)
    {
        valid_ = false;
        if (size_t(pend - pbegin) != data_.size()) {
            return;
        }
        std::copy(pbegin,  pend, data_.begin());
        valid_ = true;
        compressed_ = compressed;
    }

    pub_key_t get_pub_key() const;
};

}

#endif // BTC_UTILS_CRIPTO_H__
