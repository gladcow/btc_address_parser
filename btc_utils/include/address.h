#ifndef BTC_UTILS_ADDRESS_H__
#define BTC_UTILS_ADDRESS_H__

#include <string>
#include <vector>
#include "crypto.h"

namespace btc_utils
{

class address_t{
private:
    std::vector<unsigned char> data_;

public:
    address_t(const key_id_t& keyid);
    address_t(const std::vector<unsigned char>& script_pub_key);

    std::string to_string() const;
};

}

#endif // BTC_UTILS_ADDRESS_H__
