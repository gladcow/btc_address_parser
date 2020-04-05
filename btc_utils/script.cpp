#include <script.h>

namespace btc_utils
{

txnouttype solver(const std::vector<unsigned char>& script, std::vector<pub_key_t>& keys)
{
   return TX_NONSTANDARD;
}

}
