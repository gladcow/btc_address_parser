#include <script.h>

/** Signature hash sizes */
static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;

namespace btc_utils
{

/** Script opcodes */
enum opcode_t
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    OP_INVALIDOPCODE = 0xff,
};

/** Decode small integers: */
static int decode_OP_N(opcode_t opcode)
{
    if (opcode == OP_0)
        return 0;
    if(opcode >= OP_1 && opcode <= OP_16)
        return (int)opcode - (int)(OP_1 - 1);
    throw std::runtime_error("Invalid OP_N");
}


static bool is_pay_to_script_hash(const std::vector<unsigned char>& script)
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (script.size() == 23 &&
            script[0] == OP_HASH160 &&
            script[1] == 0x14 &&
            script[22] == OP_EQUAL);
}

// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
static bool is_witness_program(const std::vector<unsigned char>& script, int& version, std::vector<unsigned char>& program)
{
    if (script.size() < 4 || script.size() > 42) {
        return false;
    }
    if (script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16)) {
        return false;
    }
    if ((size_t)(script[1] + 2) == script.size()) {
        version = decode_OP_N((opcode_t)script[0]);
        program = std::vector<unsigned char>(script.begin() + 2, script.end());
        return true;
    }
    return false;
}

static bool match_pay_to_pub_key(const std::vector<unsigned char>& script, std::vector<unsigned char>& pubkey)
{
    if (script.size() == pub_key_t::SIZE + 2 && script[0] == pub_key_t::SIZE && script.back() == OP_CHECKSIG) {
        pubkey = std::vector<unsigned char>(script.begin() + 1, script.begin() + pub_key_t::SIZE + 1);
        return pub_key_t::valid_size(pubkey);
    }
    if (script.size() == pub_key_t::COMPRESSED_SIZE + 2 && script[0] == pub_key_t::COMPRESSED_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = std::vector<unsigned char>(script.begin() + 1, script.begin() + pub_key_t::COMPRESSED_SIZE + 1);
        return pub_key_t::valid_size(pubkey);
    }
    return false;
}

static bool match_pay_to_pubkey_hash(const std::vector<unsigned char>& script, std::vector<unsigned char>& pubkeyhash)
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        pubkeyhash = std::vector<unsigned char>(script.begin () + 3, script.begin() + 23);
        return true;
    }
    return false;
}

txnouttype solver(const std::vector<unsigned char>& script, std::vector<std::vector<unsigned char> > &solutions)
{
   solutions.clear();

   // Shortcut for pay-to-script-hash, which are more constrained than the other types:
   // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
   if (is_pay_to_script_hash(script))
   {
       std::vector<unsigned char> hashBytes(script.begin()+2, script.begin()+22);
       solutions.push_back(hashBytes);
       return TX_SCRIPTHASH;
   }

   int witnessversion;
   std::vector<unsigned char> witnessprogram;
   if (is_witness_program(script, witnessversion, witnessprogram)) {
       if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
           solutions.push_back(witnessprogram);
           return TX_WITNESS_V0_KEYHASH;
       }
       if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
           solutions.push_back(witnessprogram);
           return TX_WITNESS_V0_SCRIPTHASH;
       }
       if (witnessversion != 0) {
           solutions.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
           solutions.push_back(std::move(witnessprogram));
           return TX_WITNESS_UNKNOWN;
       }
       return TX_NONSTANDARD;
   }

   // Provably prunable, data-carrying output
   //
   // So long as script passes the IsUnspendable() test and all but the first
   // byte passes the IsPushOnly() test we don't care what exactly is in the
   // script.
   if (script.size() >= 1 && script[0] == OP_RETURN) {
       return TX_NULL_DATA;
   }

   std::vector<unsigned char> data;
   if (match_pay_to_pub_key(script, data)) {
       solutions.push_back(std::move(data));
       return TX_PUBKEY;
   }

   if (match_pay_to_pubkey_hash(script, data)) {
       solutions.push_back(std::move(data));
       return TX_PUBKEYHASH;
   }

   solutions.clear();
   return TX_NONSTANDARD;
}

}
