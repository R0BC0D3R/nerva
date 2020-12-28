// Copyright (c) 2018-2019, The NERVA Project
// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <stdexcept>
#include <string>
#include <set>
#include <boost/uuid/uuid.hpp>
#include "misc_log_ex.h"

#define CRYPTONOTE_DNS_TIMEOUT_MS 20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER 500000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK 0x10000000
#define CRYPTONOTE_MAX_TX_SIZE 1000000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER 0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW 20
#define GENESIS_TRANSACTION_VERSION 1 //genesis block is the only time version 1 tx's are allowed
#define TRANSACTION_VERSION 2
#define TRANSACTION_VERSION_MAX TRANSACTION_VERSION
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE 20

#define BULLETPROOF_MAX_OUTPUTS 16

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW 12

#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT 60 * 5

#define FINAL_SUBSIDY_PER_MINUTE ((uint64_t)300000000000)

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE 300000
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE 600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT 12
#define COIN ((uint64_t)1000000000000)

#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE 50000

#define DEFAULT_MIXIN 4
#define DEFAULT_RINGSIZE DEFAULT_MIXIN + 1
#define FEE_PER_BYTE ((uint64_t)300000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE ((uint64_t)400000000)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD ((uint64_t)10000000000000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT ((uint64_t)3000)

#define DIFFICULTY_TARGET 60

#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN DIFFICULTY_TARGET

#define DIFFICULTY_WINDOW 60
#define DIFFICULTY_BLOCKS_COUNT DIFFICULTY_WINDOW + 1

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 DIFFICULTY_TARGET *CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS 1

#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT 10000
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT 20
#define BLOCKS_SYNCHRONIZING_MAX_COUNT 2048

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME (86400 * 3)
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME 604800

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT 1000

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT 1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT 5000

#define P2P_DEFAULT_CONNECTIONS_COUNT 8
#define P2P_DEFAULT_HANDSHAKE_INTERVAL 60
#define P2P_DEFAULT_PACKET_MAX_SIZE 50000000
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE 250
#define P2P_DEFAULT_CONNECTION_TIMEOUT 5000
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT 2000
#define P2P_DEFAULT_INVOKE_TIMEOUT 60 * 2 * 1000
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT 5000
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT 70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT 2

#define P2P_FAILED_ADDR_FORGET_SECONDS (60 * 60)
#define P2P_IP_BLOCKTIME_MAINNET (60 * 60 * 24)
#define P2P_IP_BLOCKTIME_TESTNET (60 * 5)
#define P2P_IP_FAILS_BEFORE_BLOCK 10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL (5 * 60)
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT 45
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT 2
#define P2P_DEFAULT_LIMIT_RATE_UP 2048
#define P2P_DEFAULT_LIMIT_RATE_DOWN 8192

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS 0x01
#define P2P_SUPPORT_FLAGS P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define RPC_IP_FAILS_BEFORE_BLOCK 3

#define CRYPTONOTE_PRUNING_STRIPE_SIZE 4096
#define CRYPTONOTE_PRUNING_LOG_STRIPES 3
#define CRYPTONOTE_PRUNING_TIP_BLOCKS 5500

#define CRYPTONOTE_NAME "nerva_v2"
#define CRYPTONOTE_POOLDATA_FILENAME "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME "p2pstate.nerva.v2.bin"
#define MINER_CONFIG_FILE_NAME "miner_conf.json"

#define THREAD_STACK_SIZE 5 * 1024 * 1024

#define PER_KB_FEE_QUANTIZATION_DECIMALS 8

#define HASH_OF_HASHES_STEP 256

#define DEFAULT_TXPOOL_MAX_WEIGHT 648000000ull

#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50

#define CRYPTONOTE_DANDELIONPP_STEMS              2 // number of outgoing stem connections per epoch
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 10 // out of 100
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5 // seconds average for poisson distributed fluff flush
#define CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE  173 // seconds (see tx_pool.cpp for more info)

#define CRYPTONOTE_NOISE_MIN_EPOCH 5
#define CRYPTONOTE_NOISE_EPOCH_RANGE 30
#define CRYPTONOTE_NOISE_MIN_DELAY 10
#define CRYPTONOTE_NOISE_DELAY_RANGE 5
#define CRYPTONOTE_NOISE_BYTES 3 * 1024
#define CRYPTONOTE_NOISE_CHANNELS 2

// Both below are in seconds. The idea is to delay forwarding from i2p/tor
// to ipv4/6, such that 2+ incoming connections _could_ have sent the tx
#define CRYPTONOTE_FORWARD_DELAY_BASE (CRYPTONOTE_NOISE_MIN_DELAY + CRYPTONOTE_NOISE_DELAY_RANGE)
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE (CRYPTONOTE_FORWARD_DELAY_BASE + (CRYPTONOTE_FORWARD_DELAY_BASE / 2))

#define CRYPTONOTE_MAX_FRAGMENTS 20

#define DONATION_ADDR "NV2RS6bgCjHNtUFnyA9MiYFNMwEwxVivfbKcH8DdM1UVfXQ3oAAFJvfiuDGidRbFgR2Pk6FaqkriRV565qhajcfv2SBcKM77o"
#define PREMINE_ADDR DONATION_ADDR

#define PREMINE_AMOUNT ((uint64_t)-1)

struct hard_fork
{
    uint8_t version;
    uint64_t height;
};

namespace config
{
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x3800;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x7081;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x1080;

    // Hash domain separators
    const char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
    const char HASH_KEY_RINGDB[] = "ringdsb";
    const char HASH_KEY_SUBADDRESS[] = "SubAddr";
    const unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
    const unsigned char HASH_KEY_WALLET = 0x8c;
    const unsigned char HASH_KEY_WALLET_CACHE = 0x8d;

    const unsigned char HASH_KEY_MEMORY = 'k';
    const unsigned char HASH_KEY_MULTISIG[] = {'M', 'u', 'l', 't', 'i', 's', 'i', 'g', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const unsigned char HASH_KEY_TXPROOF_V2[] = "TXPROOF_V2";
    const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
    const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
    const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
    const char HASH_KEY_MESSAGE_SIGNING[] = "NervaMessageSignature";

    namespace mainnet
    {
        uint16_t const P2P_DEFAULT_PORT = 17565;
        uint16_t const RPC_DEFAULT_PORT = 17566;
        boost::uuids::uuid const NETWORK_ID = {{0x2e, 0x4e, 0x45, 0x52, 0x56, 0x41, 0x20, 0x4d, 0x41, 0x49, 0x4e, 0x4e, 0x45, 0x54, 0x20, 0x32}};
        std::string const GENESIS_TX = "011401ff0001ffffffffffffffffff0102ea27285d52cd88c5fe49ee9965cbc6dba30be29083eb971ec010d304ab7e035021018fe3d72570741b49dfad9888cbb51ea9dd1d78aa222a2af203cd6d1e56dd214b";
        uint32_t const GENESIS_NONCE = 10000;

        std::string const HF_MIN_VERSION = "0.2.0.0";
        std::string const MIN_VERSION = "0.2.0.0";

        static const hard_fork hard_forks[] = {
            {1, 1},
            {2, 257}};
    }

    namespace testnet
    {
        uint16_t const P2P_DEFAULT_PORT = 18565;
        uint16_t const RPC_DEFAULT_PORT = 18566;
        boost::uuids::uuid const NETWORK_ID = {{0x2e, 0x4e, 0x45, 0x52, 0x56, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54, 0x4e, 0x45, 0x54, 0x20, 0x32}};
        std::string const GENESIS_TX = "011401ff0001ffffffffffffffffff0102a83b64f6c1a3abf88af5761fb97603f765df1a09962d43a1effba137d7c02b6a2101797f012296afc9b0d8499cfc2f33775545d5620ef05900e7aabd0515045bcfb4";
        uint32_t const GENESIS_NONCE = 20000;

        std::string const HF_MIN_VERSION = "0.2.0.0";
        std::string const MIN_VERSION = "0.2.0.0";

        static const hard_fork hard_forks[] = {
            {1, 1},
            {2, 257}};
    } // namespace testnet
} // namespace config

#ifndef VERSION_TO_INT
#define VERSION_TO_INT

inline uint32_t version_string_to_integer(std::string data)
{
    const char *v = data.c_str();

    unsigned int byte3;
    unsigned int byte2;
    unsigned int byte1;
    unsigned int byte0;
    char dummyString[2];

    if (sscanf(v, "%u.%u.%u%1s", &byte2, &byte1, &byte0, dummyString) == 3)
        return (byte2 << 24) + (byte1 << 16) + byte0; //3 part versioning scheme
    else if (sscanf(v, "%u.%u.%u.%u%1s", &byte3, &byte2, &byte1, &byte0, dummyString) == 4)
        return (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0; //4 part versioning scheme

    MGUSER_RED("Cound not interpret version number");
    return 0;
}

#endif

namespace cryptonote
{
    enum network_type : uint8_t
    {
        MAINNET = 0,
        TESTNET,
        UNDEFINED = 255
    };

    struct config_t
    {
        uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
        uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
        uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
        uint16_t const P2P_DEFAULT_PORT;
        uint16_t const RPC_DEFAULT_PORT;
        boost::uuids::uuid const NETWORK_ID;
        std::string const GENESIS_TX;
        uint32_t const GENESIS_NONCE;
        std::string const HF_MIN_VERSION;
        std::string const MIN_VERSION;
    };

    inline const config_t &get_config(network_type nettype)
    {
        static const config_t mainnet = {
            ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
            ::config::mainnet::P2P_DEFAULT_PORT,
            ::config::mainnet::RPC_DEFAULT_PORT,
            ::config::mainnet::NETWORK_ID,
            ::config::mainnet::GENESIS_TX,
            ::config::mainnet::GENESIS_NONCE,
            ::config::mainnet::HF_MIN_VERSION,
            ::config::mainnet::MIN_VERSION};
        static const config_t testnet = {
            ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
            ::config::testnet::P2P_DEFAULT_PORT,
            ::config::testnet::RPC_DEFAULT_PORT,
            ::config::testnet::NETWORK_ID,
            ::config::testnet::GENESIS_TX,
            ::config::testnet::GENESIS_NONCE,
            ::config::testnet::HF_MIN_VERSION,
            ::config::testnet::MIN_VERSION};

        switch (nettype)
        {
        case MAINNET:
            return mainnet;
        case TESTNET:
            return testnet;
        default:
            throw std::runtime_error("Invalid network type");
        }
    };
} // namespace cryptonote
