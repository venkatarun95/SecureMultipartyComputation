#ifndef COIN_TOSS_H
#define COIN_TOSS_H

#include <cstdint>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "channel.h"

class CoinToss {
  // Can generate a large number of random bits from this state
  unsigned char* cur_seed;
  // Counter for deterministic pseudo-random number generation
  uint64_t counter;
  // Symmetric cipher algorithm to be used
  const EVP_CIPHER* cipherType;
  // Cipher object so we don't have to keep reallocating memory
  EVP_CIPHER_CTX* cipher;
  
  // Channel connecting to the other party
  CChannel& channel;
  
  // Type of hash function to be used
  const EVP_MD* hashType;
  // Length in bytes of the seed created when the two party protocol
  // is run. Depends on hashType.
  int seedSize;
  int hashSize;

  // Hash `msg` of length `length and store in `hash`
  void hashMsg(unsigned char* msg, unsigned char* hash, int length);
  // Run a two-party protocol to re-seed our coin tosses
  void refreshCommonEntropy();
  
 public:
  CoinToss(CChannel& channel);

  CoinToss(const CoinToss& other) = delete;
  CoinToss operator=(const CoinToss&)  = delete;

  ~CoinToss() {
    delete cur_seed;
    EVP_CIPHER_CTX_free(cipher);
  }

  // Calculate the next `numBytes` bytes and store in `buf`
  void nextBytes(unsigned char* buf);

  // Number of bytes returned per call to nextBytes
  int numBytesPerCall() const {return EVP_CIPHER_block_size(cipherType);}
};

#endif // #ifndef COIN_TOSS_H
