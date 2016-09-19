#include "coin-toss.h"

#include <cstring>
#include <iostream>

#include <openssl/rand.h>
#include <openssl/engine.h>

CoinToss::CoinToss(CChannel& channel)
  : cur_seed(nullptr),
    counter(0),
    cipherType(EVP_aes_256_cbc()),
    cipher(nullptr),
    channel(channel),
    hashType(EVP_sha512()),
    seedSize(EVP_MD_size(EVP_sha512())),
    hashSize(EVP_MD_size(EVP_sha512()))
{
  cur_seed = new unsigned char[seedSize];
  for (int i = 0; i < seedSize; ++i)
    cur_seed[i] = 0;
  cipher = EVP_CIPHER_CTX_new();
}


void CoinToss::hashMsg(unsigned char* msg, unsigned char* hash, int length) {
  EVP_MD_CTX* result = EVP_MD_CTX_create(); //EVP_MD_CTX_new();
  EVP_DigestInit_ex(result, hashType, (ENGINE*)NULL);
  EVP_DigestUpdate(result, msg, length);
  EVP_DigestFinal_ex(result, hash, (unsigned int*)NULL);
  EVP_MD_CTX_destroy(result);
}

void printBytes(unsigned char bytes[], int len) {
  for (int i = 0; i < len; ++i)
    std::cout << (int)bytes[i] << " ";
  std::cout << std::endl;
}

void CoinToss::refreshCommonEntropy() {
  // Decide our input
  unsigned char ourInput[seedSize];
  int err = RAND_bytes(ourInput, seedSize);
  if (err == 0) exit(1);

  unsigned char ourCommitment[hashSize];
  hashMsg(ourInput, ourCommitment, seedSize);

  // Send our commitment and receive theirs
  channel.send((char*)ourCommitment, hashSize);
  unsigned char theirCommitment[hashSize];
  channel.recv((char*)theirCommitment, hashSize);

  // Send our input and receive theirs
  channel.send((char*)ourInput, seedSize);
  unsigned char theirInput[seedSize];
  channel.recv((char*)theirInput, hashSize);

  // Verify against their commitment
  unsigned char theirCommitmentVerif[hashSize];
  hashMsg(theirInput, theirCommitmentVerif, seedSize);
  if(strncmp((char*)theirCommitmentVerif, (char*)theirCommitment, hashSize))
    // Cheater! Their commitment did not match up to their input.
    exit(1);

  // Update our common seed
  for (int i = 0; i < seedSize; ++i) {
    cur_seed[i] = cur_seed[i] ^ ourInput[i];
    cur_seed[i] = cur_seed[i] ^ theirInput[i];
  }
}

void CoinToss::nextBytes(unsigned char* buf) {
  // If we haven't refreshed our entropy in a while (or ever), then do
  // so. But if we do it this way, syncing is required
  // if (counter % (seedSize * 1024) == 0)
  //   refreshCommonEntropy();
  if (counter == 0)
    refreshCommonEntropy();

  unsigned char input[8];
  input[0] = (counter          & 0xFF) ^ cur_seed[0];
  input[1] = ((counter >> 8)   & 0xFF) ^ cur_seed[0];
  input[2] = ((counter >> 16)  & 0xFF) ^ cur_seed[0];
  input[3] = ((counter >> 24)  & 0xFF) ^ cur_seed[0];
  input[4] = ((counter >> 32)  & 0xFF) ^ cur_seed[0];
  input[5] = ((counter >> 40)  & 0xFF) ^ cur_seed[0];
  input[6] = ((counter >> 48)  & 0xFF) ^ cur_seed[0];
  input[7] = ((counter >> 56)  & 0xFF) ^ cur_seed[0];

  // Generate next number using counter-based cipher
  int resultLength;
  // TODO(venkat): Find out whether it is safe to set iv to NULL in
  // the call below
  EVP_EncryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, cur_seed, NULL);
  EVP_EncryptUpdate(cipher, buf, &resultLength, input, 8);
  EVP_EncryptFinal_ex(cipher, buf + resultLength, &resultLength);
  ++ counter;
}
