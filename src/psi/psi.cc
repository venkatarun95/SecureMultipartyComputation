#include <iostream>

#include "channel.h"
#include "coin-toss.h"

const int security_bits = 64;

using namespace std;
int main(int argc, char** argv) {
  if (argc != 2) {
    cerr << "Expecting 1 argument" << endl;
    exit(1);
  }

  CChannel channel;
  if (argv[1][0] == 's')
    channel = *(new CChannel(8889));
  else
    channel = *(new CChannel("127.0.0.1", 8889));

  channel.send((char*)"Hello", 6);
  char buf[6];
  channel.recv(buf, 6);
  cout << buf << endl;

  CoinToss tosser(channel);
  int coinLength = tosser.numBytesPerCall();
  unsigned char coins[coinLength];
  for (int i = 0; i < 10; ++i) {
    tosser.nextBytes((unsigned char*)coins);
    for (int i = 0; i < coinLength; ++i)
      cout << (int)coins[i] << " ";
    cout << endl;
  }

  channel.closeChannel();
  return 0;
}
