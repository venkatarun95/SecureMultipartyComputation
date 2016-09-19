#ifndef CHANNEL_H
#define CHANNEL_H

#include <string>

class CChannel {
 private:
  int sockfd;
 public:
  // Do nothing.
 CChannel() : sockfd(-1) {}
  // Listen on port
  CChannel(int port);
  // Connect to server
  CChannel(const char* host, int port);
  ~CChannel();
  
  void send(const char* buf, int len);
  void send(std::string str);
  void recv(char* buf, int len);
  void closeChannel();
};

#endif // #ifndef CHANNEL_H
