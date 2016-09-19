#include "channel.h"

#include <iostream>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

void error(const char* err) {
  cerr << err << " Code: " << errno << endl;
  exit(1);
}

CChannel::CChannel(int port) 
  : sockfd(-1)
{
  struct sockaddr_in serv_addr, cli_addr;

  // Create socket
  int port_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (port_socket < 0)
    error("Could not open socket.");

  // Bind to port
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(port_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    error("Could not bind to port.");

  // Listen for connection
  listen(port_socket, 1);
  unsigned cli_len = sizeof(cli_addr);
  sockfd = accept(port_socket, (struct sockaddr *) &cli_addr, &cli_len);
  if (sockfd < 0)
    error("Error while accepting connection");
}

CChannel::CChannel(const char* host, int port)
  : sockfd(-1)
{
  struct sockaddr_in serv_addr;
  struct hostent *server;

  // Create socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("Could not open socket.");

  // Resolve hostname and prepare server address
  server = gethostbyname(host);
  if (server == NULL)
    error("Could not resolve host");
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
	(char *)&serv_addr.sin_addr.s_addr,
	server->h_length);
  serv_addr.sin_port = htons(port);

  // Connect to listening server
  if (connect(sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    error("Error connecting to server.");
}

void CChannel::send(const char* buf, int len) {
  int code = write(sockfd, buf, len);
  if (code < 0)
    error("Error while writing to socket");
}

void CChannel::send(string str) {
  send(str.c_str(), str.length());
}

void CChannel::recv(char* buf, int len) {
  int code = read(sockfd, buf, len);
  if (code < 0)
    error("Error while reading from socket");
}

CChannel::~CChannel() {
  CChannel::closeChannel();
}

void CChannel::closeChannel() {
  close(sockfd);
}
