#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include<sys/wait.h>
#include "BLOWFISH.H"
#include "BLOWFISH.C"


#define MYPORT "10010" // the port users will be connecting to
#define MAXBUFLEN 512




int main(int argc, char *argv[])
{
  int sockfd, peer;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int n;
  struct sockaddr_storage their_addr;
  char send[MAXBUFLEN], recv[MAXBUFLEN];
  socklen_t addr_len;
  pid_t childpid;
  char bfkey[MAXBUFLEN];    //sym key
  short keybyte;            //key length
  unsigned long *lblock;  
  unsigned long *rblock;
  void *ptr;              //void pointer used to convert data type 
  char c;               //used to handle user input
  int i;
  char ack[3]="OK";
  char singed[MAXBUFLEN]="Purchase Contract. Signed: Alice Date: Nov. 27, 2018 Signed: Bob Date: Nov. 29, 2018.";
//initialize
  memset(send, 0, MAXBUFLEN);
  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP
  if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("listener: socket");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
    {
    close(sockfd);
    perror("listener: bind");
    continue;
    }
    break;
  }

  if (p == NULL)
  {
    fprintf(stderr, "Server: failed to bind socket\n");
    return 2;
  }
  freeaddrinfo(servinfo);

  printf("Server: waiting to recvfrom...\n");


  addr_len = sizeof their_addr;
  
  //start protocol
  memset(recv, 0, MAXBUFLEN);
  memset(bfkey, 0, MAXBUFLEN);
  recvfrom(sockfd, recv, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);
  keybyte=strlen(recv);
  memcpy(bfkey,recv,keybyte);      //copy key to bfkey 
  printf("\nPlease verify key.\n");
  printf("Key received from Alice:%s\n",recv);
//  printf("cmp:%d",strcmp("mykey",bfkey));
  printf("Key byte is: %hi\n",keybyte);
  printf("press enter to continue");
  getchar();

  //send Ack to alice
  sendto(sockfd,ack, 3, 0, (struct sockaddr *)&their_addr, addr_len) ;
  printf("Ack Sent to alice, waiting for message....\n");
  //receive contract from Alice
  memset(recv, 0, MAXBUFLEN);
  recvfrom(sockfd, recv, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);
  //printf("Encrypted Message received form Alice");
  //printf("Message length:%lu",strlen(recv));
  //strcpy(bfkey,"mykey");

  InitializeBlowfish(bfkey, keybyte);
  ptr=recv;
  lblock=(unsigned long*)ptr;
  rblock=lblock+1;
   for( i=0;i<(MAXBUFLEN/8);i++)       //enciper using blowfish
  {
    Blowfish_decipher(lblock,rblock);
    if(i!=(MAXBUFLEN/8-1))  //handle pointer out of bound
      { 
        lblock=rblock+1;
        rblock=lblock+1;
      }
  }
  printf("Plaintext message is :%s\n",recv);
  printf("\nplease verify and press <enter> to sign the contract\n");
  getchar();



  //sign the contract and send back
  strncpy(send,singed,MAXBUFLEN);
  printf("Signed plaintext contract:%s\n",send);
  ptr=send;
  lblock=(unsigned long*)ptr;
  rblock=lblock+1;
  for( i=0;i<(MAXBUFLEN/8);i++)       //enciper using blowfish
  {
    Blowfish_encipher(lblock,rblock);
      if(i!=(MAXBUFLEN/8-1))
      { 
        lblock=rblock+1;
        rblock=lblock+1;
      }
  }

  //printf("Signed ciphertext contract:%s\n",send);
 printf("send to alice...");
 sendto(sockfd,send, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, addr_len);
 printf("success!\n");
 printf("protocol finished, press enter to exit.\n");
 getchar();
 printf("Thanks for using\n");

  /*
  for( ; ;)
  {
    memset(buf, 0, sizeof(buf));
    memset(recv, 0, sizeof(recv));
    recvfrom(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);
    if ( (childpid = fork ()) == 0 ){
      strncpy(recv, &buf[14], MAXBUFLEN);
      printf("String received from and resent to the client: %s\n", recv);
      if (sendto(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, addr_len) < 0)
      {
        perror("Fail to send message");
        exit(2);
      }
      return 0;
    }
   }
   */

return 0;
}
