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
#include <sys/time.h>
#include "BLOWFISH.H"
#include "BLOWFISH.C"



// the port users will be connecting to
#define SERVERPORT "10010"
#define MAXLINE 512



int main(int argc, char *argv[])
{
  int i;
  int sockfd;
  struct timeval start, end;
  short mes_len;
  int n, seq_num = 0;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  char sendline[MAXLINE], recvline[MAXLINE];
  int rv;
  long diff, recv_time, send_time;
  FILE* Infile;    //input file pointer
  char *content;// store file content, dynamic allocated
  //char recvcontent[MAXLINE];
  //int fsize;      //file size
  //int buffsize;      //buffer size used to feed blowfish program, must 8x
  //int bnum;   //blowfish block number
  char bfkey[MAXLINE];
  short bfbyte;
  unsigned long *lblock,*rblock;
  void *ptr; //used for type convert
//handle exception
  if (argc != 2)
  {
    fprintf(stderr,"usage: ./client11b <IP address>\n");
    exit(1);
  }

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
    perror("Fail to create a socket");
    exit(2);
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if ((rv = getaddrinfo(argv[1], SERVERPORT, &hints, &servinfo)) != 0) 
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for(p = servinfo; p != NULL; p = p->ai_next) 
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) 
    {
      perror("talker: socket");
      continue;
    }
    break;
  }
  if (p == NULL) 
  {
    fprintf(stderr, "talker: failed to create socket\n");
    return 2;
  }


  addr_len = sizeof their_addr;





  //start transmission protocol
  printf("Socket created, starting Blowfish protocol...\n" );
  if((Infile = fopen("contract.txt", "r"))==NULL)
  {
    perror("Error in reading file, socket closed.");
    exit(-1);
  }
  printf("Please enter your encryption key:\n");
  // fflush(stdin);
  // fgets(bfkey, MAXLINE, stdin);
  // if ((strlen(bfkey) > 0) && (bfkey[strlen (bfkey) - 1] == '\n'))
  //       bfkey[strlen (bfkey) - 1] = '\0';
  //scanf("%s",bfkey);
  memset(bfkey,0,MAXLINE);
  strcpy(bfkey,"mykey");
  bfbyte=strlen(bfkey);
  printf("The key length is %hi\n",bfbyte);
  printf("Your key is:%s\n",bfkey);
  //printf("cmp:%d",strcmp(bfkey,"mykey"));
  sendto(sockfd,bfkey,bfbyte, 0, p->ai_addr, p->ai_addrlen);  //send key to Bob
  //receive ACk from bob
  memset(recvline,0,MAXLINE);
  recvfrom(sockfd, recvline, MAXLINE, 0, p->ai_addr, &p->ai_addrlen);
  printf("ACK received is:");
  puts(recvline);
  printf("\npress enter to continue\n");
  getchar();
  

  // fseek(Infile, 0L, SEEK_END);
  // fsize = ftell(Infile);//caculate size of the file 
  // rewind(Infile);
  // if(fsize%8==0)
  // {
  //   bnum=fsize/8;
  // }
  // else
  // {
  //   bnum=(fsize/8)+1;
  // }
  // buffsize = bnum*8;//caculate buffersize to hold information
  // content = (char*) malloc(buffsize*sizeof(char));
  //memset(content,0,buffsize*sizeof(char));//initialize buffer
  fread(sendline,1,MAXLINE,Infile);//read file content to buffer
  InitializeBlowfish(bfkey, bfbyte); //INITIALIZE BLOWFISH S AND P BLOCK
  printf("plaintext:\n%s\n",sendline);
  printf("plaintextlength:\n%lu\n",strlen(sendline));
  ptr=sendline;
  lblock=(unsigned long*)ptr;	
  rblock=lblock+1;
  for(i=0;i<MAXLINE/8;i++)       //enciper using blowfish
  {
    Blowfish_encipher(lblock,rblock);
    if(i!=(MAXLINE/8-1))
      { lblock=rblock+1;
        rblock=lblock+1;
    }
  }
  //printf("ciphertext:\n%s\n",sendline);
  //printf("ciphertext length:\n%lu\n",strlen(sendline));
  sendto(sockfd, sendline, MAXLINE, 0, p->ai_addr, p->ai_addrlen);
  printf("Message sent to bob, waiting for response....\n");
  //waiting for bob to sign the contract

  memset(recvline, 0, MAXLINE);//flash receive buffer
  recvfrom(sockfd, recvline, MAXLINE, 0, p->ai_addr, &p->ai_addrlen);
  printf("Message from Bob receiced:%s\n",recvline);


  //strncpy(recvcontent, recvline, MAXLINE);
  printf("Start decryption\n");
  ptr=recvline;
  lblock=(unsigned long*)ptr; 
  rblock=lblock+1;
  for(i=0;i<(MAXLINE/8);i++)       //decipher using blowfish
  {
    Blowfish_decipher(lblock,rblock);
    if(i!=(MAXLINE/8-1))
      { 
        lblock=rblock+1;
        rblock=lblock+1;
      }
  }
  printf("Message from Bob decrypted:%s\n",recvline);
  printf("press enter to close communication\n");
  getchar();
  //write to file


/*
  while (fgets(send, MAXLINE, stdin) != NULL)
  {
    gettimeofday(&start, NULL);
    mes_len = strlen(send);
    send_time = start.tv_sec * 1000 + start.tv_usec / 1000;
    memcpy(sendline, &mes_len, 2);
    memcpy(sendline + 2, &seq_num, 4);
    memcpy(sendline + 6, &send_time, 8);
    strncpy(&sendline[14], send, MAXLINE);
    // send input to server
    sendto(sockfd, sendline, MAXLINE + 14, 0, p->ai_addr, p->ai_addrlen);
    memset(sendline, 0, sizeof(sendline));
    seq_num++;
    if (recvfrom(sockfd, recvline, MAXLINE, 0, p->ai_addr, &p->ai_addrlen) == -1)
    { //waiting to receive echo from server
      //error: server terminated prematurely
      perror("The server terminated prematurely");
      exit(4);
    }

    // fputs(recvline, stdout);
    gettimeofday(&end, NULL);
    recv_time = end.tv_sec * 1000 + end.tv_usec / 1000;
    memcpy(&send_time, recvline + 6, 8);
    // printf("send time: %ld\n", send_time);
    strncpy(recv, &recvline[14], MAXLINE);
    printf("String received from the server: %s", recv);
    diff = recv_time - send_time;
    printf("Round trip time: %ld ms\n", diff);
    memset(recvline, 0, sizeof(recvline));
    memset(recv, 0, sizeof(recv));
  }
  */
close(sockfd);
return 0;
}
