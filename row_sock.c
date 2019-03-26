#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> 					//For standard things
#include<stdlib.h>    				//malloc
#include<string.h>    				//strlen
 
#include<netinet/ip_icmp.h>   		//Provides declarations for icmp header
#include<netinet/udp.h>   			//Provides declarations for udp header
#include<netinet/tcp.h>   			//Provides declarations for tcp header
#include<netinet/ip.h>    			//Provides declarations for ip header
#include<netinet/if_ether.h>  		//For ETH_P_ALL
#include<net/ethernet.h>  			//For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
 
 
#include <sys/ioctl.h>
#include <net/if.h> 

 
#include <linux/if_packet.h>
 
 //test outside edit	   
	   
	   
#define IS_ROUTABLE(LOCAL_IP, IP, NET_MASK) (LOCAL_IP & NET_MASK) == (IP & NET_MASK)

 
void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);
static int in_cksum(u_short *addr, int len);
void print_udp_packet_crt(unsigned char *Buffer , int Size);
void print_ip_header(unsigned char* Buffer, int Size);
void print_ethernet_header(unsigned char* Buffer, int Size);


FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
 
 
//one sock recive all
 
int main_old()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct ifreq ethreq;
	struct sockaddr_ll sll;
	
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
      //  data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		data_size = recv(sock_raw , buffer , 65536 , 0);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct ifreq ethreq;
	struct sockaddr_ll sll;
	
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	//int sock_raw = socket( AF_PACKET , SOCK_STREAM , 0) ;
	struct ifreq ifr;
	struct ifreq Interface;
	
    memset(&ifr, 0, sizeof(struct ifreq));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0");
    ioctl(sock_raw, SIOCGIFINDEX, &ifr);
	
	strncpy(ethreq.ifr_name, "eth0", IFNAMSIZ);
	if (ioctl(sock_raw, SIOCGIFFLAGS, &ethreq) == -1) 
	{
		perror("ioctl");
	}

	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock_raw, SIOCSIFFLAGS, &ethreq) == -1) {
		perror("ioctl");
	}
	
	
	memset(&sll , 0x00, sizeof( struct sockaddr_ll));

	sll.sll_family = PF_PACKET; 
// also tried with AF_PACKET


	sll.sll_ifindex =  ifr.ifr_ifindex;
// returns valid ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if((bind(sock_raw , (struct sockaddr *)&sll , sizeof(sll))) ==-1)
	{
		perror("bind: ");
		printf("error bind to dev\n");
		exit(-1);
	}


	 
     
    printf("Ready to run\n");
	getchar();	
	
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
		//data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		data_size = recv(sock_raw , buffer , 65536 , 0);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
		//PrintData (buffer , data_size);
		validated_packet(buffer , data_size);
     //   ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}




void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
  
	switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
			fprintf(logfile, "ICMP\t");
            print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
			fprintf(logfile, "IGMP\t");
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
			fprintf(logfile, "TCP \t");
        //    print_tcp_packet(buffer , size);
		//	print_ip_header(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
			fprintf(logfile, "UDP \t");
            print_udp_packet(buffer , size);
            break;
        case 103:
			fprintf(logfile, "PIM \t");
			break;
        default: //Some Other Protocol like ARP etc.
            ++others;
			fprintf(logfile, "OTHR\t");
            break;
    }
	
	print_ethernet_header(buffer , size);
	print_ip_header(buffer , size);
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

int validated_DNS_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	printf("validated_DNS_packet->Enter\n");
	
	print_udp_packet_crt(Buffer, Size);
	
	PrintData((unsigned char*)udph, ntohs(udph->len));
	
}//function

int validated_packet(unsigned char* Buffer, int Size)
{
	int i = validated_ethernet_header(Buffer, Size);
	 
	switch(validated_IP_packet(Buffer, Size))
	{
		case 17:	//udp
		{
			switch(validated_UDP_packet(Buffer, Size))
			{
				case 53:			//port
					validated_DNS_packet(Buffer, Size);
				break;
				
				default: //Some Other Protocol like ARP etc.
				
				break;
			}//switch
		}
		break;
		default:
			return 0;
		break;	
	}
	
}

unsigned short udp_sum_calc(unsigned short len_udp, unsigned short src_addr[],unsigned short dest_addr[], int padding, unsigned short buff[])
{
unsigned short prot_udp=17;
unsigned short padd=0;
unsigned short word16;
unsigned long sum;	
	
	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if (padding&1==1){
		padd=1;
		buff[len_udp]=0;
	}
	
	//initialize sum to zero
	sum=0;
	
	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (i=0;i<len_udp+padd;i=i+2){
		word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum = sum + (unsigned long)word16;
	}	
	// add the UDP pseudo header which contains the IP source and destinationn addresses
	for (i=0;i<4;i=i+2){
		word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
		sum=sum+word16;	
	}
	for (i=0;i<4;i=i+2){
		word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
		sum=sum+word16; 	
	}
	// the protocol number and the length of the UDP packet
	sum = sum + prot_udp + len_udp;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
    	while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);
		
	// Take the one's complement of sum
	sum = ~sum;

return ((unsigned short) sum);
}

unsigned short csum_1 (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--) sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

//! \brief
//!     Calculate the UDP checksum (calculated with the whole
//!     packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;
 
         // Calculate the sum                                            //
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
         }
 
         if ( len & 1 )
                 // Add the padding if the packet lenght is odd          //
                 sum += *((uint8_t *)buf);
 
         // Add the pseudo-header                                        //
         sum += *(ip_src++);
         sum += *ip_src;
 
         sum += *(ip_dst++);
         sum += *ip_dst;
 
         sum += htons(IPPROTO_UDP);
         sum += htons(length);
 
         // Add the carries                                              //
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);
 
         // Return the one's complement of sum                           //
         return ( (uint16_t)(~sum)  );
}

int validated_UDP_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen = 0x00;   
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	unsigned short org_udp_sum = udph->check;
	
	//printf("validated_UDP_packet->Enter\n");
	
	udph->check = 0x00;
	unsigned short udp_sum = udp_checksum(udph, ntohs(udph->len), iph->saddr, iph->daddr);
	
	if(udp_sum == org_udp_sum)
	{
		//printf("Validated UDP check sum: 0x%X, 0x%X OK\n", ntohs(org_udp_sum), ntohs(udp_sum));
		udph->check = org_udp_sum;
	//	printf("validated_UDP_packet->Exit with %d\n", ntohs(udph->dest));
		return ntohs(udph->dest);
	}
	else
	{
		//print_udp_packet_crt(Buffer, Size);
		printf("Invalidated UDP check sum: 0x%X/0x%X, 0x%X\n", ntohs(org_udp_sum), org_udp_sum, udp_sum);
		return 0;
	}//if
}//function

int validated_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	switch((unsigned short)eth->h_proto)
	{	
		case 0x08:		/* 0x0800 Internet Protocol packet	*/
			return (int)eth->h_proto;//ETH_P_IP;
		break;
		default:
			return 0;
		break;
	}//switch
}//function


unsigned short checksum1(const char *buf, unsigned size)
{
	unsigned sum = 0;
	int i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

unsigned short checksum2(const char *buf, unsigned size)
{
	unsigned long long sum = 0;
	const unsigned long long *b = (unsigned long long *) buf;

	unsigned t1, t2;
	unsigned short t3, t4;

	/* Main loop - 8 bytes at a time */
	while (size >= sizeof(unsigned long long))
	{
		unsigned long long s = *b++;
		sum += s;
		if (sum < s) sum++;
		size -= 8;
	}

	/* Handle tail less than 8-bytes long */
	buf = (const char *) b;
	if (size & 4)
	{
		unsigned s = *(unsigned *)buf;
		sum += s;
		if (sum < s) sum++;
		buf += 4;
	}

	if (size & 2)
	{
		unsigned short s = *(unsigned short *) buf;
		sum += s;
		if (sum < s) sum++;
		buf += 2;
	}

	if (size)
	{
		unsigned char s = *(unsigned char *) buf;
		sum += s;
		if (sum < s) sum++;
	}

	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 32;
	t1 += t2;
	if (t1 < t2) t1++;
	t3 = t1;
	t4 = t1 >> 16;
	t3 += t4;
	if (t3 < t4) t3++;

	return ~t3;
}

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/

unsigned short csum(unsigned char *ptr,int nbytes) {
  long sum;
  unsigned short oddbyte;
  short answer;

  //Debug info
  //hexdump((unsigned char *) ptr, nbytes);
  //printf("csum nbytes: %d\n", nbytes);
  //printf("csum ptr address: %p\n", ptr);

  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(unsigned short)~sum;

  return(answer);
}
uint16_t ip_checksum_3(void* vdata, int length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;
	int i;
    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
static int
in_cksum(u_short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}

int validated_IP_packet(unsigned char* Buffer, int Size)
{
	if(validated_ethernet_header(Buffer, Size) == 0x08)
	{
		struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
		unsigned short org_check_sum = iph->check;
		
		//iph->version = 0x04;
		iph->check = 0;
		
		//unsigned short ip_sum =	csum((unsigned char *) iph, iph->tot_len); 
		//unsigned short ip_sum = checksum1((unsigned char *) iph, iph->tot_len); 
		//unsigned short ip_sum = checksum2(iph, iph->tot_len); 
		//unsigned short ip_sum = ip_checksum_3(iph, iph->tot_len); 
		//unsigned short ip_sum = in_cksum(iph, iph->tot_len); 
		unsigned short ip_sum = in_cksum((u_short*)iph, sizeof(struct iphdr)); 
		
		//printf("validated_IP_packet ip version: %d\n", iph->version);
		
		if(iph->version  == 0x04)
		{
			//printf("validated_IP_packet one\n");
			if(org_check_sum == ip_sum)
			{
				//printf("validated_IP_packet iph->protocol: %d\n",iph->protocol);
				switch(iph->protocol)
				{	
					//we need DNS, NTP, UDP and TCP-stream
					case 1:  //ICMP Protocol
						return 1;
					break;
					case 17: //UDP Protocol
						return 17;
					break;
					
					default:
						//printf("validated_IP_packet default\n");
						return 0;
					break;
				}//switch(iph->protocol)
			}//if(iph-.check == ip_sum)
			else
			{
				printf("Invelad check sum: 0x%X vs 0x%X\n", ntohs(org_check_sum), ip_sum);
				return 0;
			}
		}//if(iph->version == 4)
	}
	else
	{
		return 0;
	}
	
}//function

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
 // fprintf(logfile , "\n");
 // fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \t", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \t", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "%u \t",(unsigned short)eth->h_proto);
}

void print_ethernet_header_long(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
   // print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
    unsigned int SubMask = 0x0000FFFF;
	unsigned int ip1;
	unsigned int ip2;
	
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
        
    //fprintf(logfile , "\n");
    //fprintf(logfile , "IP Header\t\n");
	//fprintf(logfile , "   |-IP Version        \t: %d\n",(unsigned int)iph->version);
    //fprintf(logfile , "   |-IP Header Length  \t: %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    //fprintf(logfile , "   |-Type Of Service   \t: %d\n",(unsigned int)iph->tos);
    //fprintf(logfile , "   |-IP Total Length   \t: %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    //fprintf(logfile , "   |-Identification    \t: %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    //fprintf(logfile , "   |-TTL      	\t\t: %d\n",(unsigned int)iph->ttl);
    //fprintf(logfile , "   |-Protocol 	\t\t: %d\n",(unsigned int)iph->protocol);
    //fprintf(logfile , "   |-Checksum 	\t\t: %d\n",ntohs(iph->check));
    //fprintf(logfile , "   |-Source IP        \t: %s\n",inet_ntoa(source.sin_addr));
    //fprintf(logfile , "   |-Destination IP   \t: %s\n",inet_ntoa(dest.sin_addr));
	
	ip1 = source.sin_addr.s_addr;
	ip2 = dest.sin_addr.s_addr;
	
	fprintf(logfile , "Source IP        \t %-15s\t", inet_ntoa(source.sin_addr));
    fprintf(logfile , "Destination IP   \t %-15s\t", inet_ntoa(dest.sin_addr));
	IS_ROUTABLE (ip1, ip2, SubMask) == 0 ? fprintf(logfile, " Routable\n") : fprintf(logfile, " Non Routable\n");
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
         
		 
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                         
    fprintf(logfile , "\n###########################################################");
}
 
void print_udp_packet_crt(unsigned char *Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    printf("\n\n***********************UDP Packet*************************\n");
     
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
        
    printf("\n###########################################################\n");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
 
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
     
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    //fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , Size - header_size);
     
    fprintf(logfile , "\n###########################################################");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile , "\n");
         
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile , "\n");
 
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(logfile , "\n###########################################################");
}
 
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
}
