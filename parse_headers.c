#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> //library for parsing pcap files

#include <netinet/in.h>
//#include <sys/param.h>
//#include <sys/time.h>
//#include <sys/types.h>


/*****************************************
 *
 * packet_headers.c
 * 
 * P538 - Computer Networks 
 * Original author: Adam J. Aviv
 *
 *
 * Reads a pcap trace and prints out the packet headers, both 
 * the Ethernet and TCP/IP headers
 *
 *
 * USAGE: ./packet_headers trace.pcap
 ****************************************/


/***************************************
 *
 * Structs to represent headers
 *
 ***************************************/
struct ethernet_h{
  
///////// http://stpetrus27.wordpress.com/2011/01/04/cc-ethernet-ii-ip-tcp-structure/


  // FILL ME IN!
   unsigned char desAdd[6];
   unsigned char srcAdd[6];
   unsigned short type;		 // short 

};

struct ip_h{
  /*need these to compute packet lengths*/
  unsigned char v_ihl; //internet header length
  unsigned char service;
  unsigned short total_len; 
  
  unsigned short identification;	
  
  // FILL ME IN! 
			
  unsigned short Flag_FragmentOffset;
  unsigned char Time_to_Live;
  unsigned char Protocol;
  unsigned short Header_Checksum;	
  unsigned int srcAdd;
  unsigned int  desAdd;	
  	
  unsigned int option_padd;  // options and padding together 
  //
  //unsigned char options[3];
  //unsigned char padding[1];

};

struct tcp_h{

  // FILL ME IN!
 unsigned short srcPort;
 unsigned short desPort;
 unsigned  int seqNum;
 unsigned int ackNum;	
 unsigned char dataOffest;
 unsigned char resv;
 unsigned short win;
 unsigned short checkSum;
 unsigned short urgentPointer;
 unsigned int op_pad;
 
};




void convert_int_to_ip (int ipInt, unsigned short* ipSp)
{
	// http://www.cplusplus.com/forum/general/9403/

        // This function conver int " 4 bytes " into seprated short int where each short int conatins part of the ip
        // It take cares of order of the bytes also.
        
        ipSp[0] = ipInt & 0xff;
	ipSp[1] = (ipInt & (0xff << 8)) >> 8;
	ipSp[2] = (ipInt & (0xff << 16)) >> 16;
        ipSp[3] = (ipInt & (0xff << 24)) >> 24;
	
	
}


int main(int argc, char * argv[]){
  /*Stuff needed to parse file*/
  pcap_t *pcap;
  char errbuf [PCAP_ERRBUF_SIZE];
  const unsigned char * packet;
  struct pcap_pkthdr header;
  int i;

  /*Header Structs*/
  struct ethernet_h * ethernet; //;;p;;/'
  struct ip_h * ip;
  struct tcp_h * tcp;
  struct tcl_info *tcl;  
  struct tcl_info *tcl1;    
  struct tcl_info2 *tcl2;    
  /*opening trace file*/
  if ((pcap = pcap_open_offline(argv[1],errbuf)) == NULL){
    fprintf(stderr, "ERROR: reading pcap file %s : %s\n", 
            argv[0],errbuf);
    exit(1);
  }

 
  /* reading one packet at a time and counting packets seen */
  for (i = 0; (packet = pcap_next(pcap,&header)) != NULL; i++){

    printf("-------- Packet %d ------------\n",i);
    printf("Size: %d bytes\n",header.len);

    /*ethernet header memory map*/
    ethernet = (struct ethernet_h *) (packet);
	
    //TODO: print src and dest MAC
	
	/////
	//http://stackoverflow.com/questions/5661101/how-to-convert-an-unsigned-character-array-into-a-hexadecimal-string-in-c
        
        // convert src address and destination address to hexa to be printed in this format
	char charConverted[12];
        int ii;
	for(ii=0;ii<6;ii++) {
	   sprintf(&charConverted[ii*2], "%02x", ethernet->srcAdd[ii]);	
	}
	//// print the mac address on correct format ..:..:..:.. 	
	  printf("MAC src: ");
	  for( ii=0;ii<10;ii=ii+2) 	 	
	  	printf("%c%c:",charConverted[ii],charConverted[ii+1]);	
	  printf("%c%c",charConverted[ii],charConverted[ii+1]);	 
	  printf("\n");
	
	for(ii=0;ii<6;ii++) {
	    sprintf(&charConverted[ii*2], "%02x", ethernet->desAdd[ii]);
	   	}
	//// print the Mac for destination
	  printf("MAC dest: ");
	  for(ii=0;ii<10;ii=ii+2) 	 	
	  	printf("%c%c:",charConverted[ii],charConverted[ii+1]);	
	  printf("%c%c",charConverted[ii],charConverted[ii+1]);	 
	  printf("\n");	
	
        /*cacluate start of IP header and map to struct*/
        ip = (struct ip_h *) (packet + sizeof(struct ethernet_h));
 
        //TODO: print src and dest IP
        // conver the source ip and destination ip to correct formate
        unsigned short* ipsrc= malloc (4* sizeof(short));
	unsigned short* ipdst= malloc (4* sizeof(short));
	convert_int_to_ip(ip->srcAdd,ipsrc) ;   
	convert_int_to_ip(ip->desAdd,ipdst) ;   		
	// print the ip source and ip des and free the memory of temp pointers.
	printf("IP src: %u.%u.%u.%u\n", ipsrc[0], ipsrc[1], ipsrc[2], ipsrc[3]);	
	free(ipsrc);	
	printf("IP dest: %u.%u.%u.%u\n", ipdst[0], ipdst[1], ipdst[2], ipdst[3]);
	free(ipdst);	
	
        
        tcp = (struct tcp_h *) (packet + sizeof(struct ethernet_h) + sizeof(struct ip_h));

       //TODO: print src and dest port number
	//https://github.com/android/platform_external_tcpdump/blob/master/addrtoname.c   .
	
         unsigned ipLenHeader=(((ip)->v_ihl) & 0x0f);
         //printf("Ip headel length: %u\n",ipLenHeader);   
       
        if (ipLenHeader == 5) {

        int srcdesPort= ip->option_padd;   
        unsigned short tempsrc = ((unsigned short *)(&srcdesPort))[0];
        unsigned short tempsrc_swapped = ( ((tempsrc<<8) & 0xFFFF) | ((tempsrc >>8) & 0xFFFF));
        printf("Src port: %u\n",tempsrc_swapped);   
        unsigned short tempdes = ((unsigned short *)(&srcdesPort))[1];
        unsigned short tempdes_swapped = ( ((tempdes<<8) & 0xFFFF) | ((tempdes >>8) & 0xFFFF));
        printf("Des port: %u\n",tempdes_swapped);   
        }
        else{

       
        unsigned short tempsrc = tcp->srcPort;
        // swap the bytes
        unsigned short tempsrc_sawpped = ( ((tempsrc<<8) & 0xFFFF) | ((tempsrc >>8) & 0xFFFF));
        // print the scr port after swapped the bytes
        printf("Src port: %u\n",tempsrc_sawpped);   
        unsigned short tempdes = tcp->desPort;
        // print the des. port after swapped the bytes
        unsigned short tempdes_swapped = ( ((tempdes<<8) & 0xFFFF) | ((tempdes >>8) & 0xFFFF));
        printf("Des port: %u\n",tempdes_swapped);  
        
        }
        
                
    	
	      
	//TODO: TLS 1.0
        int minus4byte=0; // this variable used to substract -4 bytes from ip_h length if length of ip header variable is 5
        
        if (ipLenHeader == 5)
        {
          minus4byte=4  ;
        }
            
        // added 8 bytes becuase the tcp_h might be 32 byte not 24 byte.  There is 8 bytes for options, So we can get the correct position for  TLS pointer data.    
        unsigned char* m1=  (unsigned char*) (packet + sizeof(struct ethernet_h)+ sizeof(struct ip_h)-minus4byte  + sizeof(struct tcp_h)+8);
        
        unsigned char* m2=  (unsigned char*) (m1 +1);
        unsigned char* m3=  (unsigned char*) (m1+ 2);
        
        int cc= (int)(*m2);
        //printf("ttt%i\n",cc);
         if (header.len > 66) 
         {
             // check for TLS in that packet
             if ( (  ((int)(*m2))==(int) 3  ) && (  ((int)(*m3))==(int) 1  ) )
                {
                 printf("TLS 1.0: Yes\n");
                 
                }
            else
                {
                printf("TLS 1.0: No\n");
                }
            }
        else
            {
            //  No TLS in this packet
             printf("TLS 1.0: No\n");
            }
        
          
        
        
            
        
    }

}
