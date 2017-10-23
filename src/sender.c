/*
    Raw UDP sockets
*/
#include<stdio.h> //for printf
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>
#include "selectserver.c"
#define TAILLE_MAX 512

/*
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

/*
    Generic checksum calculation function
*/
void readFileToSend(char *dt, char nameFile[]){
    FILE* fichier = NULL;

    fichier = fopen(nameFile, "r");

    if (fichier != NULL)
    {
        if(fgets(dt, TAILLE_MAX, fichier) != NULL) // On lit le fichier tant qu'on ne reçoit pas d'erreur (NULL){
            perror("readFile : get");


        printf("\n contenu packet : \n %s",dt);
        long t = ftell(fichier);
        printf("\n %ld",t);

        fclose(fichier);
    }

}

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

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
    answer=(short)~sum;

    return(answer);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,"usage: talker hostname message\n");
        exit(1);
    }

    char  *payload , *pseudogram, *ptr;
    char packet[4096] , source_ip[32], dest_ip[32] , filename[20];

    int compt, port;
    for(compt =1; compt < argc; compt ++){
        printf("\n numero %d , argument %s",compt,argv[compt]);


        if(strcmp(argv[compt], "<") == 0){
                strcpy(filename,argv[++compt]);

        } else if(strcmp(argv[compt],"-f") == 0){
                strcpy(filename,argv[++compt]);

        } else if(strcmp(argv[compt],"2>") == 0){

                printf("\n fichier log");
        } else {
            strcpy(dest_ip, argv[compt]);
            port = (int) atol(argv[++compt]);
        }
    }
    printf("\n ip dest : %s",dest_ip);
    printf("\n filename : %s",filename);
    printf("\n port : %i",port);




    int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }



    //zero out the packet buffer
    memset (packet, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) packet;

    //UDP header
    struct udphdr *udph = (struct udphdr *) (packet + sizeof (struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;
    returnMyIp(source_ip);
    //Data part pointe a la fin du packet udph
    payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    char dt[512] = {0};
    readFileToSend( dt , filename);
    strcpy(payload , dt);
    printf("\n payload : %s",payload);


    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(payload);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum ((unsigned short *) packet, iph->tot_len);

    //UDP header
    udph->source = htons (port);
    udph->dest = htons (port);
    udph->len = htons(8 + strlen(payload)); //tcp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header

    //Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(payload) );

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(payload);
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(payload));

    udph->check = csum( (unsigned short*) pseudogram , psize);

    //while (1)
    {
        //Send the packet
        if (sendto (s, packet, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }
    }

    return 0;
}

