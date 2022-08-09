//vwz745, Gilberto Ramirez

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include <dumbnet.h>

#define MAX_ADDR_SIZE 50
#define MAX_SNAPLEN 65535
#define ATTACKER 1
#define VICTIM 0
#define CONTINUOUS 1
#define DELAY 2
#define REACTIVE 3
#define EXACT 4
#define PCAP_MAGIC                      0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC              0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC             0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC     0x34cdb2a1

struct icmp_code {
    unsigned char type;
    const char* string;

};

struct icmp_code icmpcodes[] = {
    {0, "Echo Reply"},
    {3, "Destination Unreachable"},
    {4, "Source Quench"},
    {5, "Route Redirection"},
    {6, "Alternate Host Address"},
    {8, "Echo"},
    {9, "Route Advertisement"},
    {10, "Route Solicitation"},
    {11, "Time Exceeded"},
    {12, "Bad IP Header"},
    {13, "Time Stamp Request"},
    {14, "Time Stamp Reply"},
    {15, "Information Request"},
    {16, "Information Reply"},
    {17, "Address Mask Request"},
    {18, "Address Mask Reply"},
    {30, "Traceroute"},
    {31, "Data Conversion Error"},
    {32, "Mobile Host Redirection"},
    {33, "IPV6 Where are you?"},
    {34, "IPV6 I am here."},
    {35, "Mobile Registration Request"},
    {36, "Mobile Registration Reply"},
    {37, "Domain Name Request"},
    {38, "Domain Name Reply"},
    {39, "Skip"},
    {40, "Photuris"},
    {255, "Unknown"}
};

struct timev {
    unsigned int tv_sec;
    unsigned int tv_usec;
};

struct packet_header {
    struct timev ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

struct route {
    char ip[16];
    char mac[18];
    uint16_t port;
};

static size_t my_read(int fd, void *buffer, size_t size);
static void print_file_header(struct pcap_file_header *pcap_header);
static void print_packet(char *packet_buffer);
static void setfilter();
static void readcfg(char *cfgute);
static void mod_packet(char *packet_buffer, struct packet_header *pkthdr);
static void sniff(u_char *user, struct pcap_pkthdr *h, u_char *packet_buffer);
static void timeout(int signal);
static void proc_switch(int argc, char **argv);

static eth_t *e;
static pcap_t *p;
static struct route v, a, rv, ra;
static char log[128];
static char ebuf[100];
static char interface[32];
static char timing[12];
static int mode;
static int sflag;
struct itimerval t, u, s;
static uint32_t nextack = 0, prevack = -1;
static int state;
static int prevpack;
static int skip;

int main(int argc, char **argv) {

    int fd, i, status;
    unsigned int b_sec, c_sec;
    int b_usec, c_usec, firsttime = 1;
    char packet_buffer[MAX_SNAPLEN];
    struct pcap_file_header pcap_header;
    struct packet_header pkthdr;

    proc_switch(argc, argv);
    signal(SIGALRM, timeout);

    u.it_value.tv_sec = 0;
    u.it_value.tv_usec = 0;
    u.it_interval = u.it_value;
    t.it_value.tv_sec = 5;
    t.it_value.tv_usec = 0;
    t.it_interval = u.it_value;
    s.it_value.tv_sec = 0;
    s.it_value.tv_usec = 500000;
    s.it_interval = u.it_value;
    //iterate through files
    for(i=1;i < argc;i++) {

        if(argv[i][0] == '-')
            continue;

        readcfg(argv[i]);
        //open eth interface
        e = eth_open(interface);

        //opening dump log
        if((fd = open(log, O_RDONLY)) == -1) {
            fprintf(stderr, "Error opening file.\n");
            return 1;
        }
        //read file header
        if((my_read(fd, &pcap_header, sizeof(struct pcap_file_header)) == -1)) {
            fprintf(stderr, "Error reading file.\n");
            return 1;
        }
        
        print_file_header(&pcap_header);
        //p = pcap_open_live(interface, pcap_header.snaplen, 1, 1000, NULL);
        p = pcap_create(interface, ebuf);
        pcap_set_snaplen(p, pcap_header.snaplen);
        pcap_set_promisc(p, 1);
        pcap_set_timeout(p, 100);
        pcap_set_immediate_mode(p, 0);
        pcap_activate(p);
        
        setfilter();

        //read all packets
        int num = 0;
        //read packets
        while((status = read(fd, &pkthdr, sizeof(struct packet_header)))) {

            status = read(fd, packet_buffer, pkthdr.caplen);
            
            if(status == -1) {
                fprintf(stderr, "Error reading packets.\n");
                return 1;
            }
            if(firsttime) {
                firsttime = 0;
                b_sec = pkthdr.ts.tv_sec;
                b_usec = pkthdr.ts.tv_usec;
            }
            c_sec = pkthdr.ts.tv_sec - b_sec;
            c_usec = pkthdr.ts.tv_usec - b_usec;

            while(c_usec < 0) {
                c_usec += 1000000;
                c_sec--;
            }
            //print packet header
            printf("Packet %d\n", num);
            printf("%u.%06u\n", (unsigned) c_sec, (unsigned) c_usec);
            printf("Captured Packet Length = %u\n", pkthdr.caplen);
            printf("Actual Packet Length = %u\n", pkthdr.len);
        
            print_packet(packet_buffer);
            mod_packet(packet_buffer, &pkthdr);

            num+=1;
        }
        //close file
        pcap_close(p);
        close(fd);
    }
    return 0;
}
/*
 * my_read is used to guarantee that we read the specified number of bytes
 * that is requested of the read syscall. If less bytes are read then we
 * loop until all bytes are red or an unknown error occurs. Only error
 * case accounted for is EINTR.
 * Returns -1 on error, otherwise returns bytes read
 */
static size_t my_read(int fd, void *buffer, size_t size) {

    int bytes_read, total_bytes = 0;
    while((bytes_read = read(fd, buffer + total_bytes, size - total_bytes))) {

        //if read is successful, then add to total bytes
        if(bytes_read > 0) {
            total_bytes += bytes_read;
            
            //end loop if we read all bytes requested
            if(total_bytes == size)
                break;
        }
        //if interrupted by a signal, then continue
        else if(bytes_read == -1 && errno == EINTR)
            continue;

        //if eof or some other error occurs
        else
            return bytes_read;
    }
    return total_bytes;
}

static void print_file_header(struct pcap_file_header *pcap_header) {

    if(pcap_header->magic == PCAP_MAGIC)
        printf("PCAP_MAGIC\n");

    else if(pcap_header->magic == PCAP_SWAPPED_MAGIC)
        printf("PCAP_SWAPPED_MAGIC\n");

    else if(pcap_header->magic == PCAP_MODIFIED_MAGIC)
        printf("PCAP_MODIFIED_MAGIC\n");

    else 
        printf("PCAP_SWAPPED_MODIFIED_MAGIC\n");

    printf("Version major number = %hu\n", pcap_header->version_major);
    printf("Version minor number = %hu\n", pcap_header->version_minor);
    printf("GMT to local correction = %u\n", pcap_header->thiszone);
    printf("Timestamp accuracy = %u\n", pcap_header->sigfigs);
    printf("Snaplen = %u\n", pcap_header->snaplen);
    printf("Linktype = %u\n\n", pcap_header->linktype);
}

static void print_packet(char *packet_buffer) {

    //variable hold presentable addresses
    char source[MAX_ADDR_SIZE];
    char dest[MAX_ADDR_SIZE];

    //ethernet header
    struct eth_hdr *ethhdr = (struct eth_hdr *) packet_buffer;
    printf("Ethernet Header\n");
    printf("   eth_src = %s\n", eth_ntop(&(ethhdr->eth_src), source, MAX_ADDR_SIZE));
    printf("   rep_src = %s\n", (strcmp(source, v.mac) == 0) ? rv.mac : ra.mac);
    printf("   eth_dst = %s\n", eth_ntop(&(ethhdr->eth_dst), dest, MAX_ADDR_SIZE));
    printf("   rep_dst = %s\n", (strcmp(dest, v.mac) == 0) ? rv.mac : ra.mac);

    //arp header
    unsigned short ethtype = ntohs(ethhdr->eth_type);
    if(ethtype == ETH_TYPE_ARP) {
        
        struct arp_hdr *arphdr = (struct arp_hdr *) (packet_buffer + ETH_HDR_LEN);
        unsigned short arop = ntohs(arphdr->ar_op);

        printf("   ARP\n");
        
        if(arop == ARP_OP_REQUEST)
            printf("      Arp Request\n");

        else if(arop == ARP_OP_REPLY)
            printf("      Arp Reply\n");

        else if(arop == ARP_OP_REVREQUEST) 
            printf("      Arp Reverse Request\n");

        else 
            printf("      Arp Reverse Reply\n");
    }
    //ip header
    else if(ethtype == ETH_TYPE_IP) {
        struct ip_hdr *iphdr;
        iphdr =  (struct ip_hdr *) (packet_buffer + ETH_HDR_LEN);
        printf("   IP\n");
        printf("      ip len = %hu\n", ntohs(iphdr->ip_len));
        printf("      ip src = %s\n", ip_ntop(&(iphdr->ip_src), source, MAX_ADDR_SIZE));
        printf("      rep_src = %s\n", (strcmp(source, v.ip) == 0) ? rv.ip : ra.ip);
        printf("      ip dst = %s\n", ip_ntop(&(iphdr->ip_dst), dest, MAX_ADDR_SIZE));
        printf("      rep_dst = %s\n", (strcmp(dest, v.ip) == 0) ? rv.ip : ra.ip);

        unsigned char iplen = iphdr->ip_hl * 4;
        //calc next header after ip
        char *nxthdr = ((char *) iphdr) + iplen;

        //icmp header
        if(iphdr->ip_p == IP_PROTO_ICMP) {
            struct icmp_hdr *icmphdr = (struct icmp_hdr *) nxthdr;
            printf("      ICMP\n");

            //get icmp type string literal
            int i;
            for(i = 0;icmpcodes[i].type != 255; i++) {
                if(icmpcodes[i].type == icmphdr->icmp_type) {
                    break;
                }
            }
            printf("         %s\n", icmpcodes[i].string);

        }
        //igmp
        else if(iphdr->ip_p == IP_PROTO_IGMP) {
            printf("      IGMP\n");

        }
        //tcp header
        else if(iphdr->ip_p == IP_PROTO_TCP) {
            struct tcp_hdr *tcphdr = (struct tcp_hdr *) nxthdr;
            printf("      TCP\n");
            printf("         Src Port = %hu\n", ntohs(tcphdr->th_sport));
            printf("         rep_src = %hu\n", (strcmp(source, v.ip) == 0) ? rv.port : ra.port);
            printf("         Dst Port = %hu\n", ntohs(tcphdr->th_dport));
            printf("         rep_dst = %hu\n", (strcmp(dest, v.ip) == 0) ? rv.port : ra.port);
            printf("         Seq = %u\n", ntohl(tcphdr->th_seq));
            printf("         Ack = %u\n", ntohl(tcphdr->th_ack));

        }
        //udp header
        else if(iphdr->ip_p == IP_PROTO_UDP) {
            struct udp_hdr *udphdr = (struct udp_hdr *) nxthdr;
            printf("      UDP\n");
            printf("         Src Port = %hu\n", ntohs(udphdr->uh_sport));
            printf("         Dst Port = %hu\n", ntohs(udphdr->uh_dport));

        }
        else 
            printf("      OTHER\n");

    }
    else 
        printf("   OTHER\n");
   
    printf("\n");
}

static void readcfg(char *cfg) {

    FILE *fp;

    if(!(fp = fopen(cfg, "r"))) {
        fprintf(stderr, "Error opening cfg file!\n");
        exit(1);
    }
    int scan = fscanf(fp, "%s\n%s\n%s\n%hu\n%s\n%s\n%hu\n%s\n%s\n%hu\n%s\n%s\n%hu\n%s\n%s\n"
            , log, v.ip, v.mac, &(v.port)
            , a.ip, a.mac, &(a.port)
            , rv.ip, rv.mac, &(rv.port)
            , ra.ip, ra.mac, &(ra.port)
            , interface, timing);

    if(scan < 15) {
        fprintf(stderr, "Incorrect cfg file.\n");
        exit(1);
    }

    if(strcmp(timing, "continuous") == 0)
        mode = CONTINUOUS;
    else if(strcmp(timing, "delay") == 0)
        mode = DELAY;
    else if(strcmp(timing, "reactive") == 0)
        mode = REACTIVE;
    else if(strcmp(timing, "exact") == 0)
        mode = EXACT;

    fclose(fp);
}

static void mod_packet(char *packet_buffer, struct packet_header *pkthdr) {

    char addr[MAX_ADDR_SIZE];
    struct eth_hdr *ethhdr = (struct eth_hdr *) packet_buffer;
    struct ip_hdr *iphdr =  (struct ip_hdr *) (packet_buffer + ETH_HDR_LEN);
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) (((char *) iphdr) + iphdr->ip_hl * 4);
    unsigned short ethtype = ntohs(ethhdr->eth_type);
    unsigned int size = (iphdr->ip_hl * 4) + (tcphdr->th_off * 4);
    unsigned int payload = ntohs(iphdr->ip_len) - size;

    eth_ntop(&(ethhdr->eth_src), addr, MAX_ADDR_SIZE);
    
    if(strcmp(addr, a.mac) == 0) {
        prevpack = ATTACKER;

        if((payload == 0) && (prevack == nextack) && nextack && !(tcphdr->th_flags & TH_FIN)) {
            skip = 1;
            return;
        }
        skip = 0;
        eth_pton(ra.mac, &(ethhdr->eth_src));
        eth_pton(rv.mac, &(ethhdr->eth_dst));

        if(ethtype == ETH_TYPE_IP) {
            ip_pton(ra.ip, &(iphdr->ip_src));
            ip_pton(rv.ip, &(iphdr->ip_dst));

            if(iphdr->ip_p == IP_PROTO_TCP) {
                tcphdr->th_sport = htons(ra.port);
                tcphdr->th_dport = htons(rv.port);
                tcphdr->th_ack = htonl(nextack);
            }
        }
        ip_checksum((void *) iphdr, ntohs(iphdr->ip_len));

        if(sflag) {

            if(mode == CONTINUOUS)
                eth_send(e, packet_buffer, pkthdr->len);

            else if(mode == DELAY) {
                usleep(500);
                eth_send(e, packet_buffer, pkthdr->len);
            }
            else if(mode == REACTIVE) {
                eth_send(e, packet_buffer, pkthdr->len);
            }
            printf("   Packet sent\n\n");
        }
        if(tcphdr->th_flags & TH_FIN)
            state = TCP_STATE_CLOSING;

        return;
    }
    
    printf("   Packet not sent\n\n");
    if((prevpack == VICTIM) || ((skip == 1) && !(state == TCP_STATE_CLOSING)))
        return;

    prevpack = VICTIM;
    prevack = nextack;
    if(tcphdr->th_flags & TH_FIN && !(state == TCP_STATE_CLOSING))
        setitimer(ITIMER_REAL, &t, NULL);
    else
        setitimer(ITIMER_REAL, &s, NULL);
    pcap_dispatch(p, -1, (pcap_handler) sniff, (u_char *) NULL);
}
static void setfilter() {

    bpf_u_int32 netp, maskp;
    char cmd[100];
    struct bpf_program fp;

    if(pcap_lookupnet(interface, &netp, &maskp, ebuf) < 0) {
        fprintf(stderr,"pcap_lookupnet: %s\n", ebuf);
        exit(1);
    }
    snprintf(cmd, sizeof(cmd), "tcp and dst host %s and src host %s", ra.ip, rv.ip);

    if(pcap_compile(p, &fp, cmd, 0, maskp) < 0 ) {
        fprintf(stderr,"pcap_compile: %s\n", pcap_geterr(p));
        exit(-1);
    }
    if (pcap_setfilter(p, &fp) < 0) {
        fprintf(stderr,"pcap_setfilter: %s\n", pcap_geterr(p));
        exit(-1);
    }
}

static void sniff(u_char *user, struct pcap_pkthdr *h, u_char *packet_buffer) {
    setitimer(ITIMER_REAL, &u, NULL);
    //struct eth_hdr *ethhdr = (struct eth_hdr *) packet_buffer;
    struct ip_hdr *iphdr =  (struct ip_hdr *) (packet_buffer + ETH_HDR_LEN);
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) (((char *) iphdr) + iphdr->ip_hl * 4);
    //unsigned short ethtype = ntohs(ethhdr->eth_type);
    unsigned int size = (iphdr->ip_hl * 4) + (tcphdr->th_off * 4);
    unsigned int payload = ntohs(iphdr->ip_len) - size;
    uint8_t flags = tcphdr->th_flags;

    if(flags & TH_FIN)
        state = TCP_STATE_CLOSING;

    if((flags == (TH_SYN | TH_ACK)) || (state == TCP_STATE_CLOSING)) {
        nextack = ntohl(tcphdr->th_seq);
        nextack++;
        pcap_breakloop(p);
    }
    nextack+=payload;
}
static void proc_switch(int argc, char **argv) {

    int i;
    for(i =1; i < argc; i++) {

        if(strcmp(argv[i], "-s") == 0) {
            sflag = 1;
            return;
        }
    }
}
static void timeout(int signal) {
    pcap_breakloop(p);
}
