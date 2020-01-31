#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define PERTURB_SHIFT 5
#define THRESHOLD_MULTIPLIER 1.5 // about 70% of the table is filled


unsigned int hash(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

int insert_ip_into_table(int ip, unsigned int * table, int size) {
    unsigned int h = hash(ip);
    int i=0, loc;

    for (unsigned int perturb = h; perturb >>= PERTURB_SHIFT;) { // just like python
        i = (i << 2) + i + perturb + 1;
        loc = i % size;
        if (table[loc] == 0) {
            table[loc] = ip;
            return 1;
        }
        if (table[loc] == ip) {
            return 0;
        }
    }
    return 0;
}

unsigned int * resize_table(unsigned int *old_table, int old_size, int new_size) {
    unsigned int * new_table = calloc(new_size, sizeof(unsigned int));

    for (int i=0; i<old_size; i++) {
        insert_ip_into_table(
            old_table[i],
            new_table,
            new_size
        );
    }
    return new_table;
}

int main(int argc, char ** argv) {
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    struct in_addr local_ip;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char *filter_exp = calloc(80, sizeof(char));	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    unsigned char *packet;		/* The actual packet */
    struct sniff_ip *ip; 

    if (argc != 3) {
        fprintf(stderr, "%s <dev> <dotted-address>\n", argv[0]);
        exit(5);
    }
    dev = argv[1];
    strcpy(filter_exp, "ip host ");
    strcat(filter_exp, argv[2]);
    inet_aton(argv[2], &local_ip);

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}


	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(6);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(2);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(3);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(4);
	}

    int size = 8;
    unsigned int *table = calloc(size, sizeof(unsigned int));
    insert_ip_into_table(local_ip.s_addr, table, size);
    int filled_buckets = 1;
    unsigned int ip_src, ip_dst;

    while (1) {
        if (THRESHOLD_MULTIPLIER * filled_buckets > size) {
            table = resize_table(table, size, size*2);
            size *= 2;
        }
        packet = pcap_next(handle, &header);

        int size_ip;
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            continue;
        }
        ip_src = ip->ip_src.s_addr;
        ip_dst = ip->ip_dst.s_addr;
	
        if (ip_src>0) {
            if (insert_ip_into_table(ip_src, table, size) == 1) {
                filled_buckets++;
                printf("%s\n", inet_ntoa(ip->ip_src));
            } 
        }
        if (ip_dst>0) {
            if (insert_ip_into_table(ip_dst, table, size) == 1) {
                filled_buckets++;
                printf("%s\n", inet_ntoa(ip->ip_dst));
            } 
        }
        fflush(stdout);
    }
    	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
    return 0;
}
