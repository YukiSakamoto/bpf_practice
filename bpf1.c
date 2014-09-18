#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <err.h>

/*  http://bastian.rieck.ru/howtos/bpf/
 */

#define EXCHANGE_BYTE_2(x) (x<<8+x>>8)

#define SWAP_ENDIAN_2(x) (x<<8|x>>8)
#define SWAP_ENDIAN_4(x) (x<<24|x>>8)

inline
unsigned short swap_endian16(unsigned short value)
{
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF);
}

inline
unsigned int swap_endian32(unsigned int value)
{
    return (value >> 24) | (value << 24) | ((value >> 8) & 0xFF00) | ((value << 8) & 0xFF0000);
}

struct ad {
    uint8_t a[4];
};

void print_ip_header(char *ptr)
{
    struct ip *ip_hdr = (struct ip*)ptr;
    struct in_addr ip_src = ip_hdr->ip_src;
    struct in_addr ip_dst = ip_hdr->ip_dst;
    struct ad *addr_s = (struct ad*)&ip_src;
    struct ad *addr_d = (struct ad*)&ip_dst;
    char src_ipaddr_buf[128];
    char dst_ipaddr_buf[128];
    char buf1[1024];
    char buf2[1024];
    strcpy(src_ipaddr_buf, inet_ntoa(ip_src));
    strcpy(dst_ipaddr_buf, inet_ntoa(ip_dst));
    /*
    printf("src: %s\t", inet_ntoa(ip_src) );
    printf("dst: %s\n", inet_ntoa(ip_dst) );
    */

    printf("IP Header: %s --> %s \n", src_ipaddr_buf, dst_ipaddr_buf);
    /*
    printf("source: %o:%o:%o:%o dest: %o:%o:%o:%o\n",
            addr_s->a[0], addr_s->a[1], addr_s->a[2], addr_s->a[3], 
            addr_d->a[0], addr_d->a[1], addr_d->a[2], addr_d->a[3]  );
            */
}

void *print_ether_header(struct ether_header *eh)
{
    int i;
    char *eh_type;
    void (*packet_handler)(char *ptr);
    if (eh == NULL)
        return NULL;
    switch( ntohs( (u_short)eh->ether_type ) ) {
        case ETHERTYPE_PUP: 
            eh_type = "PUP";    break;
        case ETHERTYPE_IP:
            print_ip_header( (char*)eh + sizeof(struct ether_header) );
            //print_ip_header( (char*)(eh + 1) );
            eh_type = "IP";     break;
        case ETHERTYPE_ARP:
            eh_type = "ARP";    break;
        case ETHERTYPE_REVARP:
            eh_type = "REVARP"; break;
        case ETHERTYPE_VLAN:
            eh_type = "VLAN";   break;
        case ETHERTYPE_IPV6:
            eh_type = "IPV6";   break;
        case ETHERTYPE_PAE:
            eh_type = "PAE";    break;
        case ETHERTYPE_RSN_PREAUTH:
            eh_type = "802.11i";break;
        case ETHERTYPE_LOOPBACK:
            eh_type = "Loopbak(for tests)"; break;

        case ETHERTYPE_TRAIL:
            eh_type = "Trailer packet"; break;
        case ETHERTYPE_NTRAILER:
            eh_type = "NTtailer";break;
        default:
            eh_type = "Unknown";    break;
    }

    printf("ether_header: source: %02x:%02x:%02x:%02x:%02x:%02x -> dest: %02x:%02x:%02x:%02x:%02x:%02x type: %s ",
            eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
            eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
            eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
            eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
            eh_type
            );
    if (strcmp(eh_type, "Unknown") == 0) {
        printf("type_num = 0x%02x", eh->ether_type);
    }
    putchar('\n');
}


/*  Open bpf device and associate it with a specific network device passed as an argument 'interface'.
 *      Return Value:   descriptor of the BPF device    */
int init_bpf_device(const char *interface)
{
    char buf[11] = {0};
    int bpf = 0;
    int i;
    struct ifreq bound_if;

    /* search Bpf device */
    for (i = 0; i < 99; i++) {
        sprintf(buf, "/dev/bpf%i", i);
        bpf = open(buf, O_RDWR);
        if (bpf != -1) {
            printf("%s: open successful\n", buf);
            break;
        }
    }
    /* Associate bpf with a specific network device */
    strcpy(bound_if.ifr_name, interface);
    if ( 0 < ioctl(bpf, BIOCSETIF, &bound_if) ) {
        return -1;
    }
    return bpf;
}

int main(void)
{
    char iface[] = "en0";
    int bpf;
    int buf_len = 1;

    int read_bytes = 0;
    struct ether_header *frame;
    struct bpf_hdr *bpf_buf;
    struct bpf_hdr *bpf_packet;

    bpf = init_bpf_device(iface);
    /* activate immedeate mode (therefore, buf_len is initially set to "1") */
    if (ioctl(bpf, BIOCIMMEDIATE, &buf_len) == -1) {
        return -1;
    }
    printf("buf_len = %d\n", buf_len);
    /*
    if (ioctl(bpf, BIOCPROMISC, &buf_len) == -1) {
        return -1;
    }
    printf("buf_len = %d\n", buf_len);
    */
    /* request buffer length    */
    if (ioctl(bpf, BIOCGBLEN, &buf_len) == -1) {
        return -1;
    }
    printf("buf_len = %d\n", buf_len);

    bpf_buf = (struct bpf_hdr*) malloc(sizeof(struct bpf_hdr) * buf_len);
    for(;;) {
        memset(bpf_buf, 0, buf_len);
        if ((read_bytes = read(bpf, bpf_buf, buf_len)) > 0) {
            int i = 0;
            char *ptr = (char*)bpf_buf;
            while(ptr < ( (char*)bpf_buf + read_bytes) ) {
                bpf_packet = (struct bpf_hdr*)ptr;
                frame = (struct ether_header*)( (char*)bpf_packet + bpf_packet->bh_hdrlen);
                print_ether_header(frame);

                ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
            }
        }
    }


    return 0;
}
