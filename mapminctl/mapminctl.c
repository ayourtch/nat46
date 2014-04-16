/*
*
* Experiment in emulating the MAP as a 2-step process.  (c) Andrew Yourtchenko <ayourtch@gmail.com>
* 
* The user-facing code has been partially copypasted from https://github.com/cernet/MAP/blob/master/utils/ivictl.c
*
*/


/* iptables -t nat -A POSTROUTING -p udp -o mapmint -j SNAT --to 1.1.1.1:1025-2047 */

/* 
mapminctl -s -i br-lan -I wan0 -H -a 192.168.1.1/24 -A 1.1.1.1/32 -P 2001:6f8:147e:1000::/52 -R 16 -z 4 -o 14 -c 1234 -T
mapminctl -r -d -P 2610:d0:1208:cafe::/64 -T

mapminctl -s -i br-lan -I eth0.2 -H -a 192.168.1.1/24 -A 176.9.227.82/32 -P 2001:470:73cd:e000::/52 -R 256 -z 4 -o 15 -c 1100 -T
mapminctl -r -d -P 2001:470:73cd:cafe::/64 -T

*/

#include <stdio.h>   
#include <string.h>
#include <stdlib.h>    
#include <getopt.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <net/route.h>


#define RULE_PREFERENCE 32765
#define ROUTE_TABLE 77
#define NET_DEVICE_T "mapmint"
#define PROC_CTL_FILE "net/nat46/control"


void usage(int status) {
        if (status != EXIT_SUCCESS)
                printf("Try `mapminctl --help' for more information.\n");
        else {
                printf("\
Usage: mapminctl -r [rule_options]\n\
        (used to insert a mapping rule)\n\
        mapminctl -s [start_options]\n\
        (used to start MAP module)\n\
        mapminctl -q\n\
        (used to stop MAP module)\n\
        mapminctl -h\n\
        (used to display this help information)\n\
\n\
rule_options:\n\
        -p --prefix4 [PREFIX4/PLEN4]\n\
                specify the ipv4 prefix and length\n\
        -P --prefix6 [PREFIX6/PLEN6]\n\
                specify the ipv6 prefix and length\n\
        -z --psidoffset PSIDOFFSET\n\
                specify the psid offset parameter in GMA\n\
        -R --ratio RATIO\n\
                specify the address sharing ratio in GMA\n\
        -d --default\n\
                specify the ipv4 prefix is '0.0.0.0/0' instead of using '-p 0.0.0.0 -l 0'\n\
        -E --encapsulate\n\
                specify the mapping rule is used for MAP-E\n\
        -T --translate\n\
                specify the mapping rule is used for MAP-T\n\
\n\
start_options:\n\
        -i --dev4 DEV4\n\
                specify the name of ipv4 device\n\
        -I --dev6 DEV6\n\
                specify the name of ipv6 device\n\
        -c --mssclamping MSS\n\
                specify the reduced tcp mss value\n\
\n\
        HGW mode:\n\
                -H --hgw\n\
                        specify that IVI is working as home gateway\n\
                -N --nat44\n\
                        specify that IVI HGW is performing NAT44\n\
                -o --psid PSID\n\
                        specify the local PSID of the HGW, default is 0\n\
                -a --address [ADDRRESS/PREFIXLENGTH]\n\
                        specify the ipv4 address and mask used by the HGW\n\
                -A --publicaddr [PUBLICADDR/PUBLICPREFIXLENGTH]\n\
                        specify the public ipv4 address and mask used by the HGW in NAT44 mode\n\
                        always used with -N (--nat44)\n\
                -P --prefix6 [PREFIX6/PLEN6]\n\
                        specify the local IVI prefix and length used by the HGW\n\
                -z --psidoffset PSIDOFFSET\n\
                        specify the local psid offset parameter in GMA\n\
                -R --ratio RATIO\n\
                        specify the local address sharing ratio in GMA\n\
                -X --noeabits\n\
                        specify that the HGW doesn't use eabits to constitute the IPv6 address\n\
                -E --encapsulate\n\
                        specify that the HGW supports MAP-E mode\n\
                -T --translate\n\
                        specify that the HGW supports MAP-T\n\
\n");
        }
        exit(status);
}

char *safe_cpy(char *dest, const char *src, int size) {
  if (size > 0) { 
    strncpy(dest, src, size-1);
  }
  dest[size-1] = 0;
  return dest;
}

typedef char in6_addr_t[16];

int get_ipv4_prefix(char *src, in_addr_t *val, int *len) {
  char *token = strsep(&src, "/");
  *val = inet_addr(token);
  *len = atoi(src);
  return -1;
}
int get_ipv6_prefix(char *src, in6_addr_t *val, int *len) {
  char *token = strsep(&src, "/");
  inet_pton(AF_INET6, token, (void *)val);
  *len = atoi(src);
  return -1;
}

int xlog2(int arg) {
  int ret = 0;
  while (arg > 1) {
    arg = arg >> 1;
    ret++;
  }
  return ret;
}


static const struct option longopts[] =
{
        {"rule", no_argument, NULL, 'r'},
        {"start", no_argument, NULL, 's'},
        {"stop", required_argument, NULL, 'q'},
        {"help", no_argument, NULL, 'h'},
        {"hgw", no_argument, NULL, 'H'},
        {"nat44", no_argument, NULL, 'N'},
        {"noeabits", no_argument, NULL, 'X'},
        {"default", no_argument, NULL, 'd'},
        {"prefix4", required_argument, NULL, 'p'},
        {"prefix6", required_argument, NULL, 'P'},
        {"ratio", required_argument, NULL, 'R'},
        {"psidoffset", required_argument, NULL, 'z'},
        {"encapsulate", required_argument, NULL, 'E'},
        {"translate", required_argument, NULL, 'T'},
        {"psid", required_argument, NULL, 'o'},
        {"address", required_argument, NULL, 'a'},
        {"publicaddr", required_argument, NULL, 'A'},
        {"dev4", required_argument, NULL, 'i'},
        {"dev6", required_argument, NULL, 'I'},
        {"mssclamping", required_argument, NULL, 'c'},
        {NULL, no_argument, NULL, 0}
};

typedef enum { ACTION_RULE, ACTION_START, ACTION_STOP } ctl_action_t;

enum {DEVICE_STRLEN = 64};


int arg_hgw = 0;
int arg_nat44 = 0;
int arg_eabits = 1;
int arg_default = 0;

in_addr_t arg_prefix4_val;
int arg_prefix4_len = 0;
int arg_prefix4_seen = 0;

in6_addr_t arg_prefix6_val;
int arg_prefix6_len = 0;
int arg_prefix6_seen = 0;

int arg_ratio = 1;
int arg_psidoffset = 6;
int arg_encapsulate = 0;
int arg_translate = 0;
int arg_psid = 0;
int arg_psid_seen = 0;

in_addr_t arg_address_val;
int arg_address_len = 0;
int arg_address_seen = 0;

in_addr_t arg_publicaddr_val;
int arg_publicaddr_len = 0;
int arg_publicaddr_seen = 0;

char arg_dev4[DEVICE_STRLEN];
char arg_dev6[DEVICE_STRLEN];
int arg_mss = 0;


int getmapport(int a, int psidoffset, int psidbits, int psid) {
  int port = (a << (16 - psidoffset)) + ((psid & ((2 << psidbits) -1)) << (16 - psidoffset - psidbits)) ;
  return port;
}

int add_dmr_v6_route(char *dmr_prefix, int dmr_prefix_len) {
  static FILE *fp_route = NULL;
  char line[512], ifname[16];
  int found_default = 0;
  uint32_t rflags;
  struct in6_addr nhop;
  int i;
  char v6addr[INET6_ADDRSTRLEN];
  

  if (!(fp_route = fopen("/proc/net/ipv6_route", "r"))) {
    return 0;
  }
  while (fgets(line, sizeof(line), fp_route)) {
    if (sscanf(line, "00000000000000000000000000000000 00 "
                     "00000000000000000000000000000000 00 "
                     "%8" SCNx32 "%8" SCNx32 "%8" SCNx32 "%8" SCNx32 
                     "%*s %*s %*s %" SCNx32 " %15s",
                         &nhop.s6_addr32[0],
                         &nhop.s6_addr32[1],
                         &nhop.s6_addr32[2],
                         &nhop.s6_addr32[3],
                         &rflags,
                         ifname) && !((rflags & RTF_NONEXTHOP) | (rflags & RTF_REJECT)) ) {
      for(i=0;i<4;i++) {
        nhop.s6_addr32[i] = htonl(nhop.s6_addr32[i]);
      }
      printf("ip -6 route add %s/%d via %s dev %s table %d\n",
        dmr_prefix, dmr_prefix_len,
        inet_ntop(AF_INET6, &nhop, v6addr, sizeof(v6addr)),
        ifname,
        ROUTE_TABLE);
      found_default = 1;
    }
  }

  fclose(fp_route);
  return (found_default ? 1 : 0);
}

int
main(int argc, char **argv)
{
        int optc;
	int retval = EXIT_FAILURE;
	ctl_action_t action;
	char *opt_str;
        
        optc = getopt_long(argc, argv, "rsqh", longopts, NULL);
        switch (optc) {
                case 'r':
			action = ACTION_RULE;
			opt_str = "p:P:R:z:fdET";
                        break;
                case 's':
			action = ACTION_START;
			opt_str = "i:I:A:a:P:R:z:o:fc:HNXET";
                        break;
                case 'q':
			action = ACTION_STOP;
			opt_str = "";
                        break;
                case 'h':
                        usage(EXIT_SUCCESS);
                        break;
                default:
                        usage(EXIT_FAILURE);
                        break;
        }
/* 
mapminctl -s -i br-lan -I wan0 -H -a 192.168.1.1/24 -A 1.1.1.1/32 -P 2001:6f8:147e:1000::/52 -R 16 -z 4 -o 14 -c 1234 -T
mapminctl -r -d -P 2610:d0:1208:cafe::/64 -T
*/
	while ((optc = getopt_long(argc, argv, opt_str, longopts, NULL)) != -1) {
            switch(optc) {
		case 'i':
			safe_cpy(arg_dev4, optarg, sizeof(arg_dev4));
			break;
		case 'I':
			safe_cpy(arg_dev6, optarg, sizeof(arg_dev6));
			break;
		case 'H':
			arg_hgw = 1;
			break;
		case 'a':
			get_ipv4_prefix(optarg, &arg_address_val, &arg_address_len);
			arg_address_seen = 1;
			break;
		case 'A':
			get_ipv4_prefix(optarg, &arg_publicaddr_val, &arg_publicaddr_len);
			arg_publicaddr_seen = 1;
			break;
		case 'P':
			get_ipv6_prefix(optarg, &arg_prefix6_val, &arg_prefix6_len);
			arg_prefix6_seen = 1;
			break;
		case 'R':
			arg_ratio = atoi(optarg);
			break;
		case 'z':
			arg_psidoffset = atoi(optarg);
			break;
		case 'o':
			arg_psid = atoi(optarg);
			arg_psid_seen = 1;
			break;
		case 'c':
			arg_mss = atoi(optarg);
			break;
		case 'T':
			arg_translate = 1;
			break;
		case 'E':
			arg_encapsulate = 1;
			break;
		case 'd':
			arg_default = 1;
			break;
		
		default:
			break;
	    }
	}
	if (action == ACTION_STOP) {
	}
	if (action == ACTION_RULE) {
		if(arg_default && arg_translate) {
			char v6addr[INET6_ADDRSTRLEN];
			printf("echo add %s >/proc/%s\n", NET_DEVICE_T, PROC_CTL_FILE);
			printf("ifconfig %s up\n", NET_DEVICE_T);
			printf("echo config %s remote.style RFC6052 >/proc/%s\n", 
				NET_DEVICE_T, PROC_CTL_FILE);
			printf("echo config %s remote.v6 %s/%d >/proc/%s\n", 
				NET_DEVICE_T,
				inet_ntop(AF_INET6, arg_prefix6_val, v6addr, sizeof(v6addr)),
				arg_prefix6_len, PROC_CTL_FILE);
			printf("ip -4 route add default dev %s\n", NET_DEVICE_T);
			printf("ip -6 rule add pref %d from all to %s/%d iif %s lookup %d\n",
				RULE_PREFERENCE, v6addr, arg_prefix6_len, NET_DEVICE_T, ROUTE_TABLE);
			add_dmr_v6_route(v6addr, arg_prefix6_len);
		}
	}
	if (action == ACTION_START) {
		int a;
		int port1, port2;
		int psidbits = xlog2(arg_ratio);
		int proto;
		char v6addr[INET6_ADDRSTRLEN];
		char *proto_tab[3] = { "icmp", "tcp", "udp" };


		if (arg_translate) {
			if (arg_prefix6_seen) {
				in6_addr_t arg_prefix6_val_bmr;
				uint8_t *pc = (void *)&arg_prefix6_val_bmr;
				int psidbits = xlog2(arg_ratio);
				char *map_rev = "";

				memcpy(arg_prefix6_val_bmr, arg_prefix6_val, sizeof(arg_prefix6_val_bmr));
		
				pc[arg_prefix6_len/8] |= 0xff & ((arg_psid << (8-psidbits)) >> (arg_prefix6_len%8));
				pc[arg_prefix6_len/8 + 1] |= (0xff & (arg_psid << (psidbits + 8 - (arg_prefix6_len % 8)))); 

				printf("echo add %s >/proc/%s\n", NET_DEVICE_T, PROC_CTL_FILE);
				printf("ifconfig %s up\n", NET_DEVICE_T);
				if(getenv("MAP_VERSION")) {
					map_rev = getenv("MAP_VERSION");
				}

				printf("echo config %s local.style MAP%s >/proc/%s\n", 
					NET_DEVICE_T, map_rev, PROC_CTL_FILE);
				printf("echo config %s local.v6 %s/%d >/proc/%s\n", 
					NET_DEVICE_T, 
					inet_ntop(AF_INET6, arg_prefix6_val_bmr, v6addr, sizeof(v6addr)),
					64, 
					PROC_CTL_FILE);

				if(arg_psid_seen && arg_publicaddr_seen) {
					printf("echo config %s local.ea-len %d >/proc/%s\n", 
						NET_DEVICE_T, psidbits + (32 - arg_publicaddr_len), PROC_CTL_FILE);
					if (getenv("MAP_VERSION") && (0 == strcmp("0", getenv("MAP_VERSION")))) {
						printf("echo config %s local.psid-offset %d >/proc/%s\n", 
							NET_DEVICE_T, 4, PROC_CTL_FILE);

						pc[9] = (arg_publicaddr_val >> 24) & 0xff;
						pc[10] = (arg_publicaddr_val >> 16) & 0xff;
						pc[11] = (arg_publicaddr_val >> 8) & 0xff;
						pc[12] = (arg_publicaddr_val ) & 0xff;

						pc[13] = (arg_psid >> 8) & 0xff;
						pc[14] = arg_psid & 0xff;
					} else {
						printf("echo config %s local.psid-offset %d >/proc/%s\n", 
							NET_DEVICE_T, 6, PROC_CTL_FILE);
						pc[10] = (arg_publicaddr_val >> 24) & 0xff;
						pc[11] = (arg_publicaddr_val >> 16) & 0xff;
						pc[12] = (arg_publicaddr_val >> 8) & 0xff;
						pc[13] = (arg_publicaddr_val ) & 0xff;

						pc[14] = (arg_psid >> 8) & 0xff;
						pc[15] = arg_psid & 0xff;
					}

					printf("ip -6 route add %s/128 dev %s\n", 
						inet_ntop(AF_INET6, arg_prefix6_val_bmr, v6addr, sizeof(v6addr)), NET_DEVICE_T);

				}
			}
			if (arg_psid_seen) {
				printf("echo FIXME psid %d >/proc/%s\n", arg_psid, PROC_CTL_FILE);
			}
			if (arg_publicaddr_seen) {
				printf("echo config %s local.v4 %s/%d >/proc/%s\n", NET_DEVICE_T,
					inet_ntoa(*(struct in_addr *)&arg_publicaddr_val), arg_publicaddr_len, PROC_CTL_FILE);
			}
		}
		fprintf(stderr, "psid bits: %d\n", psidbits);

                // iptables -t nat -A POSTROUTING -p icmp -m connlimit --connlimit-daddr --connlimit-upto 2 -o eth0 -j SNAT --to 1.1.1.1:1025-1026
		
		for (a = (arg_psidoffset ? 1 : 0); a <= ((1 << arg_psidoffset) -1); a++) {
			// port = (a << (16 - arg_psidoffset)) + ((arg_psid & ((2 << psidbits) -1)) << (16 - arg_psidoffset - psidbits)) ;
			port1 = getmapport(a, arg_psidoffset, psidbits, arg_psid);
			port2 = getmapport(a, arg_psidoffset, psidbits, arg_psid+1) - 1;
			for(proto=0; proto < sizeof(proto_tab)/sizeof(proto_tab[0]); proto++) {
				printf("iptables -t nat -A POSTROUTING -p %s -m connlimit --connlimit-daddr --connlimit-upto %d -o %s -j SNAT --to %s:%d-%d\n", 
					proto_tab[proto],
					port2-port1+1, 
					arg_translate ? "mapmint" : (arg_encapsulate ? "mapmine" : "ethX"),
 					inet_ntoa(*(struct in_addr*)&arg_publicaddr_val), port1, port2);
			}
		}
	}

	
	exit(retval);

}























