#ifndef INC_ERROR_CODES_HPP
#define INC_ERROR_CODES_HPP

/////////////////////////////
//// Generic Error Codes ////
/////////////////////////////

// ERROR_UNSET (-1) indicates that no error code was
// provided. Acts as an alternate initial value
// which does not imply success
#define ERROR_UNSET                 -1

// NO_ERROR (0) shall be thrown by all methods
// which return an error code on success
#define NO_ERROR                    0

// ARP_CACHE_MISS codes indicate that a destination address
// was not found in the ARP table and that a message
// should be queued. These codes do not indicate an error
// ARP_CACHE_MISS_LOCAL indicates the the ARP miss was
// for a local address, so the next hop is the destination
// address in the IP packet.
// ARP_CACHE_MISS_DEFAULT indicates that the ARP cache miss
// was for the default gateway, so the next hop is the
// IP address of the default gateway.
#define ARP_CACHE_MISS_LOCAL         1
#define ARP_CACHE_MISS_DEFAULT       2

/////////////////////////////
////// Interface Errors /////
/////////////////////////////

#define INTERFACE_INIT_FAILED        101
#define INTERFACE_OPEN_FAILED        102
#define INTERFACE_CLOSE_FAILED       103
#define INTERFACE_LISTEN_FAILED      104
	// TODO Write Checksum
#define INTERFACE_STOP_LISTEN_FAILED 105
#define COMPILE_FILTER_FAILED        106
#define SET_FILTER_FAILED            107
#define INTERFACE_SEND_FAILED        108

/////////////////////////////
///////// ARP ERRORS ////////
/////////////////////////////

#define ARP_ERROR_OVERFLOW          201
#define ARP_ERROR_UNDEFINED_ADDRESS 202

/////////////////////////////
////// Ethernet Errors //////
/////////////////////////////

#define ETHERNET_ERROR_OVERFLOW     301

/////////////////////////////
//////// IPv4 Errors ////////
/////////////////////////////

#define IPV4_ERROR_OVERFLOW         401
#define IPV4_ERROR_INVALID_CHECKSUM 402
#define IPV4_ERROR_UNDEFINED_OPTION 403
#define IPV4_ERROR_INVALID_VERSION  404

/////////////////////////////
//////// IPv6 Errors ////////
/////////////////////////////

/////////////////////////////
/////// Routing Errors //////
/////////////////////////////
#define ROUTE_INTERFACE_NOT_FOUND   501

/////////////////////////////
///////// TCP Errors ////////
/////////////////////////////
#define TCP_ERROR_OVERFLOW          601
#define TCP_ERROR_INVALID_CHECKSUM  602

/////////////////////////////
///////// UDP Errors ////////
/////////////////////////////
#define UDP_ERROR_OVERFLOW          701

/////////////////////////////
//////// ICMP Errors ////////
/////////////////////////////
#define ICMP_ERROR_OVERFLOW         801
#define ICMP_ERROR_INVALID_CHECKSUM 802

/////////////////////////////
//////// NAT Errors /////////
/////////////////////////////
#define NAT_ERROR_MAPPING_NOT_FOUND     901
#define NAT_ERROR_CREATE_MAPPING_FAILED 902
#define NAT_ERROR_UNSUPPORTED_PROTOCOL  903
#define NAT_ERROR_NO_AVAILABLE_ID       904
#define NAT_ERROR_OUT_OF_RANGE          905
#define NAT_ERROR_SOCKET_CREATE_FAILED  906
#define NAT_ERROR_SOCKET_BIND_FAILED    907
#define NAT_ERROR_GET_ADDRESS_FAILED    908

/////////////////////////////
/////// PF_KEY Errors ///////
/////////////////////////////
#define PF_KEY_ERROR_OVERFLOW             1001
#define PF_KEY_ERROR_MALFORMED_EXTENSION  1002
#define PF_KEY_ERROR_UNSUPPORTED_PROTOCOL 1003
#define PF_KEY_ERROR_KEY_NOT_FOUND        1004
#define PF_KEY_ERROR_MISSING_EXTENSION    1005
#define PF_KEY_ERROR_SOCKET_OPEN_FAILED   1006
#define PF_KEY_ERROR_MESSAGE_SEND_FAILED  1006
#define PF_KEY_ERROR_INVALID_KEY_LENGTH   1007
#define PF_KEY_ERROR_KEY_DATA_PENDING     1008

/////////////////////////////
/////// IPSEC Errors ////////
/////////////////////////////
#define IPSEC_AH_ERROR_OVERFLOW          1101
#define IPSEC_AH_ERROR_NO_AUTH_HEADER    1102
#define IPSEC_AH_ERROR_ICV_LEN_INCORRECT 1103
#define IPSEC_AH_ERROR_HMAC_FAILED       1104
#define IPSEC_ERROR_UNSUPPORTED_PROTOCOL 1105
#define IPSEC_AH_ERROR_INVALID_SEQ_NUM   1106
#define IPSEC_AH_ERROR_INCORRECT_ICV     1107

/////////////////////////////
////// Monitor Errors ///////
/////////////////////////////
#define MONITOR_ERROR_OVERFLOW        1201
#define MONITOR_ERROR_ENTRY_NOT_FOUND 1202
#define MONITOR_ERROR_SOCKET_FAILED   1203
#define MONITOR_ERROR_BIND_FAILED     1204
#define MONITOR_ERROR_SEND_FAILED     1205
#define MONITOR_ERROR_NULL_POINTER    1206
#define MONITOR_ERROR_BAD_PACKET_TYPE 1207

#endif
