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

// ARP_CACHE_MISS indicates that a destination address
// was not found in the ARP table and that a message
// should be queued. It does not indicate an error
#define ARP_CACHE_MISS              1

/////////////////////////////
////// Interface Errors /////
/////////////////////////////

#define INTERFACE_INIT_FAILED        101
#define INTERFACE_OPEN_FAILED        102
#define INTERFACE_CLOSE_FAILED       103
#define INTERFACE_LISTEN_FAILED      104
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
#define ROUTE_INTERFACE_NOT_FOUND 501

#endif
