#ifndef INC_NAPT_HPP_
#define INC_NAPT_HPP_

#include <cstdint>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>

#include "layer3/IPv4Packet.hpp"

// Expiration time of 4 minutes from the last packet
// associated with an address mapping
#define NAPT_EXP_TIME_SEC 420

/// <summary>
/// Defines a tuple pair used for NAPT
/// </summary>
typedef struct
{
	struct sockaddr_storage addr;
	uint16_t identifier;    // For TCP/UDP, this is the port number.
                            // For IMCP, this is the ICMP query ID.
} napt_tuple_t;

/// <summary>
/// Defines a mapping entry used for NAPT
/// </summary>
typedef struct
{
	napt_tuple_t internal; // Address on the internal (stub) network
	napt_tuple_t external; // Address on globally-routable network
	time_t expires_at;     // Timestamp at which this entry will expire
	int socket_d;          // File descriptor of associated socket
} napt_entry_t;

/// <summary>
/// Implements Network Address Port Translation (NAPT)
/// </summary>
class NAPTTable
{
public:
	NAPTTable();
	~NAPTTable();

	/// <summary>
	/// Given a packet received from the globally-routable
	/// network, looks up the internal tuple associated with
	/// the destination tuple contained in the packet
	/// and applies the translation.
	/// </summary>
	/// <param name="packet">Packet to be translated</param>
	/// <returns>Error code</returns>
	int TranslateToInternal(IIPPacket *packet);

	/// <summary>
	/// Given a packet received from the internal (stub) network,
	/// looks up the globally-routable tuple associated with the source
	/// tuple contained in the packet and applies the translation.
	/// If the internal source tuple has no translation currently
	/// associated with it, then a new translation is created,
	/// using a global tuple which is not currently in use.
	/// </summary>
	/// <param name="packet">Packet to be translated</param>
	/// <param name="external_ip">IP Address of outgoing interface</param>
	/// <returns>Error code</returns>
	int TranslateToExternal(IIPPacket *packet, const struct sockaddr &external_ip);

	/// <summary>
	/// Checks the translation tables for entries which have
	/// passed their expiration time and removes those entries.
	/// </summary>
	void RemoveExpired();

	/// <summary>
	/// Add an explicit entry to the NAPT table
	/// </summary>
	/// <param name="protocol">Layer 4 protocol</param>
	/// <param name="new_entry">Entry to add</param>
	/// <remarks>
	/// This method may be used to create port forwards
	/// </remarks>
	void AddEntry(uint8_t protocol, const napt_entry_t &new_entry);

private:
	/// <summary>
	/// Given an external tuple, locates the associated internal tuple.
	/// </summary>
	/// <param name="protocol">Layer 4 protocol</param>
	/// <param name="ip_addr">IP address</param>
	/// <param name="id">Identifier</param>
	/// <returns>Internal tuple, or nullptr if not found</returns>
	napt_tuple_t *GetInternal(uint8_t protocol, const sockaddr &ip_addr, uint16_t id);

	/// <summary>
	/// Given an internal tuple, locates the associated external tupl.
	/// </summary>
	/// <param name="protocol">Layer 4 protocol</param>
	/// <param name="ip_addr">IP address</param>
	/// <param name="id">Identifier</param>
	/// <returns>External tuple, or nullptr if not found</returns>
	napt_tuple_t *GetExternal(uint8_t protocol, const sockaddr &ip_addr, uint16_t id);

	/// <summary>
	/// Creates a mapping from the specified internal tuple to
	/// an external tuple
	/// </summary>(uint32_t*)
	/// <param name="protocol">Layer 4 protocol</param>
	/// <param name="internal_ip">Internal IP address</param>
	/// <param name="id">Internal identifier</param>
	/// <param name="external_ip">External IP address</param>
	/// <returns>External tuple</returns>
	napt_tuple_t *CreateMappingToExternal(uint8_t protocol, const sockaddr &internal_ip, uint16_t id, const sockaddr &external_ip);

	/// <summary>
	/// Binds a socket and retrieves the bound identifier
	/// </summary>
	/// <param name="protocol">Layer 4 protocol</param>
	/// <param name="external_ip">External IP address</param>
	/// <param name="socket_d">File descriptor of bound socket out</param>
	/// <param name="id">Bound identifier out</param>
	/// <returns>Error Code</returns>
	int BindMapping(uint8_t protocol, const sockaddr &external_ip, int &socket_d, uint16_t &id);

	std::vector<napt_entry_t> _tcp_table;
	std::vector<napt_entry_t> _udp_table;
	std::vector<napt_entry_t> _icmp_table;

	std::mutex _mutex;

	static const size_t TCP_PSEUDO_HEADER_LEN = 12;
};

#endif
