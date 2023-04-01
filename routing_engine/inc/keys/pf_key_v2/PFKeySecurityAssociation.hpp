#ifndef INC_PFKEYSECURITYASSOCIATION_HPP_
#define INC_PFKEYSECURITYASSOCIATION_HPP_

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageAcquire.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageGet.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageUpdate.hpp"
#include <sys/socket.h>

#include "keys/pf_key_v2/IPFKeyInterface.hpp"

typedef enum
{
	PF_KEY_SECURITY_ASSOCIATION_STATE_INIT,    // Awaiting SADB_UPDATE message for initial keying material
	PF_KEY_SECURITY_ASSOCIATION_STATE_GET,     // Retrieving keying material
	PF_KEY_SECURITY_ASSOCIATION_STATE_IDLE,    // SA active with up-to-date keying material
	PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSING, // In process of closing
	PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSED,  // Close complete
} PFKeySecurityAssociationState_t;

/// <summary>
/// Encapsulates management utilities
/// for an active security association
/// </summary>
class PFKeySecurityAssociation
{
public:
	PFKeySecurityAssociation();
	PFKeySecurityAssociation(const PFKeySecurityAssociation &rhs);
	~PFKeySecurityAssociation();

	/// <summary>
	/// Initializes the security association
	/// by sending the SADB_ACQUIRE message
	/// and entering the "Init" state
	/// </summary>
	/// <param name="key_if">Pointer to key interface object</param>
	/// <param name="acquire">Initial acquire message</param>
	/// <returns>Error code</returns>
	int Initialize(IPFKeyInterface *key_if, PFKeyMessageAcquire *acquire);

	/// <summary>
	/// Processes an incoming PF Key message
	/// </summary>
	/// <param name="msg">Incoming message</param>
	/// <returns>Error code</returns>
	int Receive(PFKeyMessageBase *msg);

	/// <summary>
	/// Closes the security association by
	/// sending the SADB_DELETE message
	/// and entering the "Closing" state
	/// </summary>
	/// <returns>Error code</returns>
	int Close();

	/// <summary>
	/// Gets the current state of the security
	/// association. Note that these states are
	/// distinct from the states defined by the
	/// PF_KEY API
	/// </summary>
	/// <returns>State</returns>
	PFKeySecurityAssociationState_t GetState();

	/// <summary>
	/// Gets the sequence number associated
	/// with the security association
	/// </summary>
	/// <summary>Sequence number</summary>
	uint32_t GetSeqNum();

	/// <summary>
	/// Gets the source address associated
	/// with the security association
	/// </summary>
	/// <returns>Source address</returns>
	const sockaddr& GetSourceAddress();

	/// <summary>
	/// Gets the destination address associated
	/// with the security association
	/// </summary>
	/// <returns>Destination address</returns>
	const sockaddr& GetDestinationAddress();

	/// <summary>
	/// Gets the security parameters index (SPI)
	/// </summary>
	/// <returns>SPI</returns>
	uint32_t GetSPI();

	/// <summary>
	/// Gets the key data
	/// </summary>
	size_t GetKey(const uint8_t* &key_data);

private:
	uint32_t _spi;
	IPFKeyInterface *_key_if;
	PFKeyMessageAcquire _acquire;
	PFKeySecurityAssociationState_t _state;

	void _build_get(PFKeyMessageGet *msg);
	// void _build_delete(PFKeyMessageDelete *msg);

	int _init_state_receive(PFKeyMessageBase *msg);
	int _get_state_receive(PFKeyMessageBase *msg);
	int _idle_state_receive(PFKeyMessageBase *msg);
	int _closing_state_receive(PFKeyMessageBase *msg);

	static const size_t KEY_LEN_BYTES = 64;
	uint8_t _key[KEY_LEN_BYTES];
};

#endif
