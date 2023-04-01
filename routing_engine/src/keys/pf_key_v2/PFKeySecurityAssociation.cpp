#include "keys/pf_key_v2/PFKeySecurityAssociation.hpp"
#include "layer3/IPUtils.hpp"
#include <unistd.h>
#include "logging/Logger.hpp"
#include "status/error_codes.hpp"
#include <time.h>
#include <cstring>
#include <linux/xfrm.h>

PFKeySecurityAssociation::PFKeySecurityAssociation()
	: _key_if(nullptr),
	  _spi(0),
	  _acquire(),
	  _state(PF_KEY_SECURITY_ASSOCIATION_STATE_INIT)
{
	memset(&_key, 0, sizeof(_key));
}

PFKeySecurityAssociation::PFKeySecurityAssociation(const PFKeySecurityAssociation &rhs)
{
	_key_if = rhs._key_if;
	_spi = rhs._spi;
	_acquire = rhs._acquire;
	_state = rhs._state;
	memcpy(&_key, &rhs._key, sizeof(_key));
}

PFKeySecurityAssociation::~PFKeySecurityAssociation()
{
}

int PFKeySecurityAssociation::Initialize(IPFKeyInterface *key_if, PFKeyMessageAcquire *acquire)
{
	_key_if = key_if;
	_acquire = *acquire;

	// Set the sequence number in the acquire message
	_acquire.SetSeqNum(_key_if->GetUniqueSeqNum());

	PFKeyMessageGet get;
	get.SourceAddress() = acquire->SourceAddress();
	get.DestinationAddress() = acquire->DestinationAddress();
	get.Association().SetSPI(0xC05C9ECA);
	int status = _key_if->SendMessage(reinterpret_cast<PFKeyMessageBase*>(&get));

	// Send Acquire message
	//int status = _key_if->SendMessage(reinterpret_cast<PFKeyMessageBase*>(&_acquire));

	return status;
}

int PFKeySecurityAssociation::Receive(PFKeyMessageBase *msg)
{
	switch (_state)
	{
		case PF_KEY_SECURITY_ASSOCIATION_STATE_INIT:
		{
			return _init_state_receive(msg);
		}
		case PF_KEY_SECURITY_ASSOCIATION_STATE_GET:
		{
			return _get_state_receive(msg);
		}
		case PF_KEY_SECURITY_ASSOCIATION_STATE_IDLE:
		{
			return _idle_state_receive(msg);
		}
		case PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSING:
		{
			return _closing_state_receive(msg);
		}
		default:
		{
			// Ignore message
			return NO_ERROR;
		}
	}
}

int PFKeySecurityAssociation::Close()
{
	// TODO Send delete message

	_state = PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSING;

	return NO_ERROR;
}

PFKeySecurityAssociationState_t PFKeySecurityAssociation::GetState()
{
	return _state;
}

uint32_t PFKeySecurityAssociation::GetSeqNum()
{
	return _acquire.GetSeqNum();
}

const sockaddr& PFKeySecurityAssociation::GetSourceAddress()
{
	return _acquire.SourceAddress().GetAddress();
}

const sockaddr& PFKeySecurityAssociation::GetDestinationAddress()
{
	return _acquire.DestinationAddress().GetAddress();
}

uint32_t PFKeySecurityAssociation::GetSPI()
{
	return _spi;
}

size_t PFKeySecurityAssociation::GetKey(const uint8_t* &key_data)
{
	key_data = _key;
	return KEY_LEN_BYTES;
}

/*
void PFKeySecurityAssociation::_build_acquire(PFKeyMessageAcquire *msg)
{
	// Source Address
	msg->SourceAddress()->SetAddress(reinterpret_cast<struct sockaddr&>(_src));
	msg->SourceAddress()->SetPrefixLength(_src_prefix);
	msg->SourceAddress()->SetProtocol(0);
	msg->SourceAddress()->SetTypeSource();

	// Destination Address
	msg->DestinationAddress()->SetAddress(reinterpret_cast<struct sockaddr&>(_dst));
	msg->DestinationAddress()->SetPrefixLength(_dst_prefix);
	msg->DestinationAddress()->SetProtocol(0);
	msg->DestinationAddress()->SetTypeDestination();

	// Proxy Address
	if (_proxy_present)
	{
		msg->ProxyAddress()->SetAddress(reinterpret_cast<struct sockaddr&>(_proxy));
		msg->ProxyAddress()->SetPrefixLength(_proxy_prefix);
		msg->ProxyAddress()->SetProtocol(0);
		msg->ProxyAddress()->SetTypeProxy();
		msg->SetProxyAddressPresent(true);
	}

	// Proposal (Automatic)
	msg->Proposal()->SetReplayWindow(64);
	struct sadb_comb comb = {0};
	comb.sadb_comb_auth = SADB_X_AALG_SHA2_256HMAC;
	comb.sadb_comb_auth_maxbits = 512;
	comb.sadb_comb_auth_minbits = 512;
	comb.sadb_comb_encrypt = SADB_EALG_NONE;
	comb.sadb_comb_encrypt_maxbits = 0;
	comb.sadb_comb_encrypt_minbits = 0;
	comb.sadb_comb_flags = SADB_SAFLAGS_PFS;
	comb.sadb_comb_hard_addtime = 7 * SA_TIMEOUT_1DAY;
	comb.sadb_comb_hard_allocations = 1024;
	comb.sadb_comb_hard_bytes = 4 * SA_LIFETIME_1TB;
	comb.sadb_comb_hard_usetime = SA_TIMEOUT_1DAY;
	comb.sadb_comb_soft_addtime = SA_TIMEOUT_1DAY;
	comb.sadb_comb_soft_allocations = 256;
	comb.sadb_comb_soft_bytes = SA_LIFETIME_1TB;
	comb.sadb_comb_soft_usetime = SA_TIMEOUT_1DAY;
	msg->Proposal()->AddCombination(comb);

	msg->SetPID(_pid);
	msg->SetErrorNum(0);
	msg->SetSAType(SADB_SATYPE_AH);
	msg->SetSeqNum(_seq_num);
}
*/

void PFKeySecurityAssociation::_build_get(PFKeyMessageGet *msg)
{
	msg->SourceAddress() = _acquire.SourceAddress();

	// Destination Address
	msg->DestinationAddress() = _acquire.DestinationAddress();

	// Proxy Address
	if (_acquire.GetProxyAddressPresent() == true)
	{
		msg->ProxyAddress() = _acquire.ProxyAddress();
		msg->SetProxyAddressPresent(true);
	}

	msg->Association().SetSPI(_spi);
	msg->SetPID(_acquire.GetPID());
	msg->SetErrorNum(0);
	msg->SetSAType(SADB_SATYPE_AH);
	msg->SetSeqNum(_acquire.GetSeqNum());
}

// void PFKeySecurityAssociation::_build_delete(PFKeyMessageDelete *msg)
//{
//
//}

int PFKeySecurityAssociation::_init_state_receive(PFKeyMessageBase *msg)
{
	int status = NO_ERROR;

	if (msg->GetErrorNum() == 0)
	{
		if (msg->GetMessageType() == SADB_UPDATE)
		{
			// Retrieve information from update message
			PFKeyMessageUpdate *update = reinterpret_cast<PFKeyMessageUpdate*>(msg);
			_spi = update->Association().GetSPI();

			// Send get message to retrieve key material
			PFKeyMessageGet get;
			_build_get(&get);

			status = _key_if->SendMessage(reinterpret_cast<PFKeyMessageBase*>(&get));
		}
	}

	return status;
}

int PFKeySecurityAssociation::_get_state_receive(PFKeyMessageBase *msg)
{
	int status = NO_ERROR;

	if (msg->GetErrorNum() == 0)
	{
		if (msg->GetMessageType() == SADB_GET)
		{
			PFKeyMessageGet *get = reinterpret_cast<PFKeyMessageGet*>(msg);

			// Retrieve authentication key
			const uint8_t *key_data;
			size_t key_len = get->AuthKey().GetKeyData(key_data);

			// Verify that key is correct size
			if (key_len != KEY_LEN_BYTES)
			{
				return PF_KEY_ERROR_INVALID_KEY_LENGTH;
			}

			// Copy key into local storage
			memcpy(_key, key_data, KEY_LEN_BYTES);
		}
	}

	return status;
}

int PFKeySecurityAssociation::_idle_state_receive(PFKeyMessageBase *msg)
{
	int status = NO_ERROR;

	if (msg->GetErrorNum() == 0)
	{
		if (msg->GetMessageType() == SADB_UPDATE)
		{
			// Send get message to retrieve key material
			PFKeyMessageGet get;
			_build_get(&get);

			status = _key_if->SendMessage(reinterpret_cast<PFKeyMessageBase*>(&get));
		}
	}

	return status;
}

int PFKeySecurityAssociation::_closing_state_receive(PFKeyMessageBase *msg)
{
	int status = NO_ERROR;

	if (msg->GetErrorNum() == 0)
	{
		if (msg->GetMessageType() == SADB_DELETE)
		{
			// Security Association deleted
			// Enter "closed" state
			_state = PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSED;
		}
	}

	return status;
}
