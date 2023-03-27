#include "keys/PFKeyManager.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/pfkeyv2.h>
#include <cstring>
#include <functional>

#include "logging/Logger.hpp"
#include "status/error_codes.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageFactory.hpp"

PFKeyManager::PFKeyManager()
	: _socket_d(0),
	  _exiting(false),
	  _next_seq_num(0),
	  _associations(),
	  _default_proposal(),
	  _private_subnet_addr_v4(),
	  _private_subnet_id_v4(),
	  _db_mutex(),
	  _send_mutex(),
	  _rcv_mutex()
{
	memset(_rcv_buff, 0, sizeof(_rcv_buff));
	memset(_send_buff, 0, sizeof(_send_buff));
	_pid = getpid();
}

PFKeyManager::~PFKeyManager()
{
}

int PFKeyManager::GetKey(uint32_t spi, const struct sockaddr &src, const struct sockaddr &dst, uint8_t *key, size_t &keylen)
{
	for (auto e = _associations.begin(); e < _associations.end(); e++)
	{
		PFKeySecurityAssociation &entry = *e;

		// Check if the entry matches spi, source, and destination
		if (spi == entry.GetSPI() &&
			IPUtils::AddressesAreEqual(src, entry.GetSourceAddress()) &&
			IPUtils::AddressesAreEqual(dst, entry.GetDestinationAddress()))
		{
			// Verify that key data is valid
			if (entry.GetState() != PF_KEY_SECURITY_ASSOCIATION_STATE_IDLE)
			{
				return PF_KEY_ERROR_KEY_DATA_PENDING;
			}

			// Retrieve key information
			const uint8_t *found_key;
			size_t found_key_len = entry.GetKey(found_key);

			// Verify enough data in the output buffer to
			// fit the retrieved key data
			if (found_key_len > keylen)
			{
				return PF_KEY_ERROR_OVERFLOW;
			}

			// Copy key into output
			memcpy(key, found_key, found_key_len);
			keylen = found_key_len;

			return NO_ERROR;
		}
	}

	return PF_KEY_ERROR_KEY_NOT_FOUND;
}

int PFKeyManager::GetSPI(const sockaddr &src, const sockaddr &dst, uint32_t &spi)
{
	return ERROR_UNSET;
}

void PFKeyManager::RemoveClosedSAs()
{
	std::scoped_lock lock {_db_mutex};

	for (auto e = _associations.begin(); e < _associations.end();)
	{
		PFKeySecurityAssociation &entry = *e;

		if (entry.GetState() == PF_KEY_SECURITY_ASSOCIATION_STATE_CLOSED)
		{
			e = _associations.erase(e);
		}
		else
		{
			e++;
		}
	}
}

void PFKeyManager::_initialize_default_extensions()
{
	// Initialize default proposal extension
	// Initialize combination
	sadb_comb comb = {0};
	comb.sadb_comb_auth = SADB_X_AALG_SHA2_256HMAC;
	comb.sadb_comb_encrypt = SADB_EALG_NONE;
	comb.sadb_comb_flags = SADB_SAFLAGS_PFS;
	comb.sadb_comb_auth_minbits = 512;
	comb.sadb_comb_auth_maxbits = 512;
	comb.sadb_comb_encrypt_minbits = 0;
	comb.sadb_comb_encrypt_maxbits = 0;
	comb.sadb_comb_soft_allocations = 1024;
	comb.sadb_comb_hard_allocations = 4096;
	comb.sadb_comb_soft_bytes = SA_LIFETIME_1TB;
	comb.sadb_comb_hard_bytes = SA_LIFETIME_1TB * 4;
	comb.sadb_comb_soft_addtime = SA_TIMEOUT_1DAY;
	comb.sadb_comb_hard_addtime = SA_TIMEOUT_1DAY * 7;
	comb.sadb_comb_soft_usetime = SA_TIMEOUT_1DAY;
	comb.sadb_comb_hard_usetime = SA_TIMEOUT_1DAY * 7;
	// Set replay window and add combination
	_default_proposal.SetReplayWindow(64);
	_default_proposal.AddCombination(comb);

	// Initialize private subnet address extension (v4)
	struct sockaddr_in pvt_addr;
	pvt_addr.sin_family = AF_INET;
	pvt_addr.sin_port = 0;
	inet_pton(AF_INET, "192.168.0.0", &pvt_addr.sin_addr);
	_private_subnet_addr_v4.SetAddress(reinterpret_cast<struct sockaddr&>(pvt_addr));
	_private_subnet_addr_v4.SetPrefixLength(16);
	_private_subnet_addr_v4.SetProtocol(0);
	_private_subnet_addr_v4.SetTypeProxy();

	// Initialize private subnet identity extension (v4)
	_private_subnet_id_v4.SetIDNumber(0);
	_private_subnet_id_v4.SetIDString("192.168.0.0/16");
	_private_subnet_id_v4.SetTypeSource();
	_private_subnet_id_v4.SetIDType(SADB_IDENTTYPE_PREFIX);
}

void PFKeyManager::_build_from_host_acquire(const sockaddr &host, const sockaddr &gateway, PFKeyMessageAcquire *msg)
{
	// Set data for base header
	msg->SetSAType(SADB_SATYPE_AH);
	msg->SetErrorNum(0);
	msg->SetPID(_pid);
	msg->SetSeqNum(0); // Sequence number will be overwritten

	// Clear unneeded optional extensions
	msg->SetProxyAddressPresent(false);
	msg->SetSourceIDPresent(false);
	msg->SetDestinationIDPresent(false);

	// Set the source address extension
	// to be from the host's specific IP
	msg->SourceAddress().SetAddress(host);
	msg->SourceAddress().SetPrefixLength(32);
	msg->SourceAddress().SetProtocol(0);
	msg->SourceAddress().SetTypeSource();

	// Set the destination address extension
	// to be to the gateway's specific IP
	msg->DestinationAddress().SetAddress(gateway);
	msg->DestinationAddress().SetPrefixLength(32);
	msg->DestinationAddress().SetProtocol(0);
	msg->DestinationAddress().SetTypeDestination();

	// Set the proposal to the default proposal
	msg->Proposal() = _default_proposal;
}

void PFKeyManager::_build_to_host_acquire(const sockaddr &host, const sockaddr &gateway, PFKeyMessageAcquire *msg)
{
	// Set data for base header
	msg->SetSAType(SADB_SATYPE_AH);
	msg->SetErrorNum(0);
	msg->SetPID(_pid);
	msg->SetSeqNum(0); // Sequence number will be overwritten

	// Clear unneeded optional extensions
	msg->SetDestinationIDPresent(false);

	// Set the source address extension
	// to be from the gateway's specific IP
	msg->SourceAddress().SetAddress(gateway);
	msg->SourceAddress().SetPrefixLength(32);
	msg->SourceAddress().SetProtocol(0);
	msg->SourceAddress().SetTypeSource();

	// Set the destination address extension
	// to be to the host's specific IP
	msg->DestinationAddress().SetAddress(host);
	msg->DestinationAddress().SetPrefixLength(32);
	msg->DestinationAddress().SetProtocol(0);
	msg->DestinationAddress().SetTypeDestination();

	// Set the proxy address extension to be
	// equal to the entire private subnet
	msg->ProxyAddress() = _private_subnet_addr_v4;
	msg->SetProxyAddressPresent(true);

	// Set the source ID extension to be
	// equal to the entire private subnet
	msg->SourceID() = _private_subnet_id_v4;
	msg->SetSourceIDPresent(true);

	// Set the proposal to the default proposal
	msg->Proposal() = _default_proposal;
}

int PFKeyManager::AddHost(const sockaddr &host)
{
	std::stringstream sstream;
	std::scoped_lock lock {_db_mutex};

	sstream << "Adding SAs for host: " << Logger::IPToString(host);
	Logger::Log(LOG_DEBUG, sstream.str());

	PFKeyMessageAcquire acquire;
	int from_status = ERROR_UNSET;
	int to_status = ERROR_UNSET;

	// Derive gateway IP
	struct sockaddr_storage gateway;
	struct sockaddr &_gateway = reinterpret_cast<struct sockaddr&>(gateway);
	_derive_gateway(host, _gateway);

	// Initialize association from host
	_build_from_host_acquire(host, _gateway, &acquire);
	_associations.emplace_back();
	from_status = _associations.back().Initialize(static_cast<IPFKeyInterface*>(this), &acquire);

	// Initialize association to host
	_build_to_host_acquire(host, _gateway, &acquire);
	_associations.emplace_back();
	to_status = _associations.back().Initialize(static_cast<IPFKeyInterface*>(this), &acquire);

	// Error printouts if needed
	if (from_status != NO_ERROR)
	{
		sstream.str("");
		sstream << "Failed to initialize SA from host " << Logger::IPToString(host) << " (" << from_status << ")";
		Logger::Log(LOG_ERROR, sstream.str());
	}
	if (to_status != NO_ERROR)
	{
		sstream.str("");
		sstream << "Failed to initialize SA to host " << Logger::IPToString(host) << " (" << from_status << ")";
		Logger::Log(LOG_ERROR, sstream.str());
	}

	// Return error code
	if (from_status != NO_ERROR)
	{
		return from_status;
	}
	if (to_status != NO_ERROR)
	{
		return to_status;
	}
	return NO_ERROR;
}

int PFKeyManager::RemoveHost(const sockaddr &host)
{
	std::scoped_lock lock {_db_mutex};

	std::stringstream sstream;
	int from_status = NO_ERROR;
	int to_status = NO_ERROR;

	// Get each of the two unidirectional SAs
	PFKeySecurityAssociation *from_host = _get_association_by_src_addr(host);
	PFKeySecurityAssociation *to_host = _get_association_by_dst_addr(host);

	// Close SA from host
	if (from_host != nullptr)
	{
		from_status = from_host->Close();
	}
	else
	{
		// If no SA found, issue a warning
		sstream.str("");
		sstream << "Security association from host " << Logger::IPToString(host) << " not found";
		Logger::Log(LOG_WARNING, sstream.str());
	}

	// Close SA to host
	if (to_host != nullptr)
	{
		to_status = to_host->Close();
	}
	else
	{
		// If no SA found, issue a warning
		sstream.str("");
		sstream << "Security association to host " << Logger::IPToString(host) << " not found";
		Logger::Log(LOG_WARNING, sstream.str());
	}

	// Error printouts if needed
	if (from_status != NO_ERROR)
	{
		sstream.str("");
		sstream << "Failed to close SA from host " << Logger::IPToString(host) << " (" << from_status << ")";
		Logger::Log(LOG_ERROR, sstream.str());
	}
	if (to_status != NO_ERROR)
	{
		sstream.str("");
		sstream << "Failed to close SA to host " << Logger::IPToString(host) << " (" << to_status << ")";
		Logger::Log(LOG_ERROR, sstream.str());
	}

	return NO_ERROR;
}

int PFKeyManager::SendMessage(PFKeyMessageBase *msg)
{
	std::scoped_lock lock {_send_mutex};

	std::stringstream sstream;
	size_t len = PF_KEY_BUFF_SIZE;
	int status = msg->Serialize(_send_buff, len);

	if (status != NO_ERROR)
	{
		sstream.str("");
		sstream << "Serialization failed (" << status << ")";
		Logger::Log(LOG_ERROR, sstream.str());
		return status;
	}

	sstream.str("");
	sstream << "Sending PF Key Message" << std::endl << Logger::BytesToString(_send_buff, len);
	Logger::Log(LOG_DEBUG, sstream.str());

	ssize_t bytes_sent = send(_socket_d, _send_buff, len, 0);

	if (bytes_sent < 0)
	{
		sstream.str("");
		sstream << "Failed to send PF Key message (" << errno << ")";
		Logger::Log(LOG_ERROR, sstream.str());
		return PF_KEY_ERROR_MESSAGE_SEND_FAILED;
	}
	else
	{
		sstream.str("");
		sstream << "Sent " << bytes_sent << " bytes";
		Logger::Log(LOG_DEBUG, sstream.str());
	}

	return NO_ERROR;
}

int PFKeyManager::ReceiveMessage(PFKeyMessageBase *msg)
{
	std::scoped_lock lock {_rcv_mutex};

	int status = NO_ERROR;
	PFKeySecurityAssociation *_assoc = _get_association_by_seq_num(msg->GetSeqNum());

	if (_assoc != nullptr)
	{
		status = _assoc->Receive(msg);
	}

	return status;
}

uint32_t PFKeyManager::GetUniqueSeqNum()
{
	return _next_seq_num++;
}

int PFKeyManager::Initialize()
{
	std::stringstream sstream;

	_initialize_default_extensions();

	_socket_d = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

	if (_socket_d < 0)
	{
		sstream << "Failed to open PF_KEY socket (" << errno << ")";
		Logger::Log(LOG_FATAL, sstream.str());
		return PF_KEY_ERROR_SOCKET_OPEN_FAILED;
	}

	_th = std::thread(std::bind(&PFKeyManager::_receive_loop, this));

	return NO_ERROR;
}

void PFKeyManager::_receive_loop()
{
	std::stringstream sstream;
	Logger::Log(LOG_INFO, "Listening on PF_KEY Socket");

	while (!_exiting)
	{
		ssize_t bytes_received = recv(_socket_d, _rcv_buff, PF_KEY_BUFF_SIZE, 0);

		if (bytes_received > 0)
		{
			sstream.str("");
			sstream << "Received " << bytes_received << " bytes";
			Logger::Log(LOG_DEBUG, sstream.str());

			sadb_msg *hdr = (sadb_msg*)(_rcv_buff);
			std::string type_str;
			switch (hdr->sadb_msg_type)
			{
				case SADB_GETSPI:
				{
					type_str = "SADB_GETSPI";
					break;
				}
				case SADB_UPDATE:
				{
					type_str = "SADB_UPDATE";
					break;
				}
				case SADB_ADD:
				{
					type_str = "SADB_ADD";
					break;
				}
				case SADB_DELETE:
				{
					type_str = "SADB_DELETE";
					break;
				}
				case SADB_GET:
				{
					type_str = "SADB_GET";
					break;
				}
				case SADB_ACQUIRE:
				{
					type_str = "SADB_ACQUIRE";
					break;
				}
				case SADB_REGISTER:
				{
					type_str = "SADB_EXPIRE";
					break;
				}
				case SADB_EXPIRE:
				{
					type_str = "SADB_EXPIRE";
					break;
				}
				case SADB_FLUSH:
				{
					type_str = "SADB_FLUSH";
					break;
				}
				default:
				{
					type_str = "UNKNOWN";
				}
			}

			sstream.str("");
			sstream << "Received PF_KEY message (" << type_str << ")";
			Logger::Log(LOG_DEBUG, sstream.str());

			// Get an instance of the correct message object
			PFKeyMessageBase *msg = PFKeyMessageFactory::Build(_rcv_buff, (size_t)bytes_received);

			if (msg != nullptr)
			{
				// Deserialize the message from the buffer
				int status = msg->Deserialize(_rcv_buff, bytes_received);

				if (status == NO_ERROR)
				{
					// Dispatch the message
					ReceiveMessage(msg);
				}
				else
				{
					sstream.str("");
					sstream << "Failed to deserialize message: (" << status << ")";
					Logger::Log(LOG_ERROR, sstream.str());
				}

				delete msg;
			}
			else
			{
				Logger::Log(LOG_ERROR, "PFKeyMessageFactory: Failed to build PF Key message object");
			}
		}
	}
}

PFKeySecurityAssociation* PFKeyManager::_get_association_by_seq_num(uint32_t seq_num)
{
	for (auto e = _associations.begin(); e < _associations.end(); e++)
	{
		PFKeySecurityAssociation &entry = *e;

		if (seq_num == entry.GetSeqNum())
		{
			return &entry;
		}
	}

	return nullptr;
}

PFKeySecurityAssociation* PFKeyManager::_get_association_by_src_addr(const sockaddr &src)
{
	for (auto e = _associations.begin(); e < _associations.end(); e++)
	{
		PFKeySecurityAssociation &entry = *e;

		if (IPUtils::AddressesAreEqual(src, entry.GetSourceAddress()))
		{
			return &entry;
		}
	}

	return nullptr;
}

PFKeySecurityAssociation* PFKeyManager::_get_association_by_dst_addr(const sockaddr &dst)
{
	for (auto e = _associations.begin(); e < _associations.end(); e++)
	{
		PFKeySecurityAssociation &entry = *e;

		if (IPUtils::AddressesAreEqual(dst, entry.GetDestinationAddress()))
		{
			return &entry;
		}
	}

	return nullptr;
}

void PFKeyManager::_derive_gateway(const struct sockaddr &host_ip, struct sockaddr &gateway)
{
	struct sockaddr_storage netmask;
	switch (host_ip.sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in &_netmask = reinterpret_cast<struct sockaddr_in&>(netmask);
			_netmask.sin_family = AF_INET;
			_netmask.sin_port = 0;
			inet_pton(AF_INET, "255.255.255.252", &_netmask.sin_addr);
			break;
		}
		case AF_INET6:
		{
			// No implemented
			return;
		}
		default:
		{
			return;
		}
	}

	IPUtils::GetFirstHostIP(host_ip, reinterpret_cast<struct sockaddr&>(netmask), gateway);
}

int PFKeyManager::GetReplayContext(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t &right, uint32_t *map)
{
	// Not implemented
	return ERROR_UNSET;
}


int PFKeyManager::MarkSequenceNumber(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t seq_num)
{
	// Not implemented
	return ERROR_UNSET;
}
