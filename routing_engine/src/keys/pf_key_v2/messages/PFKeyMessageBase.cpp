#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"

PFKeyMessageBase::~PFKeyMessageBase()
{
}

uint8_t PFKeyMessageBase::GetErrorNum()
{
	return _header.sadb_msg_errno;
}

void PFKeyMessageBase::SetErrorNum(uint8_t num)
{
	_header.sadb_msg_errno = num;
}

uint8_t PFKeyMessageBase::GetSAType()
{
	return _header.sadb_msg_satype;
}

void PFKeyMessageBase::SetSAType(uint8_t type)
{
	_header.sadb_msg_satype = type;
}

uint32_t PFKeyMessageBase::GetSeqNum()
{
	return _header.sadb_msg_seq;
}

void PFKeyMessageBase::SetSeqNum(uint32_t num)
{
	_header.sadb_msg_seq = num;
}

uint32_t PFKeyMessageBase::GetPID()
{
	return _header.sadb_msg_pid;
}

void PFKeyMessageBase::SetPID(uint32_t pid)
{
	_header.sadb_msg_pid = pid;
}
