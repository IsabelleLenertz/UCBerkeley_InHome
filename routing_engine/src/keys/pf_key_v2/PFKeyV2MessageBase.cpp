#include "keys/pf_key_v2/PFKeyV2MessageBase.hpp"

PFKeyV2MessageBase::PFKeyV2MessageBase()
	: _err_code(0),
	  _sa_type(SADB_SATYPE_AH),
	  _seq_num(0),
	  _pid(0)
{
}

PFKeyV2MessageBase::~PFKeyV2MessageBase()
{
}

uint8_t PFKeyV2MessageBase::GetErrorCode()
{
	return _err_code;
}

uint8_t PFKeyV2MessageBase::GetSAType()
{
	return _sa_type;
}

void PFKeyV2MessageBase::SetSAType(uint8_t type)
{
	_sa_type = type;
}

uint32_t PFKeyV2MessageBase::GetSequenceNumber()
{
	return _seq_num;
}

void PFKeyV2MessageBase::SetSequenceNumber(uint32_t num)
{
	_seq_num = num;
}


uint32_t PFKeyV2MessageBase::GetPID()
{
	return _pid;
}


void PFKeyV2MessageBase::SetPID(uint32_t pid)
{
	_pid = pid;
}
