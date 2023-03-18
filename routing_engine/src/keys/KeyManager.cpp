#include "keys/KeyManager.hpp"
#include "status/error_codes.hpp"

KeyManager::KeyManager()
	: _update_sa_callback()
{
}

KeyManager::~KeyManager()
{
}

int KeyManager::SetProposal(const std::vector<struct sadb_comb> combs)
{
	// TODO Implement
	return NO_ERROR;
}


int KeyManager::AcquireKey(const struct sockaddr &src, const struct sockaddr &dst)
{
	// TODO Implement
	return NO_ERROR;
}

int KeyManager::DeleteKey(const struct sockaddr &src, const struct sockaddr &dst)
{
	// TODO Implement
	return NO_ERROR;
}

int KeyManager::SetSAUpdatedCallback(UpdateSACallback_t callback)
{
	// TODO Implement
	return NO_ERROR;
}

int KeyManager::ProcessUpdate(const struct sockaddr &src, const struct sockaddr &dst, uint32_t spi)
{
	// TODO Implement
	return NO_ERROR;
}
