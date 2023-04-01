#ifndef INC_PFKEYASSOCIATIONEXTENSION_HPP_
#define INC_PFKEYASSOCIATIONEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"

class PFKeyAssociationExtension : public IPFKeyExtension
{
public:
	PFKeyAssociationExtension();
	// PFKeyAssociationExtension(const PFKeyAssociationExtension &rhs);
	~PFKeyAssociationExtension() override;

	PFKeyAssociationExtension& operator=(const PFKeyAssociationExtension &rhs);

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(const uint8_t *data, size_t &len);

	size_t GetLengthBytes();

	uint16_t GetType();

	bool IsValid();

	/// <summary>
	/// Gets the Security Parameters Index (SPI)
	/// </summary>
	/// <returns>SPI</returns>
	uint32_t GetSPI();

	/// <summary>
	/// Sets the Security Parameters Index (SPI)
	/// </summary>
	/// <param name="spi">SPI</param>
	void SetSPI(uint32_t spi);

	/// <summary>
	/// Gets the replay window
	/// </summary>
	/// <returns>Replay window</returns>
	uint8_t GetReplayWindow();

	/// <summary>
	/// Sets the replay window
	/// </summary>
	/// <param name="window">Replay window</param>
	void SetReplayWindow(uint8_t window);

	/// <summary>
	/// Gets the state of the security association
	/// </summary>
	/// <returns>State</returns>
	uint8_t GetState();

	/// <summary>
	/// Sets the state of the security association
	/// </summary>
	/// <param name="state">State</param>
	void SetState(uint8_t state);

	/// <summary>
	/// Gets the authentication algorithm
	/// </summary>
	/// <returns>Authentication algorithm</returns>
	uint8_t GetAuthAlgorithm();

	/// <summary>
	/// Sets the authentication algorithm
	/// </summary>
	/// <param name="alg">Authentication algorithm</param>
	void SetAuthAlgorithm(uint8_t alg);

	/// <summary>
	/// Gets the authentication algorithm
	/// </summary>
	/// <returns>Encryption algorithm</returns>
	uint8_t GetEncryptAlgorithm();

	/// <summary>
	/// Sets the auuthentication algorithm
	/// </summary>
	/// <param name="alg">Encryption algorithm</param>
	void SetEncryptAlgorithm(uint8_t alg);

	/// <summary>
	/// Gets the 32-bit flags word
	/// </summary>
	/// <returns>Flags</returns>
	uint32_t GetFlags();

	/// <summary>
	/// Sets the 32-bit flags word
	/// </summary>
	/// <param name="flags">Flags</param>
	void SetFlags(uint32_t flags);

private:
	struct sadb_sa _sa;
};

#endif
