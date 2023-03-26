#ifndef INC_PFKEYKEYEXTENSION_HPP_
#define INC_PFKEYKEYEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"
#include <vector>

class PFKeyKeyExtension : public IPFKeyExtension
{
public:
	PFKeyKeyExtension();
	// PFKeyKeyExtension(const PFKeyKeyExtension &rhs);
	~PFKeyKeyExtension() override;

	PFKeyKeyExtension& operator=(const PFKeyKeyExtension &rhs);

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(const uint8_t *data, size_t &len);

	size_t GetLengthBytes();

	uint16_t GetType();

	bool IsValid();

	/// <summary>
	/// Sets the type of this extension
	/// to SADB_EXT_KEY_AUTH
	/// </summary>
	void SetTypeAuth();

	/// <summary>
	/// Sets the type of this extension
	/// to SADB_EXT_KEY_ENCRYPT
	/// </summary>
	void SetTypeEncrypt();

	/// <summary>
	/// Gets the key data
	/// </summary>
	/// <param name="data">Pointer to data out</param>
	/// <returns>Size of data, in bytes</returns>
	size_t GetKeyData(const uint8_t* &data);

	/// <summary>
	/// Gets the number of bits in key
	/// </summary>
	/// <returns>Number of bits</returns>
	uint16_t GetNumKeyBits();

	/// <summary>
	/// Sets the key data
	/// </summary>
	/// <param name="data">Pointer to key data</param>
	/// <param name="bits">Number of bits in key data</param>
	/// <param name="len">Length of data, in bytes</returns>
	void SetKeyData(const uint8_t *data, size_t len, uint16_t bits);

private:
	uint16_t _type;
	uint16_t _bits;
	std::vector<uint8_t> _key_data;
};

#endif
