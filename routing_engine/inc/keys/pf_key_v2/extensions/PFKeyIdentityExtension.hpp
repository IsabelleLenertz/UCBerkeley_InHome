#ifndef INC_PFKEYIDENTITYEXTENSION_HPP_
#define INC_PFKEYIDENTITYEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"
#include <string>

class PFKeyIdentityExtension : public IPFKeyExtension
{
public:
	PFKeyIdentityExtension();
	// PFKeyIdentityExtension(const PFKeyIdentityExtension &rhs);
	~PFKeyIdentityExtension() override;

	PFKeyIdentityExtension& operator=(const PFKeyIdentityExtension &rhs);

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t &len);
	size_t GetLengthBytes();
	uint16_t GetType();
	bool IsValid();

	/// <summary>
	/// Sets identity extension as a source identity
	/// </summary>
	void SetTypeSource();

	/// <summary>
	/// Sets identity extension as a destination identity
	/// </summary>
	void SetTypeDestination();

	/// <summary>
	/// Gets the type of identifier represented
	/// by this ID extension
	/// </summary>
	/// <returns>ID Type</returns>
	uint16_t GetIDType();

	/// <summary>
	/// Sets the type of identifier represented
	/// by this ID extension
	/// </summary>
	void SetIDType(uint16_t id_type);

	/// <summary>
	/// Gets the 64-bit ID number
	/// </summary>
	/// <returns>ID number</returns>
	uint64_t GetIDNumber();

	/// <summary>
	/// Sets the 64-bit ID number
	/// </summary>
	/// <param name="id_num">64-bit ID number</param>
	void SetIDNumber(uint64_t id_num);

	/// <summary>
	/// Gets the ID string as a null-terminated C string
	/// </summary>
	/// <returns>null-terminated ID string</returns>
	const char * GetIDString();

	/// <summary>
	/// Sets the ID string
	/// </summary>
	/// <param name="id_string">C string ID string</param>
	void SetIDString(const char *id_string);

private:
	uint16_t _type;
	uint16_t _id_type;
	uint64_t _id_num;
	std::string _id_string;
};

#endif /* INC_KEYS_PF_KEY_V2_EXTENSIONS_PFKEYIDENTITYEXTENSION_HPP_ */
