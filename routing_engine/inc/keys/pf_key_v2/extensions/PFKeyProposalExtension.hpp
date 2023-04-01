#ifndef INC_PFKEYPROPOSALEXTENSION_HPP_
#define INC_PFKEYPROPOSALEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"
#include <vector>

class PFKeyProposalExtension : public IPFKeyExtension
{
public:
	PFKeyProposalExtension();
	// PFKeyProposalExtension(const PFKeyProposalExtension &rhs);
	~PFKeyProposalExtension() override;

	PFKeyProposalExtension& operator=(const PFKeyProposalExtension &rhs);

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(const uint8_t *data, size_t &len);

	size_t GetLengthBytes();

	uint16_t GetType();

	bool IsValid();

	/// <summary>
	/// Gets the size of the replay window
	/// </summary>
	/// <returns>Size of replay window</returns>
	uint8_t GetReplayWindow();

	/// <summary>
	/// Sets the size of the replay window
	/// </summary>
	/// <param name="window">Size of replay window</param>
	void SetReplayWindow(uint8_t window);

	/// <summary>
	/// Adds the specified combination to the list
	/// of proposed combinations
	/// </summary>
	/// <param name="comb">Combination to add</param>
	void AddCombination(const struct sadb_comb comb);

	/// <summary>
	/// Gets the number of combinations contained
	/// in the list of proposed combinations
	/// </summary>
	/// <returns>Number of combinations</returns>
	size_t GetCombinationCount();

	/// <summary>
	/// Gets the combination at the specified index
	/// in the list of proposed combinations
	/// </summary>
	/// <param name="index">Index to get</param>
	/// <returns>Pointer to combination object</returns>
	struct sadb_comb *GetCombinationAt(size_t index);

	/// <summary>
	/// Removes the combination at the specified index
	/// from the list of proposed combinations
	/// </summary>
	/// <param name="index">Index to remove</param>
	void RemoveCombinationAt(size_t index);

private:
	uint8_t _window;
	std::vector<struct sadb_comb> _combs;
};

#endif
