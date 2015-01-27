#include "verifier.h"
class GroupVerifierAPI
{
public:
	GroupVerifierAPI();
	~GroupVerifierAPI();
	string SerializeVerifier();
	void DeserializeVerifier(string member);
	bool VerificationSignature(string sign,string mes);
	void CreateNewVerifier(string PK);
private:
	Verifier* GroupVerifier;
};