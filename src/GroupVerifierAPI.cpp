#include "GroupVerifierAPI.h"
GroupVerifierAPI::GroupVerifierAPI()
{
	GroupVerifier=new Verifier();
}
GroupVerifierAPI::~GroupVerifierAPI()
{
	delete GroupVerifier;
}
string GroupVerifierAPI::SerializeVerifier()
{
	return GroupVerifier->GetPublicKey();
}
void GroupVerifierAPI::DeserializeVerifier(string verifier)
{
	GroupVerifier->SetPublicKey(verifier);
}
bool GroupVerifierAPI::VerificationSignature(string sign,string mes)
{
	return GroupVerifier->Verification(sign,(char*)mes.c_str(),mes.length());
}
void GroupVerifierAPI::CreateNewVerifier(string PK)
{
	GroupVerifier->SetPublicKey(PK);
}