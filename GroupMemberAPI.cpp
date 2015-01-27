#include "GroupMemberAPI.h"
GroupMemberAPI::GroupMemberAPI()
{
	GroupMember=new Member();
}
GroupMemberAPI::~GroupMemberAPI()
{
	delete GroupMember;
}
string GroupMemberAPI::SerializeMember()
{
	return GroupMember->GetPublicKey()+seporator+GroupMember->GetSecretKey()+seporator;
}
void GroupMemberAPI::DeserializeMember(string member)
{
	GroupMember->SetPublicKey(Helper::TakeNextItemFromString(member));	
	GroupMember->SetSecretKey(Helper::TakeNextItemFromString(member));
}
void GroupMemberAPI::CreateNewMember(string PK)
{
	GroupMember->SetPublicKey(PK);
}
string GroupMemberAPI::CreateJoinRequest()
{
	return GroupMember->CreateRequest();
}
void GroupMemberAPI::ReciveMemberKey(string responce)
{
	GroupMember->SetSecretKey(GroupMember->GetKHex()+"\n"+responce+"\n");
}
string GroupMemberAPI::CreateSignature(string mes)
{
	return GroupMember->Signature((char*)mes.c_str(), mes.length());
}