#include "GroupManagerAPI.h"
GroupManagerAPI::GroupManagerAPI()
{
	GroupManager=new Manager();
}
GroupManagerAPI::~GroupManagerAPI()
{
	delete GroupManager;
}
void GroupManagerAPI::CreateNewGroup()
{
	string GroupPublicKey;
	string ManagerIssuerKey;
	string ManagerOpenKey;
	GroupManager->KeyGeneration(GroupPublicKey,ManagerIssuerKey,ManagerOpenKey);
	GroupManager->SetPublicKey(GroupPublicKey);	
	GroupManager->SetIssuerKey(ManagerIssuerKey);	
	GroupManager->SetOpenKey(ManagerOpenKey);
	GroupManager->SetRegistrationList("");
}
string GroupManagerAPI::SerializeGroup()
{
	string group;
	group.append(GroupManager->GetPublicKey()+seporator);
	group.append(GroupManager->GetIssuerKey()+seporator);
	group.append(GroupManager->GetOpenKey()+seporator);
	group.append(GroupManager->GetRegistrationList()+seporator);
	return group;
}
void GroupManagerAPI::DeserializeGroup(string  group)
{
	GroupManager->SetPublicKey(Helper::TakeNextItemFromString(group));	
	GroupManager->SetIssuerKey(Helper::TakeNextItemFromString(group));	
	GroupManager->SetOpenKey(Helper::TakeNextItemFromString(group));	
	GroupManager->SetRegistrationList(Helper::TakeNextItemFromString(group));
}
bool GroupManagerAPI::RegisterNewMember(string request, string & respond)
{
	return GroupManager->JoinMember(request, respond);
}
int GroupManagerAPI::OpenSignature(string signature, string mes)
{
	return GroupManager->Open(signature, (char*)mes.c_str(), mes.length());
}
string GroupManagerAPI::GetGroupPublicKey()
{
	return GroupManager->GetPublicKey();
}