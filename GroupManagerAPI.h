#include "manager.h"
class GroupManagerAPI
{
public:
	GroupManagerAPI();
	~GroupManagerAPI();
	//Generation new keys and return them in HEX string (PubKey+IssueKey+OpenKey+RegList=0)
	void CreateNewGroup();
	//Take current group in HEX string (PubKey+IssueKey+OpenKey+RegList)
	string SerializeGroup();
	//Set group from string (PubKey+IssueKey+OpenKey+RegList)
	void DeserializeGroup(string group);
	//add new member to current group
	bool RegisterNewMember(string request, string & respond);
	//open sign in current group
	int OpenSignature(string signature, string mes);
	//get gpk from current group
	string GetGroupPublicKey();
private:
	Manager* GroupManager;
};