#include "member.h"
class GroupMemberAPI
{
public:
	GroupMemberAPI();
	~GroupMemberAPI();
	string SerializeMember();
	void DeserializeMember(string member);
	void CreateNewMember(string PK);
	string CreateJoinRequest();
	void ReciveMemberKey(string responce);
	string CreateSignature(string mes);
private:
	Member* GroupMember;
};