//g++ *.cpp -l pbc -l gmp -I /pbc-0.5.14/include -o test
#include "GroupManagerAPI.h"
#include "GroupMemberAPI.h"
#include "GroupVerifierAPI.h"
int main(int argc,char**argv)
{
	GroupManagerAPI Server;	//Server - manager of group
	GroupMemberAPI User0;	//User
	GroupMemberAPI User1;	//Another user
	GroupMemberAPI User2;	//Another user
	GroupVerifierAPI Verifier;		//Verifier
	string gpk;		//group public key
	//strings for serialization
	string sServer;
	string sUser0;
	string sUser1;
	string sUser2;
	string sVerifier;
	//strings for requests
	string request0;
	string request1;
	string request2;
	//strings for responds
	string respond0;
	string respond1;
	string respond2;
	//results of registration process
	bool reg_status0;
	bool reg_status1;
	bool reg_status2;
	//strings for signature
	string sign0;
	string sign1;
	string sign2;
	//results of verification process
	bool result;
	//results of opening process
	int open;
	//compute...
	Server.CreateNewGroup();
	gpk=Server.GetGroupPublicKey();
	//create users
	User0.CreateNewMember(gpk);
	User1.CreateNewMember(gpk);
	User2.CreateNewMember(gpk);
	//request keys
	request0=User0.CreateJoinRequest();
	request1=User1.CreateJoinRequest();
	request2=User2.CreateJoinRequest();
	//recive requests by server
	reg_status0=Server.RegisterNewMember(request0,respond0);
	reg_status1=Server.RegisterNewMember(request1,respond1);
	reg_status2=Server.RegisterNewMember(request2,respond2);
	printf("User_0 registr %d\n",reg_status0);
	printf("User_1 registr %d\n",reg_status1);
	printf("User_2 registr %d\n",reg_status2);
	//recive users keys
	User0.ReciveMemberKey(respond0);
	User1.ReciveMemberKey(respond1);
	User2.ReciveMemberKey(respond2);
	//sign the messages
	sign0=User0.CreateSignature("qwe");
	sign1=User1.CreateSignature("asd");
	sign2=User2.CreateSignature("zxc");
	//init verifier by public key
	Verifier.CreateNewVerifier(gpk);
	//verify
	result=Verifier.VerificationSignature(sign0,"qwe");
	printf("Sign_0 verify %d\n",result);
	//*** Serialize 	***
	sServer=Server.SerializeGroup();
	sUser0=User0.SerializeMember();
	sUser1=User1.SerializeMember();
	sUser2=User2.SerializeMember();
	sVerifier=Verifier.SerializeVerifier();
	//*** Deserialize 	***
	Server.DeserializeGroup(sServer);
	User0.DeserializeMember(sUser0);
	User1.DeserializeMember(sUser1);
	User2.DeserializeMember(sUser2);
	Verifier.DeserializeVerifier(sVerifier);
	//*** Continue 		***
	result=Verifier.VerificationSignature(sign1,"asd");
	printf("Sign_1 verify %d\n",result);
	result=Verifier.VerificationSignature(sign2,"zxc");
	printf("Sign_2 verify %d\n",result);
	//opening
	open=Server.OpenSignature(sign0,"qwe");
	printf("This is user: %d\n",open);
	open=Server.OpenSignature(sign1,"asd");
	printf("This is user: %d\n",open);
	open=Server.OpenSignature(sign2,"zxc");
	printf("This is user: %d\n",open);
	return 0;
}