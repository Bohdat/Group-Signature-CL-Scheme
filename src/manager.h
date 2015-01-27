#include <string>
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "helper.h"
using namespace std;
class Manager
{
public:
	Manager();
	~Manager();
	void KeyGeneration(string & PK, string & IK, string & OK);
	void SetPublicKey(string PK);
	void SetIssuerKey(string IK);
	void SetOpenKey(string OK);
	void SetRegistrationList(string RL);
	//recive member request and set respond, if success return 0
	bool JoinMember(string request, string & respond);
	int Open(string sign, char*mes, int len_mes);
	string GetPublicKey();
	string GetIssuerKey();
	string GetOpenKey();
	string GetRegistrationList();
private:
	string GroupPublicKeyToString(element_t g_w,element_t gt_w,element_t X_w,element_t Y_w,element_t h_w,element_t y1_w,element_t y2_w,element_t y3_w);
	void GroupPublicKeyFromString(string gpk);
	string SecretIssuerKeyToString(element_t x, element_t y);
	void SecretIssuerKeyFromString(string issuer_key,element_t x, element_t y);
	string SecretOpenKeyToString(element_t x1_w, element_t x2_w, element_t x3_w,element_t x4_w,element_t x5_w);
	void SecretOpenKeyFromString(string open_key, element_t x1, element_t x2, element_t x3);
	string MemberSecretToString(element_t ai,element_t bi,element_t ci);
	void RequestFromString(string request,string & hash_string, element_t Sk, element_t Pi1);
	void SignatureFromString(string signature, element_t c_H,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
	void AddToRegistrationList(element_t Pi1, element_t Pi2);
	int SearchInRegistrationList(element_t Pi2);
	bool Verification(string signature,char*mes, int len_mes);
	//pairing
	pairing_t pairing;
	//Public key
    element_t gt;
	element_t g;
	element_t X;
	element_t Y;
	element_t h;
	element_t y1;
	element_t y2;
	element_t y3;
	//issuer secret
	element_t x;
	element_t y;
	//open secret
	element_t x1;
	element_t x2;
	element_t x3;
	element_t x4;
	element_t x5;
	//registration list in HEX
	string RegistrList;
	//count of registrated members in group
	int member_count;
};