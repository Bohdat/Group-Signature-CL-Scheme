#include <string>
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "helper.h"
using namespace std;
class Member
{
public:
    Member();
    ~Member();
    string CreateRequest();
    void SetSecretKey(string SK);
    string Signature(char*mes, int len_mes);
    void SetPublicKey(string PK);
    string GetKHex();
    string GetPublicKey();
    string GetSecretKey();
private:
    void MemberSecretFromString(string member_secret);
    string Hash_g_R(element_t R);
    string RequestToString(string hash_string, element_t Sk, element_t Pi1);
    string SignatureToString(element_t c,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
    string GroupPublicKeyToString(element_t g_w,element_t gt_w,element_t X_w,element_t Y_w,element_t h_w,element_t y1_w,element_t y2_w,element_t y3_w);
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
    //Secret key
    string ki_hex;
    element_t ki;
    element_t ai;
    element_t bi;
    element_t ci;
};