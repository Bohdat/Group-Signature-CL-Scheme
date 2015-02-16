#include <string>
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "helper.h"
using namespace std;
class Verifier
{
public:
    Verifier();
    ~Verifier();
	bool Verification(string signature, char*mes, int len_mes);	
    string GetPublicKey();
    void SetPublicKey(string PK);
private:
    void Read_Sign(element_t c,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
    void SignatureFromString(string signature, element_t c_H,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
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
};