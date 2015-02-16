#ifndef _HELPER_
#define _HELPER_
#include <string>
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include "./base58/base58.h"
#define seporator "\n***"
#define end_point "\n+++"
#define _PAIRING_PARAM_ "type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1"
using namespace std;
class Helper
{
public:
	static string Element_to_HEX(element_t elem);
	static string int_to_HEX(int x);
	static int int_from_HEX(string str);
	static void Element_from_HEX(element_t elem,string elem_hex);
	static void TakeNextElementFromString(string & tmp, element_t elem);
	static void TakeNextLineFromString(string & str, string & line);
	static string TakeNextItemFromString(string & str);
	static void Hash_T1_T2_T3(element_t res,element_t T1,element_t T2,element_t T3);
    static void Hash_C(element_t res,element_t R1,element_t R2,element_t R3,element_t R4, element_t R5,element_t g,element_t gt,element_t X, element_t Y, element_t h,element_t y1, element_t y2, element_t y3,char* mes, int len_mes);
	static string Hash_g_R(element_t g, element_t R);

	static string Element_to_BASE_58(element_t elem);
	static void Element_from_BASE_58(element_t elem,string elem_base58);
};
#endif