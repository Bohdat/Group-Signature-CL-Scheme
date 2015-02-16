#include "manager.h"
Manager::Manager()
{
	pairing_init_set_str(pairing, _PAIRING_PARAM_);
	//init public key
	element_init_G1(g, pairing);
	element_init_GT(gt, pairing);
	element_init_G1(X, pairing);
	element_init_G1(Y, pairing);
	element_init_GT(h, pairing);
	element_init_GT(y1, pairing);
	element_init_GT(y2, pairing);
	element_init_GT(y3, pairing);
	//init issuer key
	element_init_Zr(x, pairing);
	element_init_Zr(y, pairing);
	//init open key
	element_init_Zr(x1, pairing);
	element_init_Zr(x2, pairing);
	element_init_Zr(x3, pairing);
	element_init_Zr(x4, pairing);
	element_init_Zr(x5, pairing);
}
Manager::~Manager()
{	
	//clear public key
	element_clear(g);
	element_clear(gt);
	element_clear(X);
	element_clear(Y);
	element_clear(h);
	element_clear(y1);
	element_clear(y2);
	element_clear(y3);
	//clear issuer key
	element_clear(x);
	element_clear(y);
	//clear open key
	element_clear(x1);
	element_clear(x2);
	element_clear(x3);
	element_clear(x4);
	element_clear(x5);
	//clear paring
	pairing_clear(pairing);
}
void Manager::KeyGeneration(string & PK, string & IK, string & OK)
{
	element_t gt_new;
	element_t g_new;
	element_t X_new;
	element_t Y_new;
	element_t h_new;
	element_t y1_new;
	element_t y2_new;
	element_t y3_new;
	//issuer secret
	element_t x_new;
	element_t y_new;
	//open secret
	element_t x1_new;
	element_t x2_new;
	element_t x3_new;
	element_t x4_new;
	element_t x5_new;
	//init public key
	element_init_G1(g_new, pairing);
	element_init_GT(gt_new, pairing);
	element_init_G1(X_new, pairing);
	element_init_G1(Y_new, pairing);
	element_init_GT(h_new, pairing);
	element_init_GT(y1_new, pairing);
	element_init_GT(y2_new, pairing);
	element_init_GT(y3_new, pairing);
	//init issuer key
	element_init_Zr(x_new, pairing);
	element_init_Zr(y_new, pairing);
	//init open key
	element_init_Zr(x1_new, pairing);
	element_init_Zr(x2_new, pairing);
	element_init_Zr(x3_new, pairing);
	element_init_Zr(x4_new, pairing);
	element_init_Zr(x5_new, pairing);
	//set tmp variables
	element_t temp_y1;
	element_t temp_y2;
	element_init_GT(temp_y1, pairing);
	element_init_GT(temp_y2, pairing);
	//generate system parameters
	element_random(g_new);
	element_pairing(gt_new,g_new,g_new);
	//generate private keys of group manager
	element_random(x_new);
	element_random(y_new);
	//compute X Y
	element_pow_zn(X_new,g_new,x_new);
	element_pow_zn(Y_new,g_new,y_new);
	//generate h != 1
	do
	{
		element_random(h_new);
	}
	while(element_is1(h_new));
	//rand of secret set x1...x5
	element_random(x1_new);
	element_random(x2_new);
	element_random(x3_new);
	element_random(x4_new);
	element_random(x5_new);
	//compute y1
	element_pow_zn(temp_y1,gt_new,x1_new);
	element_pow_zn(temp_y2,h_new,x2_new);
	element_mul(y1_new,temp_y1,temp_y2);
	//compute y2
	element_pow_zn(temp_y1,gt_new,x3_new);
	element_pow_zn(temp_y2,h_new,x4_new);
	element_mul(y2_new,temp_y1,temp_y2);
	//compute y3
	element_pow_zn(y3_new,gt_new,x5_new);
	//Write keys
	PK=GroupPublicKeyToString(g_new, gt_new, X_new, Y_new, h_new, y1_new, y2_new, y3_new);
	IK=SecretIssuerKeyToString(x_new,y_new);
	OK=SecretOpenKeyToString(x1_new,x2_new,x3_new,x4_new,x5_new);
    //clear elements
	//clear public key
	element_clear(g_new);
	element_clear(gt_new);
	element_clear(X_new);
	element_clear(Y_new);
	element_clear(h_new);
	element_clear(y1_new);
	element_clear(y2_new);
	element_clear(y3_new);
	//clear issuer key
	element_clear(x_new);
	element_clear(y_new);
	//clear open key
	element_clear(x1_new);
	element_clear(x2_new);
	element_clear(x3_new);
	element_clear(x4_new);
	element_clear(x5_new);
	//clear tmps
    element_clear(temp_y1);
    element_clear(temp_y2);
}
bool Manager::JoinMember(string request, string & respond)
{
	//elements
	element_t Pi1;
	element_t Pi2;
	element_t Sk;
	element_t R;
	element_init_G1(Pi1,pairing);
	element_init_GT(Pi2, pairing);
	element_init_Zr(Sk, pairing);
	element_init_G1(R,pairing);
	//read & check SoK
	string hash;
	string hash_check;
	RequestFromString(request,hash,Sk,Pi1);
	//check Pi1 is point of curve
	if(element_item_count(Pi1)!=2)
	{
    	element_clear(Pi1);
    	element_clear(Pi2);
    	element_clear(Sk);
    	element_clear(R);
    	return 1;//failure
	}
	element_t tmp1, tmp2;
	element_t c_Hsok;
	element_init_G1(tmp1, pairing);
	element_init_G1(tmp2, pairing);
	element_init_Zr(c_Hsok, pairing);
	element_from_hash(c_Hsok,(void*)hash.c_str(),hash.length());
	element_pow_zn(tmp1,g,Sk);
	element_pow_zn(tmp2,Pi1,c_Hsok);
	element_div(R,tmp1,tmp2);
	hash_check=Helper::Hash_g_R(g,R);
	if(hash.compare(hash_check))
	{
    	element_clear(Pi1);
    	element_clear(Pi2);
    	element_clear(Sk);
    	element_clear(R);
    	element_clear(tmp1);
    	element_clear(tmp2);
    	element_clear(c_Hsok);
    	return 1;//failure
	}
	//generate r_issuer
	element_t issuer_r;
	element_init_Zr(issuer_r, pairing);
	element_random(issuer_r);
	//create a b c
	element_t ai;
	element_t bi;
	element_t ci;
	element_t temp_ci1;
	element_t temp_ci2;
	//init
	element_init_G1(ai, pairing);
	element_init_G1(bi, pairing);
	element_init_G1(ci, pairing);
	element_init_G1(temp_ci1, pairing);
	element_init_G1(temp_ci2, pairing);
	//compute ai bi ci
	element_pow_zn(ai,g,issuer_r);//ai
	element_pow_zn(bi,ai,y);//bi
	element_pow_zn(temp_ci1,ai,x);
	element_pow_zn(temp_ci2,Pi1,issuer_r);
	element_pow_zn(temp_ci2,temp_ci2,x);
	element_pow_zn(temp_ci2,temp_ci2,y);
	element_mul(ci,temp_ci1,temp_ci2);//ci
	//create RESPOND
	respond=MemberSecretToString(ai,bi,ci);
	//compute Pi2
	element_pairing(Pi2,Pi1,g);
	//Write_to_reg_list
	AddToRegistrationList(Pi1, Pi2);
    //clear elements
    element_clear(issuer_r);
    element_clear(Pi1);
    element_clear(Pi2);
    element_clear(temp_ci1);
    element_clear(temp_ci2);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(c_Hsok);
    element_clear(Sk);
    element_clear(R);
    element_clear(ai);
    element_clear(bi);
    element_clear(ci);
    return 0;//success
}
int Manager::Open(string sign, char*mes, int len_mes)
{	
	int ret;
	if(Verification(sign, mes, len_mes)!=true)
		return -1;
	//compare variable
	bool cmp_var=0;
    //elements
    element_t T1,T2,T3,T4;
    element_t T5, T6, T7;
    element_t H;
    element_t Sp;
    element_t Sm;
    element_t Sv;
    element_t c_H;
    element_t tmp_pow;
    element_t check_T4;
    element_t tmp_T2;
    element_init_GT(T1, pairing);
    element_init_GT(T2, pairing);
    element_init_GT(T3, pairing);
    element_init_GT(T4, pairing);
    element_init_G1(T5, pairing);
    element_init_G1(T6, pairing);
    element_init_G1(T7, pairing);
    element_init_Zr(H, pairing);
    element_init_Zr(Sp,pairing);
    element_init_Zr(Sm,pairing);
    element_init_Zr(Sv,pairing);
    element_init_Zr(c_H, pairing);
    element_init_Zr(tmp_pow, pairing);
    element_init_GT(check_T4, pairing);
    element_init_GT(tmp_T2, pairing);
    //read sign
    SignatureFromString(sign, c_H, Sp, Sm, Sv, T1, T2, T3, T4, T5, T6, T7);
    //add verify sign
    Helper::Hash_T1_T2_T3(H,T1,T2,T3);
    //T4 check
    element_mul(tmp_pow, x5,H);
    element_add(tmp_pow, tmp_pow,x3);
    element_pow_zn(check_T4, T1, tmp_pow);
    element_pow_zn(tmp_T2, T2, x4);
    element_mul(check_T4, check_T4,tmp_T2);
    cmp_var=element_cmp(check_T4,T4);//0==ok
    //compute Pi2
    element_t check_Pi2;
    element_init_GT(check_Pi2, pairing);
    element_pow_zn(tmp_T2, T1, x1);
    element_pow_zn(check_Pi2, T2, x2);
    element_mul(tmp_T2, tmp_T2,check_Pi2);
    element_div(check_Pi2, T3,tmp_T2);
    //find Pi2 in reg list
    if(cmp_var)
    	ret=-1;
    else
    	ret=SearchInRegistrationList(check_Pi2);
    //clear elements
    element_clear(T1);
    element_clear(T2);
    element_clear(T3);
    element_clear(T4);
    element_clear(T5);
    element_clear(T6);
    element_clear(T7);
    element_clear(H);
    element_clear(c_H);
    element_clear(Sp);
    element_clear(Sm);
    element_clear(Sv);
    element_clear(tmp_pow);
    element_clear(check_T4);
    element_clear(tmp_T2);
    return ret;
}
bool Manager::Verification(string signature, char*mes, int len_mes)
{
    //compare variables
    bool cmp_value_1=0;
    bool cmp_value_2=0;
    //elements
    element_t T1,T2,T3,T4;
    element_t T5, T6, T7;
    element_t c_H;
    element_t H;
    element_t Sp;
    element_t Sm;
    element_t Sv;
    //init
    element_init_GT(T1, pairing);
    element_init_GT(T2, pairing);
    element_init_GT(T3, pairing);
    element_init_GT(T4, pairing);
    element_init_G1(T5, pairing);
    element_init_G1(T6, pairing);
    element_init_G1(T7, pairing);
    element_init_Zr(Sp,pairing);
    element_init_Zr(Sm,pairing);
    element_init_Zr(Sv,pairing);
    element_init_Zr(H, pairing);
    element_init_Zr(c_H, pairing);
    SignatureFromString(signature, c_H,Sp,Sm,Sv,T1,T2,T3,T4,T5,T6,T7);
    //heshing
    Helper::Hash_T1_T2_T3(H,T1,T2,T3);
    //compute R1'
    element_t tmp_1;
    element_t tmp_2;
    element_t tmp_3;
    element_t R1_;
    element_init_GT(R1_, pairing);
    element_init_GT(tmp_1, pairing);
    element_init_GT(tmp_2, pairing);
    element_init_GT(tmp_3, pairing);
    element_pairing(tmp_1, g, T7);
    element_pow_zn(tmp_2, tmp_1, Sp);
    element_pairing(tmp_1, X, T6);
    element_pow_zn(tmp_3, tmp_1, Sm);
    element_div(R1_, tmp_2, tmp_3);
    element_pairing(tmp_3, X, T5);
    element_pow_zn(tmp_3, tmp_3, c_H);
    element_div(R1_, R1_, tmp_3);
    //compute R2'
    element_t R2_;
    element_init_GT(R2_, pairing);
    element_pow_zn(R2_, gt, Sv);
    element_pow_zn(tmp_1, T1, c_H);
    element_div(R2_, R2_, tmp_1);
    //compute R3'
    element_t R3_;
    element_init_GT(R3_, pairing);
    element_pow_zn(tmp_1, h, Sv);
    element_pow_zn(tmp_2, T2, c_H);
    element_sub(R3_, tmp_1, tmp_2);
    //compute R4'
    element_t R4_;
    element_init_GT(R4_, pairing);
    element_pow_zn(tmp_1, y1, Sv);
    element_pow_zn(tmp_2, gt, Sm);
    element_mul(tmp_3, tmp_1, tmp_2);
    element_pow_zn(tmp_1,T3, c_H);
    element_sub(R4_, tmp_3, tmp_1);
    //compute R5'
    element_t R5_;
    element_init_GT(R5_, pairing);
    element_t tmp_pow;
    element_init_Zr(tmp_pow, pairing);
    element_t tmp_div;
    element_init_GT(tmp_div, pairing);
    element_pow_zn(R5_, y2, Sv);
    element_pow_zn(tmp_div,y3,H);
    element_pow_zn(tmp_div,tmp_div,Sv);
    element_mul(R5_,R5_,tmp_div);
    element_pow_zn(tmp_div,T4, c_H);
    element_div(R5_, R5_, tmp_div);
    //check c_H == c_H'
    element_t check_c_H;
    element_init_Zr(check_c_H, pairing);
    Helper::Hash_C(check_c_H,R1_,R2_,R3_,R4_,R5_,g,gt,X,Y,h,y1,y2,y3,mes,len_mes);
    //check e(T 5 , Y ) == e(g, T 6 )
    element_t check_1;
    element_init_GT(check_1, pairing);
    element_t check_2;
    element_init_GT(check_2, pairing);
    element_pairing(check_1, T5,Y);
    element_pairing(check_2, g,T6);
    //cmp_value_1
    cmp_value_1=element_cmp(check_c_H,c_H);//0==ok
    //cmp_value_2
    cmp_value_2=element_cmp(check_1,check_2);//0==ok
    //clear elements
    element_clear(T1);
    element_clear(T2);
    element_clear(T3);
    element_clear(T4);
    element_clear(T5);
    element_clear(T6);
    element_clear(T7);
    element_clear(Sp);
    element_clear(Sm);
    element_clear(Sv);
    element_clear(H);
    element_clear(c_H);
    element_clear(R1_);
    element_clear(R2_);
    element_clear(R3_);
    element_clear(R4_);
    element_clear(R5_);
    element_clear(tmp_1);
    element_clear(tmp_2);
    element_clear(tmp_3);
    element_clear(tmp_pow);
    element_clear(tmp_div);
    element_clear(check_c_H);
    element_clear(check_1);
    element_clear(check_2); 
    if(cmp_value_1||cmp_value_2)
        return 0;
    else
        return 1;
}
string Manager::GroupPublicKeyToString(element_t g_w,element_t gt_w,element_t X_w,element_t Y_w,element_t h_w,element_t y1_w,element_t y2_w,element_t y3_w)
{
	string gpk;
    gpk.append(Helper::Element_to_BASE_58(g_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(gt_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(X_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(Y_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(h_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(y1_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(y2_w)+"\n");
    gpk.append(Helper::Element_to_BASE_58(y3_w)+"\n");
    return gpk;
}
string Manager::SecretIssuerKeyToString(element_t x_new, element_t y_new)
{
	string issuer_key;
    issuer_key.append(Helper::Element_to_BASE_58(x_new)+"\n");
    issuer_key.append(Helper::Element_to_BASE_58(y_new)+"\n");
    return issuer_key;
}
string Manager::SecretOpenKeyToString(element_t x1_w, element_t x2_w, element_t x3_w,element_t x4_w,element_t x5_w)
{
	string open_key;
    open_key.append(Helper::Element_to_BASE_58(x1_w)+"\n");
    open_key.append(Helper::Element_to_BASE_58(x2_w)+"\n");
    open_key.append(Helper::Element_to_BASE_58(x3_w)+"\n");
    open_key.append(Helper::Element_to_BASE_58(x4_w)+"\n");
    open_key.append(Helper::Element_to_BASE_58(x5_w)+"\n");
    return open_key;
}
string Manager::MemberSecretToString(element_t ai,element_t bi,element_t ci)
{
	string member_secret;
    member_secret.append(Helper::Element_to_BASE_58(ai)+"\n");
    member_secret.append(Helper::Element_to_BASE_58(bi)+"\n");
    member_secret.append(Helper::Element_to_BASE_58(ci)+"\n");
    return member_secret;
} 
void Manager::RequestFromString(string request,string & hash_string, element_t Sk, element_t Pi1)
{
	Helper::TakeNextLineFromString(request, hash_string);
    Helper::TakeNextElementFromString(request,Sk);
    Helper::TakeNextElementFromString(request,Pi1);
}
void Manager::AddToRegistrationList(element_t Pi1, element_t Pi2)
{
    RegistrList.append(Helper::Element_to_BASE_58(Pi1)+"\n");
    RegistrList.append(Helper::Element_to_BASE_58(Pi2)+"\n");
    RegistrList.append(Helper::int_to_HEX(member_count++)+end_point);
}
int Manager::SearchInRegistrationList(element_t Pi2)
{
	string tmp;
	tmp=Helper::Element_to_BASE_58(Pi2);
	size_t found=RegistrList.find(tmp);
	if(found==string::npos)
		return -1;
	found=RegistrList.find(end_point,found);
	if(found==string::npos)
		return -1;
	return Helper::int_from_HEX(RegistrList.substr(found-8,8));
}
string Manager::GetRegistrationList()
{
	return RegistrList;
}
void Manager::SetRegistrationList(string RL)
{
	RegistrList=RL;
	//set member_count value = last_number + 1
	size_t found=RegistrList.find(end_point,found);
	if(found==string::npos)
		member_count=0;
	else
		member_count=Helper::int_from_HEX(RegistrList.substr(found-8,8))+1;
}
void Manager::SignatureFromString(string signature, element_t c_H,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7)
{
    Helper::TakeNextElementFromString(signature,c_H);
    Helper::TakeNextElementFromString(signature,Sp);
    Helper::TakeNextElementFromString(signature,Sm);
    Helper::TakeNextElementFromString(signature,Sv);
    Helper::TakeNextElementFromString(signature,T1);
    Helper::TakeNextElementFromString(signature,T2);
    Helper::TakeNextElementFromString(signature,T3);
    Helper::TakeNextElementFromString(signature,T4);
    Helper::TakeNextElementFromString(signature,T5);
    Helper::TakeNextElementFromString(signature,T6);
    Helper::TakeNextElementFromString(signature,T7);
}
string Manager::GetPublicKey()
{
	return GroupPublicKeyToString(g, gt, X, Y, h, y1, y2, y3);
}
string Manager::GetIssuerKey()
{
	return SecretIssuerKeyToString(x,y);
}
string Manager::GetOpenKey()
{
	return SecretOpenKeyToString(x1, x2, x3, x4, x5);
}
void Manager::SetPublicKey(string PK)
{
    Helper::TakeNextElementFromString(PK,g);
    Helper::TakeNextElementFromString(PK,gt);
    Helper::TakeNextElementFromString(PK,X);
    Helper::TakeNextElementFromString(PK,Y);
    Helper::TakeNextElementFromString(PK,h);
    Helper::TakeNextElementFromString(PK,y1);
    Helper::TakeNextElementFromString(PK,y2);
    Helper::TakeNextElementFromString(PK,y3);
}
void Manager::SetIssuerKey(string IK)
{
    Helper::TakeNextElementFromString(IK,x);
    Helper::TakeNextElementFromString(IK,y);
}
void Manager::SetOpenKey(string OK)
{
    Helper::TakeNextElementFromString(OK,x1);
    Helper::TakeNextElementFromString(OK,x2);
    Helper::TakeNextElementFromString(OK,x3);
    Helper::TakeNextElementFromString(OK,x4);
    Helper::TakeNextElementFromString(OK,x5);
}