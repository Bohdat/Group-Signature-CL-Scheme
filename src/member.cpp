#include "member.h"
Member::Member()
{
    pairing_init_set_str(pairing, _PAIRING_PARAM_);
    element_init_G1(g, pairing);
    element_init_GT(gt, pairing);
    element_init_G1(X, pairing);
    element_init_G1(Y, pairing);
    element_init_GT(h, pairing);
    element_init_GT(y1, pairing);
    element_init_GT(y2, pairing);
    element_init_GT(y3, pairing);
    //init secret
    element_init_Zr(ki, pairing);
    element_init_G1(ai, pairing);
    element_init_G1(bi, pairing);
    element_init_G1(ci, pairing);
}
Member::~Member()
{
    //public
    element_clear(g);
    element_clear(gt);
    element_clear(X);
    element_clear(Y);
    element_clear(h);
    element_clear(y1);
    element_clear(y2);
    element_clear(y3);
    //secret
    element_clear(ki);
    element_clear(ai);
    element_clear(bi);
    element_clear(ci);
    pairing_clear(pairing);
    ki_hex.clear();
}
string Member::Signature(char*mes, int len_mes)
{
    element_t temp_GT;
    element_init_GT(temp_GT, pairing);
    element_t r1,r2;//r r'
    element_t T1,T2,T3,T4;
    element_t T5, T6, T7;
    element_t member_Pi2;
    element_t u;
    element_t H;
    //init
    element_init_GT(member_Pi2, pairing);
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_GT(T1, pairing);
    element_init_GT(T2, pairing);
    element_init_GT(T3, pairing);
    element_init_GT(T4, pairing);
    element_init_G1(T5, pairing);
    element_init_G1(T6, pairing);
    element_init_G1(T7, pairing);
    element_init_Zr(u, pairing);
    element_init_Zr(H, pairing);
    element_t R1;
    element_init_GT(R1, pairing);
    element_t R2;
    element_init_GT(R2, pairing);
    element_t R3;
    element_init_GT(R3, pairing);
    element_t R4;
    element_init_GT(R4, pairing);
    element_t R5;
    element_init_GT(R5, pairing);    
    //set
    element_random(r1);
    element_random(r2);
    element_random(u);
    //compute T5 T6 T7
    element_pow_zn(T5, ai, r2);
    element_pow_zn(T6, bi, r2);
    element_pow_zn(T7, ci, r1);
    element_pow_zn(T7, T7, r2);
    //compute Pi2
    element_pow_zn(member_Pi2,gt,ki);
    //compute T1 T2 T3
    element_pow_zn(T1,gt,u);
    element_pow_zn(T2,h,u);
    element_pow_zn(T3,y1,u);
    element_mul(T3,T3,member_Pi2);
    //compute Hash T1 T2 T3
    Helper::Hash_T1_T2_T3(H,T1,T2,T3);
    //compute T4
    element_pow_zn(temp_GT,y2,u);
    element_pow_zn(T4,y3,H);
    element_pow_zn(T4,T4,u);
    element_mul(T4,T4,temp_GT);
    //set rp rm rv
    element_t rp,rm,rv;
    element_t tmp1,tmp2;
    element_init_Zr(rp, pairing);
    element_init_Zr(rm, pairing);
    element_init_Zr(rv, pairing);
    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    //rand rp rm rv
    element_random(rp);
    element_random(rm);
    element_random(rv);
    //compute R1
    element_pairing(tmp1,g,T7);
    element_pow_zn(tmp1,tmp1,rp);
    element_pairing(tmp2,X,T6);
    element_pow_zn(tmp2,tmp2,rm);
    element_div(R1,tmp1,tmp2);
    //compute R2
    element_pow_zn(R2,gt,rv);
    //compute R3
    element_pow_zn(R3,h,rv);
    //compute R4
    element_pow_zn(tmp1,y1,rv);
    element_pow_zn(tmp2,gt,rm);
    element_mul(R4,tmp1,tmp2);
    //compute R5
    element_pow_zn(tmp2,y3,rv);
    element_pow_zn(tmp2,tmp2,H);
    element_pow_zn(R5,y2,rv);
    element_mul(R5,R5,tmp2);  
    //compute c_H
    element_t c_H;
    element_init_Zr(c_H, pairing);
    Helper::Hash_C(c_H,R1,R2,R3,R4,R5,g,gt,X,Y,h,y1,y2,y3,mes,len_mes);
    element_t Sp;
    element_t Sm;
    element_t Sv;
    element_init_Zr(Sp,pairing);
    element_init_Zr(Sm,pairing);
    element_init_Zr(Sv,pairing);    
    //compute Sp
    element_div(Sp, c_H, r1);
    element_add(Sp, Sp, rp);
    //compute Sm
    element_mul(Sm, c_H, ki);
    element_add(Sm, Sm, rm);
    //compute Sv
    element_mul(Sv, c_H, u);
    element_add(Sv, Sv, rv);
    //Convert signature to hex string
    string sign=SignatureToString(c_H, Sp, Sm, Sv, T1, T2, T3, T4, T5, T6, T7);
    //clear elements
    element_clear(temp_GT);
    element_clear(r1);
    element_clear(r2);
    element_clear(T1);
    element_clear(T2);
    element_clear(T3);
    element_clear(T4);
    element_clear(T5);
    element_clear(T6);
    element_clear(T7);
    element_clear(member_Pi2);
    element_clear(u);
    element_clear(H);
    element_clear(R1);
    element_clear(R2);
    element_clear(R3);
    element_clear(R4);
    element_clear(R5);
    element_clear(rp);
    element_clear(rm);
    element_clear(rv);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(Sp);
    element_clear(Sm);
    element_clear(Sv);
    return sign;
}
string Member::CreateRequest()
{
    element_t ki;
    element_t Pi1;
    element_t R;
    element_t rk;
    element_t Sk;
    element_t c_Hsok;
    //init
    element_init_Zr(ki, pairing);
    element_init_G1(Pi1, pairing);
    element_init_G1(R, pairing);
    element_init_Zr(rk, pairing);
    element_init_Zr(Sk, pairing);
    element_init_Zr(c_Hsok, pairing);
    element_random(ki);
    //compute Pi1
    element_pow_zn(Pi1,g,ki);
    //compute SoK
    element_random(rk);
    element_pow_zn(R,g,rk);
    string hash;
    hash=Hash_g_R(R);
    element_from_hash(c_Hsok,(void*)hash.c_str(),hash.length());
    element_mul(Sk,c_Hsok,ki);
    element_add(Sk,Sk,rk);
    string request;
    request=RequestToString(hash,Sk,Pi1);
    //save ki
    ki_hex=Helper::Element_to_HEX(ki);
    //clear
    element_clear(ki);
    element_clear(Pi1);
    element_clear(R);
    element_clear(rk);
    return request;
}
string Member::Hash_g_R(element_t R)
{
    int len1=element_length_in_bytes(g);
    int len2=len1+element_length_in_bytes(R);
    unsigned char*buf=new unsigned char[len2];
    element_to_bytes(buf,g);
    element_to_bytes(buf+len1,R);
    unsigned char h[20];
    char hex[41];
    sha1::calc(buf,len2,h);
    sha1::toHexString(h,hex);
    string hash(hex);
    delete[]buf;
    return hash;
}
string Member::RequestToString(string hash_string, element_t Sk, element_t Pi1)
{
    string request;
    request=hash_string+"\n";
    request.append(Helper::Element_to_HEX(Sk)+"\n");
    request.append(Helper::Element_to_HEX(Pi1)+"\n");
    return request;
}
string Member::GetKHex()
{
    return ki_hex;
}
void Member::MemberSecretFromString(string member_secret)
{
    Helper::TakeNextElementFromString(member_secret,ki);
    Helper::TakeNextElementFromString(member_secret,ai);
    Helper::TakeNextElementFromString(member_secret,bi);
    Helper::TakeNextElementFromString(member_secret,ci);
}
void Member::SetPublicKey(string PK)
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
void Member::SetSecretKey(string SK)
{
    Helper::TakeNextElementFromString(SK,ki);
    Helper::TakeNextElementFromString(SK,ai);
    Helper::TakeNextElementFromString(SK,bi);
    Helper::TakeNextElementFromString(SK,ci);
}
string Member::SignatureToString(element_t c,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7)
{
    string signature;
    signature.append(Helper::Element_to_HEX(c)+"\n");
    signature.append(Helper::Element_to_HEX(Sp)+"\n");
    signature.append(Helper::Element_to_HEX(Sm)+"\n");
    signature.append(Helper::Element_to_HEX(Sv)+"\n");
    signature.append(Helper::Element_to_HEX(T1)+"\n");
    signature.append(Helper::Element_to_HEX(T2)+"\n");
    signature.append(Helper::Element_to_HEX(T3)+"\n");
    signature.append(Helper::Element_to_HEX(T4)+"\n");
    signature.append(Helper::Element_to_HEX(T5)+"\n");
    signature.append(Helper::Element_to_HEX(T6)+"\n");
    signature.append(Helper::Element_to_HEX(T7)+"\n");
    return signature;
}
string Member::GetSecretKey()
{
    string SK;
    SK.append(Helper::Element_to_HEX(ki)+"\n");
    SK.append(Helper::Element_to_HEX(ai)+"\n");
    SK.append(Helper::Element_to_HEX(bi)+"\n");
    SK.append(Helper::Element_to_HEX(ci)+"\n");
    return SK;
}
string Member::GetPublicKey()
{
    return GroupPublicKeyToString(g, gt, X, Y, h, y1, y2, y3);
}
string Member::GroupPublicKeyToString(element_t g_w,element_t gt_w,element_t X_w,element_t Y_w,element_t h_w,element_t y1_w,element_t y2_w,element_t y3_w)
{
    string gpk;
    gpk.append(Helper::Element_to_HEX(g_w)+"\n");
    gpk.append(Helper::Element_to_HEX(gt_w)+"\n");
    gpk.append(Helper::Element_to_HEX(X_w)+"\n");
    gpk.append(Helper::Element_to_HEX(Y_w)+"\n");
    gpk.append(Helper::Element_to_HEX(h_w)+"\n");
    gpk.append(Helper::Element_to_HEX(y1_w)+"\n");
    gpk.append(Helper::Element_to_HEX(y2_w)+"\n");
    gpk.append(Helper::Element_to_HEX(y3_w)+"\n");
    return gpk;
}