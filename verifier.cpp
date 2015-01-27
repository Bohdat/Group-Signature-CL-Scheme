#include "verifier.h"
Verifier::Verifier()
{
    pairing_init_set_str(pairing, _PAIRING_PARAM_);
    //init system param
    element_init_G1(g, pairing);
    element_init_GT(gt, pairing);
    element_init_G1(X, pairing);
    element_init_G1(Y, pairing);
    element_init_GT(h, pairing);
    //init y1 y2 y3
    element_init_GT(y1, pairing);
    element_init_GT(y2, pairing);
    element_init_GT(y3, pairing);
}
Verifier::~Verifier()
{    
    element_clear(g);
    element_clear(gt);
    element_clear(X);
    element_clear(Y);
    element_clear(h);
    element_clear(y1);
    element_clear(y2);
    element_clear(y3);
    pairing_clear(pairing);
}
bool Verifier::Verification(string signature, char*mes, int len_mes)
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
    cmp_value_1=element_cmp(check_c_H,c_H);//0==success
    //cmp_value_2
    cmp_value_2=element_cmp(check_1,check_2);//0==success
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
    return cmp_value_1||cmp_value_2;// 0 == succes
}
void Verifier::SetPublicKey(string PK)
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
string Verifier::GetPublicKey()
{
    string gpk;
    gpk.append(Helper::Element_to_HEX(g)+"\n");
    gpk.append(Helper::Element_to_HEX(gt)+"\n");
    gpk.append(Helper::Element_to_HEX(X)+"\n");
    gpk.append(Helper::Element_to_HEX(Y)+"\n");
    gpk.append(Helper::Element_to_HEX(h)+"\n");
    gpk.append(Helper::Element_to_HEX(y1)+"\n");
    gpk.append(Helper::Element_to_HEX(y2)+"\n");
    gpk.append(Helper::Element_to_HEX(y3)+"\n");
    return gpk;
}
void Verifier::SignatureFromString(string signature, element_t c_H,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7)
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