#include <iomanip>
#include <sstream>

#include "helper.h"
//HEX convertation
string Helper::Element_to_HEX(element_t elem)
{
    int len;
    unsigned char*buf;
    len=element_length_in_bytes(elem);
    buf=new unsigned char[len];
    element_to_bytes(buf,elem);
    stringstream ss;
    for(int i(0);i<len;++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    delete[]buf;
    return ss.str();
}
void Helper::Element_from_HEX(element_t elem,string elem_hex)
{
    int len;
    unsigned char*buf;
    len=elem_hex.length()/2;
    buf=new unsigned char[len];
    for (std::string::size_type i = 0, i_end = elem_hex.size(); i < i_end; i += 2)
    {
        unsigned byte;
        std::istringstream hex_byte(elem_hex.substr(i, 2));
        hex_byte >> std::hex >> byte;
        buf[i/2] = static_cast<unsigned char>(byte);
    }
    element_from_bytes(elem,buf);
    delete[]buf;
}
// BASE 58 convertation
string Helper::Element_to_BASE_58(element_t elem)
{
    int len=element_length_in_bytes(elem);
    unsigned char* buf=new unsigned char[len];
    element_to_bytes(buf,elem);
    string ret=EncodeBase58(buf, len);
    delete[]buf;
    return ret;
}
void Helper::Element_from_BASE_58(element_t elem,string elem_base58)
{
    int len=elem_base58.length();
    unsigned char* buf=new unsigned char[len];
    DecodeBase58(elem_base58, buf, len);
    element_from_bytes(elem,buf);
    delete[]buf;
}
void Helper::TakeNextElementFromString(string & str,element_t elem)
{
	string tmp;
	size_t pos;
    pos=str.find("\n");
	tmp=str.substr(0,pos);
	str.erase(0,pos+1);
	Element_from_HEX(elem,tmp);
}
void Helper::TakeNextLineFromString(string & str, string & line)
{
	size_t pos;
    pos=str.find("\n");
	line=str.substr(0,pos);
	str.erase(0,pos+1);
}
string Helper::TakeNextItemFromString(string & str)
{
	string ret;
	size_t pos;
    pos=str.find(seporator);
    if(pos!=string::npos)
    {
		ret=str.substr(0,pos);
		str.erase(0,pos+strlen(seporator));
	}
	return ret;
}
void Helper::Hash_T1_T2_T3(element_t res,element_t T1,element_t T2,element_t T3)
{
    int len1=element_length_in_bytes(T1);
    int len2=len1+element_length_in_bytes(T2);
    int len3=len2+element_length_in_bytes(T3);
    unsigned char*buf=new unsigned char[len3];
    element_to_bytes(buf,T1);
    element_to_bytes(buf+len1,T2);
    element_to_bytes(buf+len2,T3);
    unsigned char hash[20];
    sha1::calc(buf,len3,hash);
    element_from_hash(res,(void*)hash,20);
    delete[]buf;
}
void Helper::Hash_C(element_t res,element_t R1,element_t R2,element_t R3,element_t R4, element_t R5,element_t g,element_t gt,element_t X, element_t Y, element_t h,element_t y1, element_t y2, element_t y3, char* mes, int len_mes)
{
    int len1=element_length_in_bytes(R1);
    int len2=len1+element_length_in_bytes(R2);
    int len3=len2+element_length_in_bytes(R3);
    int len4=len3+element_length_in_bytes(R4);
    int len5=len4+element_length_in_bytes(R5);
    int len6=len5+element_length_in_bytes(g);
    int len7=len6+element_length_in_bytes(gt);
    int len8=len7+element_length_in_bytes(X);
    int len9=len8+element_length_in_bytes(Y);
    int len10=len9+element_length_in_bytes(h);
    int len11=len10+element_length_in_bytes(y1);
    int len12=len11+element_length_in_bytes(y2);
    int len13=len12+element_length_in_bytes(y3);
    int len14=len13+len_mes;
    unsigned char*buf=new unsigned char[len14];
    element_to_bytes(buf,R1);
    element_to_bytes(buf+len1,R2);
    element_to_bytes(buf+len2,R3);
    element_to_bytes(buf+len3,R4);
    element_to_bytes(buf+len4,R5);
    element_to_bytes(buf+len5,g);
    element_to_bytes(buf+len6,gt);
    element_to_bytes(buf+len7,X);
    element_to_bytes(buf+len8,Y);
    element_to_bytes(buf+len9,h);
    element_to_bytes(buf+len10,y1);
    element_to_bytes(buf+len11,y2);
    element_to_bytes(buf+len12,y3);
    strcpy((char*)buf+len13,mes);
    unsigned char hash[20];
    sha1::calc(buf,len14,hash);
    element_from_hash(res,(void*)hash,20);
    delete[]buf;
}
string Helper::Hash_g_R(element_t g, element_t R)
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
string Helper::int_to_HEX(int x)
{
	stringstream stream;
	stream << hex << setfill ('0') << setw(sizeof(int)*2) << x;
	return stream.str();
}
int Helper::int_from_HEX(string str)
{
	int x;   
	stringstream stream;
	stream << hex << (char*)str.c_str();
	stream >> x;
	return x;
}