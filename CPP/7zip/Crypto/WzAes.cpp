// Crypto/WzAes.cpp
/*
This code implements Brian Gladman's scheme
specified in password Based File Encryption Utility.

Note: you must include MyAes.cpp to project to initialize AES tables
*/

#include "StdAfx.h"
#include <iostream>
#include "../Common/StreamObjects.h"
#include "../Common/StreamUtils.h"

#include "Pbkdf2HmacSha1.h"
#include "RandGen.h"
#include "WzAes.h"
#include <iostream>

// define it if you don't want to use speed-optimized version of Pbkdf2HmacSha1
// #define _NO_WZAES_OPTIMIZATIONS

namespace NCrypto {
namespace NWzAes {

const unsigned kAesKeySizeMax = 32;

static const UInt32 kNumKeyGenIterations = 1000;

STDMETHODIMP CBaseCoder::CryptoSetPassword(const Byte *data, UInt32 size)
{
//	std::cout<<"here is set password"<<std::endl;    in
  if(size > kPasswordSizeMax)
    return E_INVALIDARG;
  _key.Password.SetCapacity(size);
  memcpy(_key.Password, data, size);
  return S_OK;
}

#ifndef _NO_WZAES_OPTIMIZATIONS

static void BytesToBeUInt32s(const Byte *src, UInt32 *dest, unsigned destSize)
{
  for (unsigned i = 0; i < destSize; i++)
      dest[i] =
          ((UInt32)(src[i * 4 + 0]) << 24) |
          ((UInt32)(src[i * 4 + 1]) << 16) |
          ((UInt32)(src[i * 4 + 2]) <<  8) |
          ((UInt32)(src[i * 4 + 3]));
}

#endif

STDMETHODIMP CBaseCoder::Init()
{
  printf("In WzAes.cpp Init()\n");
  UInt32 keySize = _key.GetKeySize();		//32  ����aes256    32*8=256   
 // printf("keySize is %d\n",keySize);	//32
  UInt32 keysTotalSize = 2 * keySize + kPwdVerifCodeSize;
 // printf("keysTotalSize is %d\n",keysTotalSize);		//32*2+2=66  ����Ǹ�����һ��治֪��
  Byte buf[2 * kAesKeySizeMax + kPwdVerifCodeSize];
  //printf("buf Size is %d\n",2 * kAesKeySizeMax + kPwdVerifCodeSize);	//66
  // for (unsigned ii = 0; ii < 1000; ii++)
  {
    #ifdef _NO_WZAES_OPTIMIZATIONS

    NSha1::Pbkdf2Hmac(
      _key.Password, _key.Password.GetCapacity(),
      _key.Salt, _key.GetSaltSize(),
      kNumKeyGenIterations,
      buf, keysTotalSize);

    #else

    UInt32 buf32[(2 * kAesKeySizeMax + kPwdVerifCodeSize + 3) / 4];		//  (2 * 32 + 2 + 3)/4 = 17
    UInt32 key32SizeTotal = (keysTotalSize + 3) / 4;	//69/4=17

    UInt32 salt[kSaltSizeMax * 4];		//16*4=64		����᲻���е�󰡡�����
    UInt32 saltSizeInWords = _key.GetSaltSize() / 4;    // printf("saltSizeInWords�� %d\n",saltSizeInWords);   =4   16�ֽ�
    BytesToBeUInt32s(_key.Salt, salt, saltSizeInWords);	//��ȡ��saltֵ
	//printf("_key.Password.GetCapacity()�� %d\n",_key.Password.GetCapacity());			���ĳ���

	 printf("start the updateblock on the _buffer\n");
	 //Ҫ��ϸ������ˣ�����,���Ǻ��Լ��������гɹ�һ���Ĳ���
    NSha1::Pbkdf2Hmac32(
      _key.Password, _key.Password.GetCapacity(),
      salt, saltSizeInWords,
      kNumKeyGenIterations,
      buf32, key32SizeTotal);

	 printf("end the updateblock on _buffer\n");

    for (UInt32 j = 0; j < keysTotalSize; j++)		//66=keysTotalSize
      buf[j] = (Byte)(buf32[j / 4] >> (24 - 8 * (j & 3)));		//��ȡ��buf����
    
    #endif
  }
  printf("buf is %x %x %x\n",*(buf + 0),*(buf + 1),*(buf + 2));
  _hmac.SetKey(buf + keySize, keySize); //һ��Ҫ����Щ���ݣ����ǻᵼ�´���    keysize=32    ��ʵ������ȥ��һ��^36363636   ^5c5c5c5c�������ݻ���
    printf("buf is %x %x %x\n",*(buf + 0),*(buf + 1),*(buf + 2));
  //�����2�ֽ���ֵ֤
  memcpy(_key.PwdVerifComputed, buf + 2 * keySize, kPwdVerifCodeSize);
  //printf("keySize is :%d\n",keySize);
  AesCtr2_Init(&_aes);
  Aes_SetKey_Enc(_aes.aes + _aes.offset + 8, buf, keySize);//keysize=32   offset=3  +8 =11   ���ֺ�ctr�պò�4����
  //printf("check is %x %x %x\n",_aes.aes[11],_aes.aes[15],_aes.aes[16]);
  FILE *fp;
  fp=fopen("buf.txt","ab");
  for(int k=0;k<32;k++)
	{
	 fprintf(fp,"%02x",buf[k]);
	}
    fwrite("|",sizeof(char),1,fp);
	for(int k=32;k<64;k++)
	{
		fprintf(fp,"%02x",buf[k]);
    }
    fwrite("*",sizeof(char),1,fp);
  fclose(fp);

  return S_OK;
}

HRESULT CEncoder::WriteHeader(ISequentialOutStream *outStream)
{

	printf("In WzAes.cpp WriteHeader()\n");
  UInt32 saltSize = _key.GetSaltSize();
  g_RandomGenerator.Generate(_key.Salt, saltSize);
  Init();
  RINOK(WriteStream(outStream, _key.Salt, saltSize));
  return WriteStream(outStream, _key.PwdVerifComputed, kPwdVerifCodeSize);
}

HRESULT CEncoder::WriteFooter(ISequentialOutStream *outStream)
{
	printf("In WzAes.cpp WriteFooter()\n");
  Byte mac[kMacSize];
  _hmac.Final(mac, kMacSize);
  return WriteStream(outStream, mac, kMacSize);
}

STDMETHODIMP CDecoder::SetDecoderProperties2(const Byte *data, UInt32 size)
{

  if (size != 1)
    return E_INVALIDARG;
  _key.Init();
  return SetKeyMode(data[0]) ? S_OK : E_INVALIDARG;
}

HRESULT CDecoder::ReadHeader(ISequentialInStream *inStream)
{
  UInt32 saltSize = _key.GetSaltSize();
  UInt32 extraSize = saltSize + kPwdVerifCodeSize;
  Byte temp[kSaltSizeMax + kPwdVerifCodeSize];
  RINOK(ReadStream_FAIL(inStream, temp, extraSize));
  UInt32 i;
  for (i = 0; i < saltSize; i++)
    _key.Salt[i] = temp[i];
  for (i = 0; i < kPwdVerifCodeSize; i++)
    _pwdVerifFromArchive[i] = temp[saltSize + i];
  return S_OK;
}

//self add
void CDecoder::CDecoderPtf()
{
	printf("In WzAes.cpp CDecoderPtf()\n");
	//printf("before_buffer:%d%d%d%d%d%d%d%d%d%d\n",_hmac._sha._buffer[0],_buffer[1],_buffer[2],_buffer[3],_buffer[4],_buffer[5],_buffer[6],_buffer[7],_buffer[8],_buffer[9]);
}
static bool CompareArrays(const Byte *p1, const Byte *p2, UInt32 size)
{
	printf("In WzAes.cpp CompareArrays()\n");
  for (UInt32 i = 0; i < size; i++)
    if (p1[i] != p2[i])
      return false;
  return true;
}

//��֤�����ֽڵ�������ֵ֤
bool CDecoder::CheckPasswordVerifyCode()
{
		printf("in CheckPasswordVerifyCode check is unchange:%x %x %x %x\n",_hmac._sha._buffer[0],_hmac._sha._buffer[1],_hmac._sha._state[0],_hmac._sha._state[1]);
  //self add
  printf("WzAes.cpp: PwdVerifComputed:%x%x \n",_key.PwdVerifComputed[0],_key.PwdVerifComputed[1]);
  printf("WzAes.cpp: PwdVerify:%x%x \n",_pwdVerifFromArchive[0],_pwdVerifFromArchive[1]);
  bool isVerify =CompareArrays(_key.PwdVerifComputed, _pwdVerifFromArchive, kPwdVerifCodeSize);
  if(isVerify)
  {
         printf("the pwd verify value is true\n");
  }
  //end add self
  return CompareArrays(_key.PwdVerifComputed, _pwdVerifFromArchive, kPwdVerifCodeSize);
}

//��֤10Byte�ֶ�
HRESULT CDecoder::CheckMac(ISequentialInStream *inStream, bool &isOK)
{
	printf("In WzAes.cpp CheckMac()\n");
  //printf("check is unchange:%x %x %x %x\n",_hmac._sha._buffer[0],_hmac._sha._buffer[1],_hmac._sha._state[0],_hmac._sha._state[1]);
  
	isOK = false;
  Byte mac1[kMacSize];   //macsize =10
  RINOK(ReadStream_FAIL(inStream, mac1, kMacSize));		//����mac1
  Byte mac2[kMacSize];
  _hmac.Final(mac2, kMacSize);
  //self add
  printf("mac1:%02x%x%x%x%x%x%x%x%x%x\n",mac1[0],mac1[1],mac1[2],mac1[3],mac1[4],mac1[5],mac1[6],mac1[7],mac1[8],mac1[9]);
  if( isOK = CompareArrays(mac1, mac2, kMacSize))
      return S_OK;
  else
	  return S_FALSE;
}

CAesCtr2::CAesCtr2()
{
		printf("In WzAes.cpp CAesCtr2()\n");
  offset = ((0 - (unsigned)(ptrdiff_t)aes) & 0xF) / sizeof(UInt32);
  std::cout<<"CAesCtr2() check offset: "<<offset<<std::endl;		//���offset=3
  memset(aes,0,75);
}

void AesCtr2_Init(CAesCtr2 *p)  // CAesCtr2 
{
	printf("In WzAes.cpp AesCtr2_Init()\n");
  UInt32 *ctr = p->aes + p->offset + 4;  //֤���ӵ�7����λ��ʼ�� һЩ�Ƚ�������Ķ���,��Ϊ����aes ctr���������ctr��������
  memset(p->aes,0,75);
  printf("original �� aes->offset:%d  p->aes:%d\n",p->offset,*(p->aes + p->offset + 4));
  unsigned i;
  for (i = 0; i < 4; i++)
    ctr[i] = 0;    //��ǰ4��������Ϊ0      ctr��Ҫ 4Bytes nounce+8Bytes iv+4Bytes counter
  p->pos = AES_BLOCK_SIZE;		//��AES��block����16��С��
}

void AesCtr2_Code(CAesCtr2 *p, Byte *data, SizeT size)
{
	printf("In WzAes.cpp AesCtr2_Code()\n");
	//	printf("size is :%d\n",size); //��ѹ�����ݵ�����
  unsigned pos = p->pos;		//16���������block�Ĵ�С����Ϊ
  UInt32 *buf32 = p->aes + p->offset;	//ƫ��3������
  printf("pos is :%d   offset is :%d\n",p->pos,p->offset);
  printf("In WzAes data[0~3] is %x %x %x %x\n",*data,*(data+1),*(data+2),*(data+3));
  if (size == 0)
    return;
  if (pos != AES_BLOCK_SIZE)
  {
	 // printf("ever happen \n");  never here
    const Byte *buf = (const Byte *)buf32;
    do{
      *data++ ^= buf[pos++];
	//printf("ajdhjkahdjkahjdhajkdhasdk!\n");   never
	}while (--size != 0 && pos != AES_BLOCK_SIZE);		
	// for(int cot=0;cot<=20;cot++) printf("%x ",buf[cot]);
  }
  printf("roundkey= buf32[12~] is  %x %x %x %x %x %x %x %x\n",*(buf32+12),*(buf32+13),*(buf32+14),*(buf32+15),*(buf32+16),*(buf32+17),*(buf32+18),*(buf32+19));
 
 
  if (size >= 16)
  {
    SizeT size2 = size >> 4;
	//printf("data[0~7] is  %x %x %x %x %x %x %x %x \n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));	
   /// printf("data[121~127]  %x %x %x %x %x %x %x  \n",*(data+121),*(data+122),*(data+123),*(data+124),*(data+125),*(data+126),*(data+127));
//	printf("data[128~134] is  %x %x %x %x %x %x %x  \n",*(data+128),*(data+129),*(data+130),*(data+131),*(data+132),*(data+133),*(data+134));
	g_AesCtr_Code(buf32 + 4, data, size2);	//����ȥ�Ĳ������ƶ���3+4=7���ֽڵ�   ,�һ����������counter
//	printf("buf32[0~7](aes+3) is  %x %x %x %x %x %x %x %x \n",*buf32,*(buf32+1),*(buf32+2),*(buf32+3),*(buf32+4),*(buf32+5),*(buf32+6),*(buf32+7));	//change�������˼������㣬������buf���Ƕ���
 //   printf("data[0~7] is  %x %x %x %x %x %x %x %x \n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));	
//	printf("data[121~127]  %x %x %x %x %x %x %x  \n",*(data+121),*(data+122),*(data+123),*(data+124),*(data+125),*(data+126),*(data+127));
//	printf("data[128~134]  %x %x %x %x %x %x %x  \n",*(data+128),*(data+129),*(data+130),*(data+131),*(data+132),*(data+133),*(data+134));
	size2 <<= 4;
    data += size2;
    size -= size2;
    pos = AES_BLOCK_SIZE;
  }
  if (size != 0)
  {
    unsigned j;
    const Byte *buf;
	//printf("????buf32 is  %x %x %x %x \n",buf32[0],buf32[1],buf32[2],buf32[3]);
    for (j = 0; j < 4; j++)
      buf32[j] = 0;//������0
    g_AesCtr_Code(buf32 + 4, (Byte *)buf32, 1);//����ȥ�Ĳ�����aes�����ƶ���7���ֵģ����ܾ���ǰ��4����IV
   //	printf("2222data is  %x %x %x %x %x %x %x %x \n",*(data),*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));	
	//printf("buf32[0~3](aes��3~6��) is  %x %x %x %x %x\n",buf32[0],buf32[1],buf32[2],buf32[3],buf32[12]);
	//printf("data[121~127]  %x %x %x %x %x %x %x  \n",*(data-7),*(data-6),*(data-5),*(data-4),*(data-3),*(data-2),*(data-1));
	
	buf = (const Byte *)buf32;
    pos = 0;
	//���Ҫ��ȥwhile�ˣ�������
    do
	{
      *data++ ^= buf[pos++];
    //printf("do it\n");
	}while (--size != 0 && pos != AES_BLOCK_SIZE);
	//printf("data[128~134]  %x %x %x %x %x %x %x  \n",*(data-10),*(data-9),*(data-8),*(data-7),*(data-6),*(data-2),*(data-1));
  }
  
  p->pos = pos;
}

STDMETHODIMP_(UInt32) CEncoder::Filter(Byte *data, UInt32 size)
{
	printf("In WzAes.cpp CEncoder::Filter()\n");
  AesCtr2_Code(&_aes, data, size);
  _hmac.Update(data, size);
  return size;
}

STDMETHODIMP_(UInt32) CDecoder::Filter(Byte *data, UInt32 size)
{
	//printf("In WzAes.cpp CDecoder::Filter()\n");
	printf("In CDecoder::Filter() data is %x %x %x %x %x %x and size is %d\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),size);
  _hmac.Update(data, size);
  //same   printf("Again In CDecoder::Filter() data is %x %x %x %x %x %x and size is %d\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),size);
  AesCtr2_Code(&_aes, data, size);
  return size;
}

}}
