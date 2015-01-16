// Pbkdf2HmacSha1.cpp

#include "StdAfx.h"
#include <iostream>
#include "HmacSha1.h"
#include <stdio.h>

namespace NCrypto {
namespace NSha1 {

void Pbkdf2Hmac(const Byte *pwd, size_t pwdSize, const Byte *salt, size_t saltSize,
    UInt32 numIterations, Byte *key, size_t keySize)
{
  CHmac baseCtx;
  baseCtx.SetKey(pwd, pwdSize);
  for (UInt32 i = 1; keySize > 0; i++)
  {
    CHmac ctx = baseCtx;
    ctx.Update(salt, saltSize);
    Byte u[kDigestSize] = { (Byte)(i >> 24), (Byte)(i >> 16), (Byte)(i >> 8), (Byte)(i) };
    const unsigned int curSize = (keySize < kDigestSize) ? (unsigned int)keySize : kDigestSize;
    ctx.Update(u, 4);
    ctx.Final(u, kDigestSize);

    unsigned int s;
    for (s = 0; s < curSize; s++)
      key[s] = u[s];
    
    for (UInt32 j = numIterations; j > 1; j--)
    {
      ctx = baseCtx;
      ctx.Update(u, kDigestSize);
      ctx.Final(u, kDigestSize);
      for (s = 0; s < curSize; s++)
        key[s] ^= u[s];
    }

    key += curSize;
    keySize -= curSize;
  }
}

void Pbkdf2Hmac32(const Byte *pwd, size_t pwdSize, const UInt32 *salt, size_t saltSize,
    UInt32 numIterations, UInt32 *key, size_t keySize)	  //�������������ֱ� 1000   ����������һ�������buf   һ���Ǵ�С   
{
  CHmac32 baseCtx;

  //update the _buffer of CContextBase2
//  printf("start \n");
  baseCtx.SetKey(pwd, pwdSize);		//��һ�����ڰ�����block��sha�����ˣ��е���׼�����ѣ� ��һ����^0x36363636   һ���ǣ�^0x36363636 ^ 0x5c5c5c5c;Ȼ��������
//  printf("end \n");
  for (UInt32 i = 1; keySize > 0; i++)
  {
    CHmac32 ctx = baseCtx;    //һЩsha1�Ľṹ
	
    ctx.Update(salt, saltSize);			//���ڽ���salt��sha1������

	
    UInt32 u[kDigestSizeInWords] = { i };
    const unsigned int curSize = (keySize < kDigestSizeInWords) ? (unsigned int)keySize : kDigestSizeInWords;	//���ڿ�ѭ���Ž����ٸ�
	//std::cout<<"curSize :"<<curSize<<std::endl;   5.5.5.2
    ctx.Update(u, 1);	//��������ڰ�U�Ž�ȥblock����
    ctx.Final(u, kDigestSizeInWords);		//�����ǽ��д��ģ���㣬��mac�ģ��õ���u����cpu�����uu

    // Speed-optimized code start
    ctx = baseCtx;
    ctx.GetLoopXorDigest(u, numIterations - 1);		//һֱ�����ﶼ���ڻ�ȡux���ѣ�������
    // Speed-optimized code end
    
    unsigned int s;
    for (s = 0; s < curSize; s++)
      key[s] = u[s];				//����ڰ�ux���kbuf���棬������������17*4=68
    
    /*
    // Default code start
    for (UInt32 j = numIterations; j > 1; j--)
    {
      ctx = baseCtx;
      ctx.Update(u, kDigestSizeInWords);
      ctx.Final(u, kDigestSizeInWords);
      for (s = 0; s < curSize; s++)
        key[s] ^= u[s];
    }
    // Default code end
    */

    key += curSize;
    keySize -= curSize;
  }
}

}}
