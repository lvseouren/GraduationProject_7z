// DeflateDecoder.cpp

#include "StdAfx.h"
#include <iostream>
#include "DeflateDecoder.h"

namespace NCompress {
namespace NDeflate {
namespace NDecoder {

static const int kLenIdFinished = -1;
static const int kLenIdNeedInit = -2;
//extern class CHmac _hmac;

CCoder::CCoder(bool deflate64Mode, bool deflateNSIS):
    _deflate64Mode(deflate64Mode),
    _deflateNSIS(deflateNSIS),
    _keepHistory(false),
    _needInitInStream(true),
    ZlibMode(false) {}

UInt32 CCoder::ReadBits(int numBits)
{
  return m_InBitStream.ReadBits(numBits);
}

bool CCoder::DeCodeLevelTable(Byte *values, int numSymbols)
{
  int i = 0;
  do
  {
    UInt32 number = m_LevelDecoder.DecodeSymbol(&m_InBitStream);
    if (number < kTableDirectLevels)
      values[i++] = (Byte)number;
    else if (number < kLevelTableSize)
    {
      if (number == kTableLevelRepNumber)
      {
        if (i == 0)
          return false;
        int num = ReadBits(2) + 3;
        for (; num > 0 && i < numSymbols; num--, i++)
          values[i] = values[i - 1];
      }
      else
      {
        int num;
        if (number == kTableLevel0Number)
          num = ReadBits(3) + 3;
        else
          num = ReadBits(7) + 11;
        for (;num > 0 && i < numSymbols; num--)
          values[i++] = 0;
      }
    }
    else
      return false;
  }
  while(i < numSymbols);
  return true;
}

#define RIF(x) { if (!(x)) return false; }

bool CCoder::ReadTables(void)
{
  m_FinalBlock = (ReadBits(kFinalBlockFieldSize) == NFinalBlockField::kFinalBlock);
  UInt32 blockType = ReadBits(kBlockTypeFieldSize);
  if (blockType > NBlockType::kDynamicHuffman)
    return false;

  if (blockType == NBlockType::kStored)
  {
    m_StoredMode = true;
    m_InBitStream.AlignToByte();
    m_StoredBlockSize = ReadBits(kStoredBlockLengthFieldSize);
    if (_deflateNSIS)
      return true;
    return (m_StoredBlockSize == (UInt16)~ReadBits(kStoredBlockLengthFieldSize));
  }

  m_StoredMode = false;

  CLevels levels;
  if (blockType == NBlockType::kFixedHuffman)
  {
    levels.SetFixedLevels();
    _numDistLevels = _deflate64Mode ? kDistTableSize64 : kDistTableSize32;
  }
  else
  {
    int numLitLenLevels = ReadBits(kNumLenCodesFieldSize) + kNumLitLenCodesMin;
    _numDistLevels = ReadBits(kNumDistCodesFieldSize) + kNumDistCodesMin;
    int numLevelCodes = ReadBits(kNumLevelCodesFieldSize) + kNumLevelCodesMin;

    if (!_deflate64Mode)
      if (_numDistLevels > kDistTableSize32)
        return false;
    
    Byte levelLevels[kLevelTableSize];
    for (int i = 0; i < kLevelTableSize; i++)
    {
      int position = kCodeLengthAlphabetOrder[i];
      if(i < numLevelCodes)
        levelLevels[position] = (Byte)ReadBits(kLevelFieldSize);
      else
        levelLevels[position] = 0;
    }
    
    RIF(m_LevelDecoder.SetCodeLengths(levelLevels));
    
    Byte tmpLevels[kFixedMainTableSize + kFixedDistTableSize];
    if (!DeCodeLevelTable(tmpLevels, numLitLenLevels + _numDistLevels))
      return false;

    levels.SubClear();
    memcpy(levels.litLenLevels, tmpLevels, numLitLenLevels);
    memcpy(levels.distLevels, tmpLevels + numLitLenLevels, _numDistLevels);
  }
  RIF(m_MainDecoder.SetCodeLengths(levels.litLenLevels));
  return m_DistDecoder.SetCodeLengths(levels.distLevels);
}

HRESULT CCoder::CodeSpec(UInt32 curSize)
{
	printf("\nIn CCoder::CodeSpec() \n");
  if (_remainLen == kLenIdFinished)
  {
	  //printf("!@#!@#!@#!@#!@#!@#!@#\n");
	  return S_OK;
  }
  if (_remainLen == kLenIdNeedInit)
  {
    if (!_keepHistory)
      if (!m_OutWindowStream.Create(_deflate64Mode ? kHistorySize64: kHistorySize32))
        return E_OUTOFMEMORY;

	//下面是进行AES的地方了！
    RINOK(InitInStream(_needInitInStream));
	
    m_OutWindowStream.Init(_keepHistory);

    m_FinalBlock = false;
    _remainLen = 0;
    _needReadTable = true;
  }

  if (curSize == 0)//NOT
    return S_OK;
  
  printf("_remainLen:%d and curSize:%d\n",_remainLen,curSize);    //0 和  247
 
  while(_remainLen > 0 && curSize > 0)			//从不来这步
  {
	  printf("!@#$%^&*((*&^%$#@\n");
    _remainLen--;
    Byte b = m_OutWindowStream.GetByte(_rep0);
    m_OutWindowStream.PutByte(b);
    curSize--;
  }
 
   
  while(curSize > 0)
  {
	

    if (_needReadTable)				// only one time 
    {
		
      if (m_FinalBlock)
      {
		//printf("in the m_FinalBlock\n");   never here
        _remainLen = kLenIdFinished;
        break;
      }
      if (!ReadTables())
        return S_FALSE;
      _needReadTable = false;
    }

	//printf("in the CodeSpec2\n");
    if(m_StoredMode)//NOT use
    {
      for (; m_StoredBlockSize > 0 && curSize > 0; m_StoredBlockSize--, curSize--)
        m_OutWindowStream.PutByte(m_InBitStream.ReadByte());
      _needReadTable = (m_StoredBlockSize == 0);
      continue;
    }
//	UInt32 number1 = m_MainDecoder.DecodeSymbol(&m_InBitStream);
	//printf("number1:%d\n",number1);
    while(curSize > 0)
    {
	  //printf("in the CodeSpec3\n");
      if (m_InBitStream.NumExtraBytes > 4)
        return S_FALSE;
	  
	  // printf("in the CodeSpec3\n");
      UInt32 number = m_MainDecoder.DecodeSymbol(&m_InBitStream);
	 // if(number>=0x100)  printf("number is :%d",number);
	 // printf("in the CodeSpec3\n");
      if (number < 0x100)
      { 
       // printf("number:%d\n",number);    理解为有个0x100作为间隔符号？
		//  if(number>=0x100)  printf("number is :%d",number);
        m_OutWindowStream.PutByte((Byte)number);
        curSize--;
        continue;
      }
      else if (number == kSymbolEndOfBlock)//到最后一下估计是
      {
		 printf("happen ever\n");   //never in here
        _needReadTable = true;
        break;
      }
      else if (number < kMainTableSize)
      {
		//printf("number:%d\n",number);
		//printf("kMainTableSize:%d\n",kMainTableSize);
		 
        number -= kSymbolMatch;
        UInt32 len;
        {
          int numBits;
          if (_deflate64Mode)
          {
            len = kLenStart64[number];
            numBits = kLenDirectBits64[number];
          }
          else
          {
            len = kLenStart32[number];
            numBits = kLenDirectBits32[number];
          }
          len += kMatchMinLen + m_InBitStream.ReadBits(numBits);
        }
        UInt32 locLen = len;
        if (locLen > curSize)
          locLen = (UInt32)curSize;
        number = m_DistDecoder.DecodeSymbol(&m_InBitStream);
        if (number >= _numDistLevels)
		{
		 // printf("return\n");
          return S_FALSE;//util to this
		}

		//printf("in the CodeSpec4\n");
        UInt32 distance = kDistStart[number] + m_InBitStream.ReadBits(kDistDirectBits[number]);
        if (!m_OutWindowStream.CopyBlock(distance, locLen))
          return S_FALSE;
		
		//printf("in the CodeSpec5\n");
        curSize -= locLen;
        len -= locLen;
        if (len != 0)
        {
          _remainLen = (Int32)len;
          _rep0 = distance;
          break;
        }
      }
      else
	  {
        return S_FALSE;
		//printf("in the CodeSpec6\n");
	  }
    }
  }
  printf("In CCoder::CodeSpec() end \n\n");
  return S_OK;
}

#ifdef _NO_EXCEPTIONS

#define DEFLATE_TRY_BEGIN
#define DEFLATE_TRY_END

#else

#define DEFLATE_TRY_BEGIN try {
#define DEFLATE_TRY_END } \
  catch(const CInBufferException &e)  { return e.ErrorCode; } \
  catch(const CLzOutWindowException &e)  { return e.ErrorCode; } \
  catch(...) { return S_FALSE; }

#endif


HRESULT CCoder::CodeReal(ISequentialOutStream *outStream,
      const UInt64 *outSize, ICompressProgressInfo *progress)
{
	std::cout<<"In the CCoder::CodeReal"<<std::endl;
  DEFLATE_TRY_BEGIN
  m_OutWindowStream.SetStream(outStream);//赋值给COutBuffer成员变量_stream
  CCoderReleaser flusher(this);

  const UInt64 inStart = _needInitInStream ? 0 : m_InBitStream.GetProcessedSize();
  const UInt64 start = m_OutWindowStream.GetProcessedSize();
  std::cout<<"check instart and start:"<<inStart<<" and "<<start<<std::endl;   //都是0
  for (;;)
  {
    UInt32 curSize = 1 << 18;
    if (outSize != 0)
    {
	  //为什么
      const UInt64 rem = *outSize - (m_OutWindowStream.GetProcessedSize() - start);
      if (curSize > rem)
        curSize = (UInt32)rem;
	  //printf("check curSize is %d\n",curSize);    一直都是outsize   没压缩前的大小
    }
    if (curSize == 0)
      break;
	//	printf("check is unchange:%x %x %x %x\n",_hmac._sha._buffer[0],_hmac._sha._buffer[1],_hmac._sha._state[0],_hmac._sha._state[1]);
	//printf("--------------------\nCodeReal 1 \n");
	//printf("curSize:%d\n",curSize);		//没有压缩的文件
	//here

    RINOK(CodeSpec(curSize));//这里进行了很多hmac操作！

	//printf("--------------------\nCodeReal 2 \n");
    if (_remainLen == kLenIdFinished)
      break;
    if (progress != NULL)	//直觉告诉我这个就是验证···不对吧
    {
      const UInt64 inSize = m_InBitStream.GetProcessedSize() - inStart;
      const UInt64 nowPos64 = m_OutWindowStream.GetProcessedSize() - start;
	  std::cout<<"check inSize and nowPos64:"<<inSize<<" and "<<nowPos64<<std::endl;   //压缩的数据 138 and 未压缩的247
      RINOK(progress->SetRatioInfo(&inSize, &nowPos64));
	  
    }
  }
  if (_remainLen == kLenIdFinished && ZlibMode)
  {
    m_InBitStream.AlignToByte();
    for (int i = 0; i < 4; i++)
      ZlibFooter[i] = m_InBitStream.ReadByte();
  }
  flusher.NeedFlush = false;
  HRESULT res = Flush();
  if (res == S_OK && InputEofError())
    return S_FALSE;
  return res;
  DEFLATE_TRY_END
}

HRESULT CCoder::Code(ISequentialInStream *inStream, ISequentialOutStream *outStream,
    const UInt64 * /* inSize */, const UInt64 *outSize, ICompressProgressInfo *progress)
{

  printf("in the code   DeflateDecoder::Code\n");//Yes
  SetInStream(inStream);//将inStream赋给CInBuffer中_instream,没有return语句。
  printf("outsize is %d\n",*outSize);   //没有压缩的大小
  SetOutStreamSize(outSize);	//这里是解压缩之后的大小
  //这里的stream猜测是数据输入流，但是根本搞不清这个sream是怎么使用的

  HRESULT res = CodeReal(outStream, outSize, progress);
  ReleaseInStream();
  return res;
}

STDMETHODIMP CCoder::GetInStreamProcessedSize(UInt64 *value)
{
  if (value == NULL)
    return E_INVALIDARG;
  *value = m_InBitStream.GetProcessedSize();
  return S_OK;
}

STDMETHODIMP CCoder::SetInStream(ISequentialInStream *inStream)
{
  m_InBitStream.SetStream(inStream);
  return S_OK;
}

STDMETHODIMP CCoder::ReleaseInStream()
{
  m_InBitStream.ReleaseStream();
  return S_OK;
}

STDMETHODIMP CCoder::SetOutStreamSize(const UInt64 * /* outSize */)
{
  _remainLen = kLenIdNeedInit;
  _needInitInStream = true;
  m_OutWindowStream.Init(_keepHistory);
  return S_OK;
}

#ifndef NO_READ_FROM_CODER

STDMETHODIMP CCoder::Read(void *data, UInt32 size, UInt32 *processedSize)
{
  DEFLATE_TRY_BEGIN
  if (processedSize)
    *processedSize = 0;
  const UInt64 startPos = m_OutWindowStream.GetProcessedSize();
  m_OutWindowStream.SetMemStream((Byte *)data);
  RINOK(CodeSpec(size));
  if (processedSize)
    *processedSize = (UInt32)(m_OutWindowStream.GetProcessedSize() - startPos);
  return Flush();
  DEFLATE_TRY_END
}

#endif

STDMETHODIMP CCoder::CodeResume(ISequentialOutStream *outStream, const UInt64 *outSize, ICompressProgressInfo *progress)
{
  _remainLen = kLenIdNeedInit;
  m_OutWindowStream.Init(_keepHistory);
  return CodeReal(outStream, outSize, progress);
}

}}}
