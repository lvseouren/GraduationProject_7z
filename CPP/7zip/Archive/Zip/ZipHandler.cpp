// ZipHandler.cpp

#include "StdAfx.h"
#include <iostream>
#include "Common/ComTry.h"
#include "Common/IntToString.h"

#include "Windows/PropVariant.h"
#include "Windows/Time.h"

#include "../../IPassword.h"

#include "../../Common/FilterCoder.h"
#include "../../Common/ProgressUtils.h"
#include "../../Common/StreamObjects.h"
#include "../../Common/StreamUtils.h"

#include "../../Compress/CopyCoder.h"
#include "../../Compress/LzmaDecoder.h"
#include "../../Compress/ImplodeDecoder.h"
#include "../../Compress/PpmdZip.h"
#include "../../Compress/ShrinkDecoder.h"

#include "../../Crypto/WzAes.h"
#include "../../Crypto/ZipCrypto.h"
#include "../../Crypto/ZipStrong.h"

#include "../Common/ItemNameUtils.h"
#include "../Common/OutStreamWithCRC.h"

#include "ZipHandler.h"
#include <iostream>
using namespace std;

using namespace NWindows;

namespace NArchive {
namespace NZip {

static const CMethodId kMethodId_ZipBase = 0x040100;
static const CMethodId kMethodId_BZip2 = 0x040202;

static const char *kHostOS[] =
{
  "FAT",
  "AMIGA",
  "VMS",
  "Unix",
  "VM/CMS",
  "Atari",
  "HPFS",
  "Macintosh",
  "Z-System",
  "CP/M",
  "TOPS-20",
  "NTFS",
  "SMS/QDOS",
  "Acorn",
  "VFAT",
  "MVS",
  "BeOS",
  "Tandem",
  "OS/400",
  "OS/X"
};

static const char *kUnknownOS = "Unknown";

static const char *kMethods[] =
{
  "Store",
  "Shrink",
  "Reduced1",
  "Reduced2",
  "Reduced3",
  "Reduced4",
  "Implode",
  "Tokenizing",
  "Deflate",
  "Deflate64",
  "PKImploding"
};

static const char *kBZip2Method = "BZip2";
static const char *kLZMAMethod = "LZMA";
static const char *kJpegMethod = "Jpeg";
static const char *kWavPackMethod = "WavPack";
static const char *kPPMdMethod = "PPMd";
static const char *kAESMethod = "AES";
static const char *kZipCryptoMethod = "ZipCrypto";
static const char *kStrongCryptoMethod = "StrongCrypto";

static struct CStrongCryptoPair
{
  UInt16 Id;
  const char *Name;
} g_StrongCryptoPairs[] =
{
  { NStrongCryptoFlags::kDES, "DES" },
  { NStrongCryptoFlags::kRC2old, "RC2a" },
  { NStrongCryptoFlags::k3DES168, "3DES-168" },
  { NStrongCryptoFlags::k3DES112, "3DES-112" },
  { NStrongCryptoFlags::kAES128, "pkAES-128" },
  { NStrongCryptoFlags::kAES192, "pkAES-192" },
  { NStrongCryptoFlags::kAES256, "pkAES-256" },
  { NStrongCryptoFlags::kRC2, "RC2" },
  { NStrongCryptoFlags::kBlowfish, "Blowfish" },
  { NStrongCryptoFlags::kTwofish, "Twofish" },
  { NStrongCryptoFlags::kRC4, "RC4" }
};

static const STATPROPSTG kProps[] =
{
  { NULL, kpidPath, VT_BSTR},
  { NULL, kpidIsDir, VT_BOOL},
  { NULL, kpidSize, VT_UI8},
  { NULL, kpidPackSize, VT_UI8},
  { NULL, kpidMTime, VT_FILETIME},
  { NULL, kpidCTime, VT_FILETIME},
  { NULL, kpidATime, VT_FILETIME},
  { NULL, kpidAttrib, VT_UI4},
  // { NULL, kpidPosixAttrib, VT_UI4},
  { NULL, kpidEncrypted, VT_BOOL},
  { NULL, kpidComment, VT_BSTR},
  { NULL, kpidCRC, VT_UI4},
  { NULL, kpidMethod, VT_BSTR},
  { NULL, kpidHostOS, VT_BSTR},
  { NULL, kpidUnpackVer, VT_UI4}
};

static const STATPROPSTG kArcProps[] =
{
  { NULL, kpidBit64, VT_BOOL},
  { NULL, kpidComment, VT_BSTR},
  { NULL, kpidPhySize, VT_UI8},
  { NULL, kpidOffset, VT_UI8}
};

CHandler::CHandler()
{
  InitMethodProps();
}

static AString BytesToString(const CByteBuffer &data)
{
  AString s;
  int size = (int)data.GetCapacity();
  if (size > 0)
  {
    char *p = s.GetBuffer(size + 1);
    memcpy(p, (const Byte *)data, size);
    p[size] = '\0';
    s.ReleaseBuffer();
  }
  return s;
}

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

STDMETHODIMP CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value)
{
  std::cout<<"in zip handler"<<std::endl;
  COM_TRY_BEGIN
  NWindows::NCOM::CPropVariant prop;
  switch(propID)
  {
    case kpidBit64:  if (m_Archive.IsZip64) prop = m_Archive.IsZip64; break;
    case kpidComment:  prop = MultiByteToUnicodeString(BytesToString(m_Archive.ArcInfo.Comment), CP_ACP); break;
    case kpidPhySize:  prop = m_Archive.ArcInfo.GetPhySize(); break;
    case kpidOffset:  if (m_Archive.ArcInfo.StartPosition != 0) prop = m_Archive.ArcInfo.StartPosition; break;
    case kpidError: if (!m_Archive.IsOkHeaders) prop = "Incorrect headers"; break;
  }
  prop.Detach(value);
  COM_TRY_END
  return S_OK;
}

STDMETHODIMP CHandler::GetNumberOfItems(UInt32 *numItems)
{
  *numItems = m_Items.Size();
  return S_OK;
}

STDMETHODIMP CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value)
{
  COM_TRY_BEGIN
  NWindows::NCOM::CPropVariant prop;
  const CItemEx &item = m_Items[index];
  switch(propID)
  {
    case kpidPath:  prop = NItemName::GetOSName2(item.GetUnicodeString(item.Name)); break;
    case kpidIsDir:  prop = item.IsDir(); break;
    case kpidSize:  prop = item.UnPackSize; break;
    case kpidPackSize:  prop = item.PackSize; break;
    case kpidTimeType:
    {
      FILETIME ft;
      UInt32 unixTime;
      if (item.CentralExtra.GetNtfsTime(NFileHeader::NNtfsExtra::kMTime, ft))
        prop = (UInt32)NFileTimeType::kWindows;
      else if (item.CentralExtra.GetUnixTime(true, NFileHeader::NUnixTime::kMTime, unixTime))
        prop = (UInt32)NFileTimeType::kUnix;
      else
        prop = (UInt32)NFileTimeType::kDOS;
      break;
    }
    case kpidCTime:
    {
      FILETIME ft;
      if (item.CentralExtra.GetNtfsTime(NFileHeader::NNtfsExtra::kCTime, ft))
        prop = ft;
      break;
    }
    case kpidATime:
    {
      FILETIME ft;
      if (item.CentralExtra.GetNtfsTime(NFileHeader::NNtfsExtra::kATime, ft))
        prop = ft;
      break;
    }
    case kpidMTime:
    {
      FILETIME utc;
      if (!item.CentralExtra.GetNtfsTime(NFileHeader::NNtfsExtra::kMTime, utc))
      {
        UInt32 unixTime;
        if (item.CentralExtra.GetUnixTime(true, NFileHeader::NUnixTime::kMTime, unixTime))
          NTime::UnixTimeToFileTime(unixTime, utc);
        else
        {
          FILETIME localFileTime;
          if (!NTime::DosTimeToFileTime(item.Time, localFileTime) ||
              !LocalFileTimeToFileTime(&localFileTime, &utc))
            utc.dwHighDateTime = utc.dwLowDateTime = 0;
        }
      }
      prop = utc;
      break;
    }
    case kpidAttrib:  prop = item.GetWinAttrib(); break;
    case kpidPosixAttrib:
    {
      UInt32 attrib;
      if (item.GetPosixAttrib(attrib))
        prop = attrib;
      break;
    }
    case kpidEncrypted:  prop = item.IsEncrypted(); break;
    case kpidComment:  prop = item.GetUnicodeString(BytesToString(item.Comment)); break;
    case kpidCRC:  if (item.IsThereCrc()) prop = item.FileCRC; break;
    case kpidMethod:
    {
      UInt16 methodId = item.CompressionMethod;
      AString method;
      if (item.IsEncrypted())
      {
        if (methodId == NFileHeader::NCompressionMethod::kWzAES)
        {
          method = kAESMethod;
          CWzAesExtraField aesField;
          if (item.CentralExtra.GetWzAesField(aesField))
          {
            method += '-';
            char s[32];
            ConvertUInt64ToString((aesField.Strength + 1) * 64 , s);
            method += s;
            method += ' ';
            methodId = aesField.Method;
          }
        }
        else
        {
          if (item.IsStrongEncrypted())
          {
            CStrongCryptoField f;
            bool finded = false;
            if (item.CentralExtra.GetStrongCryptoField(f))
            {
              for (int i = 0; i < sizeof(g_StrongCryptoPairs) / sizeof(g_StrongCryptoPairs[0]); i++)
              {
                const CStrongCryptoPair &pair = g_StrongCryptoPairs[i];
                if (f.AlgId == pair.Id)
                {
                  method += pair.Name;
                  finded = true;
                  break;
                }
              }
            }
            if (!finded)
              method += kStrongCryptoMethod;
          }
          else
            method += kZipCryptoMethod;
          method += ' ';
        }
      }
      if (methodId < sizeof(kMethods) / sizeof(kMethods[0]))
        method += kMethods[methodId];
      else switch (methodId)
      {
        case NFileHeader::NCompressionMethod::kLZMA:
          method += kLZMAMethod;
          if (item.IsLzmaEOS())
            method += ":EOS";
          break;
        case NFileHeader::NCompressionMethod::kBZip2: method += kBZip2Method; break;
        case NFileHeader::NCompressionMethod::kJpeg: method += kJpegMethod; break;
        case NFileHeader::NCompressionMethod::kWavPack: method += kWavPackMethod; break;
        case NFileHeader::NCompressionMethod::kPPMd: method += kPPMdMethod; break;
        default:
        {
          char s[32];
          ConvertUInt64ToString(methodId, s);
          method += s;
        }
      }
      prop = method;
      break;
    }
    case kpidHostOS:
      prop = (item.MadeByVersion.HostOS < sizeof(kHostOS) / sizeof(kHostOS[0])) ?
        (kHostOS[item.MadeByVersion.HostOS]) : kUnknownOS;
      break;
    case kpidUnpackVer:
      prop = (UInt32)item.ExtractVersion.Version;
      break;
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

class CProgressImp: public CProgressVirt
{
  CMyComPtr<IArchiveOpenCallback> _callback;
public:
  STDMETHOD(SetTotal)(UInt64 numFiles);
  STDMETHOD(SetCompleted)(UInt64 numFiles);
  CProgressImp(IArchiveOpenCallback *callback): _callback(callback) {}
};

STDMETHODIMP CProgressImp::SetTotal(UInt64 numFiles)
{
  if (_callback)
    return _callback->SetTotal(&numFiles, NULL);
  return S_OK;
}

STDMETHODIMP CProgressImp::SetCompleted(UInt64 numFiles)
{
  if (_callback)
    return _callback->SetCompleted(&numFiles, NULL);
  return S_OK;
}

STDMETHODIMP CHandler::Open(IInStream *inStream,
    const UInt64 *maxCheckStartPosition, IArchiveOpenCallback *callback)
{
  COM_TRY_BEGIN
  try
  {
    Close();
    RINOK(inStream->Seek(0, STREAM_SEEK_SET, NULL));
    RINOK(m_Archive.Open(inStream, maxCheckStartPosition));
    CProgressImp progressImp(callback);
    return m_Archive.ReadHeaders(m_Items, &progressImp);
  }
  catch(const CInArchiveException &) { Close(); return S_FALSE; }
  catch(...) { Close(); throw; }
  COM_TRY_END
}

STDMETHODIMP CHandler::Close()
{
  m_Items.Clear();
  m_Archive.Close();
  return S_OK;
}

//////////////////////////////////////
// CHandler::DecompressItems

class CLzmaDecoder:
  public ICompressCoder,
  public CMyUnknownImp
{
  NCompress::NLzma::CDecoder *DecoderSpec;
  CMyComPtr<ICompressCoder> Decoder;
public:
  CLzmaDecoder();
  STDMETHOD(Code)(ISequentialInStream *inStream, ISequentialOutStream *outStream,
      const UInt64 *inSize, const UInt64 *outSize, ICompressProgressInfo *progress);

  MY_UNKNOWN_IMP
};

CLzmaDecoder::CLzmaDecoder()
{
  DecoderSpec = new NCompress::NLzma::CDecoder;
  Decoder = DecoderSpec;
}

HRESULT CLzmaDecoder::Code(ISequentialInStream *inStream, ISequentialOutStream *outStream,
    const UInt64 * /* inSize */, const UInt64 *outSize, ICompressProgressInfo *progress)
{
  printf("in the Code CLzmaDecoder:");//Not use
  Byte buf[9];
  RINOK(ReadStream_FALSE(inStream, buf, 9));
  if (buf[2] != 5 || buf[3] != 0)
    return E_NOTIMPL;
  RINOK(DecoderSpec->SetDecoderProperties2(buf + 4, 5));
  return Decoder->Code(inStream, outStream, NULL, outSize, progress);
}

struct CMethodItem
{
  UInt16 ZipMethod;
  CMyComPtr<ICompressCoder> Coder;
};

class CZipDecoder
{
  NCrypto::NZip::CDecoder *_zipCryptoDecoderSpec;
  NCrypto::NZipStrong::CDecoder *_pkAesDecoderSpec;
  NCrypto::NWzAes::CDecoder *_wzAesDecoderSpec;

  CMyComPtr<ICompressFilter> _zipCryptoDecoder;
  CMyComPtr<ICompressFilter> _pkAesDecoder;
  CMyComPtr<ICompressFilter> _wzAesDecoder;

  CFilterCoder *filterStreamSpec;
  CMyComPtr<ISequentialInStream> filterStream;
  CMyComPtr<ICryptoGetTextPassword> getTextPassword;
  CObjectVector<CMethodItem> methodItems;

public:
  CZipDecoder():
      _zipCryptoDecoderSpec(0),
      _pkAesDecoderSpec(0),
      _wzAesDecoderSpec(0),
      filterStreamSpec(0) {}

  HRESULT Decode(
    DECL_EXTERNAL_CODECS_LOC_VARS
    CInArchive &archive, const CItemEx &item,
    ISequentialOutStream *realOutStream,
    IArchiveExtractCallback *extractCallback,
    ICompressProgressInfo *compressProgress,
    #ifndef _7ZIP_ST
    UInt32 numThreads,
    #endif
    Int32 &res);
};


//解码函数
HRESULT CZipDecoder::Decode(
    DECL_EXTERNAL_CODECS_LOC_VARS
    CInArchive &archive,
	const CItemEx &item,
    ISequentialOutStream *realOutStream,
    IArchiveExtractCallback *extractCallback,
    ICompressProgressInfo *compressProgress,
    #ifndef _7ZIP_ST
    UInt32 numThreads,
    #endif
    Int32 &res)
{
  printf("\nthe start Decode()\n\n");
  #ifndef _7ZIP_ST
  //线程数等于压缩包中需要解压的文件数
  //printf("threads num:%d\n",numThreads);
  #endif
  res = NExtract::NOperationResult::kDataError;
  CInStreamReleaser inStreamReleaser;

  bool needCRC = true;
  bool wzAesMode = false;
  bool pkAesMode = false;
  UInt16 methodId = item.CompressionMethod;
  std::cout<<"methodId is: "<<methodId<<std::endl;		//压缩文件的方式
  if (item.IsEncrypted())
  {
	//printf("beforeStrongEncrypted\n");//use
    if (item.IsStrongEncrypted())   //强加密目测是和pkzip相关的
    {
	  printf("isStrongEncrypted\n");//not use
      CStrongCryptoField f;
      if (item.CentralExtra.GetStrongCryptoField(f))
      {
		printf("isPKzip\n");
        pkAesMode = true;
      }
      if (!pkAesMode)
      {
        res = NExtract::NOperationResult::kUnSupportedMethod;
        return S_OK;
      }
    }
    if (methodId == NFileHeader::NCompressionMethod::kWzAES)
    {
	  //printf("CompressMethod:kWzAES\n");//use
      CWzAesExtraField aesField;
      if (item.CentralExtra.GetWzAesField(aesField))
      {
		//printf("wzAesMode = true\n");//use
        wzAesMode = true;
        needCRC = aesField.NeedCrc();
		//std::cout<<"bool is :"<<needCRC<<std::endl;    bool=0   否
      }
    }
  }

  //  
  COutStreamWithCRC *outStreamSpec = new COutStreamWithCRC;
  CMyComPtr<ISequentialOutStream> outStream = outStreamSpec;
  outStreamSpec->SetStream(realOutStream);		//这个realstream暂时当做是输出的文件口咯，毕竟只重写了write函数
  outStreamSpec->Init(needCRC);
  
  UInt64 authenticationPos;
  
  CMyComPtr<ISequentialInStream> inStream;   //这货可能就是文件输入流~
  {
    UInt64 packSize = item.PackSize;
    if (wzAesMode)//use
    {
      if (packSize < NCrypto::NWzAes::kMacSize)
	  {
		std::cout<<"if packSize<10 happened"<<std::endl;     
        return S_OK;
	  }
	 // std::cout<<"packSize before: "<<packSize<<std::endl;		166  = 16salt 2check + 138compressed +10verify
      packSize -= NCrypto::NWzAes::kMacSize;	//怀疑就是找到某些位置了--最后十字节，偏移了10字节
	  //std::cout<<"packSize after: "<<packSize<<std::endl;			//packsize 和 compress size（压缩后的数据大小）不一样：差了18,就是16salt+2byte校验  
    }
	//为了找到校验时候的位置
    UInt64 dataPos = item.GetDataPosition();
	//std::cout<<"dataPos : "<<dataPos<<std::endl;			第一个文件是53（这里是包含了头部salt才53的）    第二个：276=53+上一个的insize=166(为compresssize+18)+57(head)    第三个：583      实质头部应该是 53  57  51
    inStream.Attach(archive.CreateLimitedStream(dataPos, packSize));		//这句应该是跳转了，在流当中
    authenticationPos = dataPos + packSize;			//定位到最后10字节，验证    53+156（16+2+138）=209
	std::cout<<"authenticationPos : "<<authenticationPos<<std::endl;			//这里的packSize被 -10，因为留下最后10字节的验证信息
  }
  
  //Encryption is applied only to the content of files. It is performed after compression, and not to any other associated data. 
  CMyComPtr<ICompressFilter> cryptoFilter;
  if (item.IsEncrypted())
  {
    if (wzAesMode)
    {
      CWzAesExtraField aesField;	//这里包含了AES头部的信息
      if (!item.CentralExtra.GetWzAesField(aesField)) //这里就是一些指针定位和提取头部验证
        return S_OK;
      methodId = aesField.Method;
	  printf("\nmethodId:%d\n",methodId);//methodId:8,是压缩算法Deflate
      if (!_wzAesDecoder)
      {
		//self add
		  printf("\nnew CDecoder object\n");//OK，生成专门解winzip的对象
        _wzAesDecoderSpec = new NCrypto::NWzAes::CDecoder;
        _wzAesDecoder = _wzAesDecoderSpec;
      }
      cryptoFilter = _wzAesDecoder;			//后面会被用到，其实就是生成一个类来进行解密吧，这个wzAesDecoder已经初始化很多数据了
      Byte properties = aesField.Strength;
	  //self add
	  //printf("properties:%d\n",properties);
	  //设置AES秘钥的属性，此处为3，aes256
      RINOK(_wzAesDecoderSpec->SetDecoderProperties2(&properties, 1));
    }

	///////////////////////////////////////////////////////////////////////Not use
    else if (pkAesMode)
    {
      if (!_pkAesDecoder)
      {
        _pkAesDecoderSpec = new NCrypto::NZipStrong::CDecoder;
        _pkAesDecoder = _pkAesDecoderSpec;
      }
      cryptoFilter = _pkAesDecoder;
    }
    else
    {
      if (!_zipCryptoDecoder)
      {
        _zipCryptoDecoderSpec = new NCrypto::NZip::CDecoder;
        _zipCryptoDecoder = _zipCryptoDecoderSpec;
      }
      cryptoFilter = _zipCryptoDecoder;
    }
	//////////////////////////////////密码处理段落///////////////////////////////////////

	//printf("111\n");
    CMyComPtr<ICryptoSetPassword> cryptoSetPassword;	//应该用于存储密码
    RINOK(cryptoFilter.QueryInterface(IID_ICryptoSetPassword, &cryptoSetPassword));
    
    if (!getTextPassword)
      extractCallback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&getTextPassword);

    //printf("222\n");
    if (getTextPassword)
    {
      CMyComBSTR password;

	  //获取命令行输入的密码明文
      RINOK(getTextPassword->CryptoGetTextPassword(&password));

      AString charPassword;
	  //*password.m_str表示用户输入的第一个密码明文字符
	  //cout<<"password:"<<*password.m_str<<endl;
      if (wzAesMode || pkAesMode)//Yes----目测是wzAesMode
      {
        charPassword = UnicodeStringToMultiByte((const wchar_t *)password, CP_ACP);
		cout<<"charPassword:"<<charPassword<<endl;
        /*
        for (int i = 0;; i++)
        {
          wchar_t c = password[i];
          if (c == 0)
            break;
          if (c >= 0x80)
          {
            res = NExtract::NOperationResult::kDataError;
            return S_OK;
          }
          charPassword += (char)c;
        }
        */
      }
      else//Not use
      {
        // we use OEM. WinZip/Windows probably use ANSI for some files
        charPassword = UnicodeStringToMultiByte((const wchar_t *)password, CP_OEMCP);
      }
	  //printf("333\n");
	  //处理密码,放到一个脚_key的结构体当中
      HRESULT result = cryptoSetPassword->CryptoSetPassword(
        (const Byte *)(const char *)charPassword, charPassword.Length());

	 // printf("getTextPasswod：%s\n",charPassword);//明文没有变
      if (result != S_OK)
        return S_OK;
    }
    else//Not use
    {
      RINOK(cryptoSetPassword->CryptoSetPassword(0, 0));
    }
  }
  cout<<"check methodItems:"<< methodItems.Size()<<endl;//  0   1   1  ???为什么，目测是为了循环利用一些类


  int m;
  for (m = 0; m < methodItems.Size(); m++)
    if (methodItems[m].ZipMethod == methodId)
      break;

  if (m == methodItems.Size())		//这个只会进行一次，无论后面有几个文件
  {
    CMethodItem mi;
    mi.ZipMethod = methodId;
    if (methodId == NFileHeader::NCompressionMethod::kStored)
	{
      mi.Coder = new NCompress::CCopyCoder;
	  printf("Compress Method:kStored\n");
	}
    else if (methodId == NFileHeader::NCompressionMethod::kShrunk)
	{
		 printf("Compress Method:kShrunk\n");
		 mi.Coder = new NCompress::NShrink::CDecoder;
    }
      
    else if (methodId == NFileHeader::NCompressionMethod::kImploded)
	{
       mi.Coder = new NCompress::NImplode::NDecoder::CCoder;
	   printf("Compress Method:kImploded\n");
	}
    else if (methodId == NFileHeader::NCompressionMethod::kLZMA)
	{
	  printf("Compress Method:kLZMA\n");
      mi.Coder = new CLzmaDecoder;
	}
    else if (methodId == NFileHeader::NCompressionMethod::kPPMd)
	{
      mi.Coder = new NCompress::NPpmdZip::CDecoder(true);
      printf("Compress Method:kPPMd\n");
	}
    else
    {
		
	  printf("Compress Method:NO\n");//OK
      CMethodId szMethodID;
	  
      if (methodId == NFileHeader::NCompressionMethod::kBZip2)//NOT
	  {
        szMethodID = kMethodId_BZip2;
		printf("szMethodID:%d\n",szMethodID);
	  }
      else
      {
        if (methodId > 0xFF)//NOT
        {
          res = NExtract::NOperationResult::kUnSupportedMethod;
          return S_OK;
        }
        szMethodID = kMethodId_ZipBase + (Byte)methodId;
		//printf("szMethodID:%d\n",szMethodID);//OK:262408
      }

      RINOK(CreateCoder(EXTERNAL_CODECS_LOC_VARS szMethodID, mi.Coder, false));

      if (mi.Coder == 0)//NOT
      {
        res = NExtract::NOperationResult::kUnSupportedMethod;
        return S_OK;
      }
    }
    m = methodItems.Add(mi);
	//self add
	printf("m:%d\n",m);//m:0
  }
  ///////////////上面这一片都是一次性的初始化工作，没有什么太大的关系




  //methodItems是容器类对象，存放结构体CMethodItem结构体
  //Coder是结构体CMyComPtr<ICompressCoder>指针类型成员
  //这里是为了设置aes256用的
  ICompressCoder *coder = methodItems[m].Coder;  //这个指针是个不容易理解的东西
  {
    CMyComPtr<ICompressSetDecoderProperties2> setDecoderProperties;
    coder->QueryInterface(IID_ICompressSetDecoderProperties2, (void **)&setDecoderProperties);
    if (setDecoderProperties)
    {
      Byte properties = (Byte)item.Flags;
      RINOK(setDecoderProperties->SetDecoderProperties2(&properties, 1));   //用于初始化
    }
  }
  
  #ifndef _7ZIP_ST//Use
  {
    CMyComPtr<ICompressSetCoderMt> setCoderMt;
    coder->QueryInterface(IID_ICompressSetCoderMt, (void **)&setCoderMt);
    if (setCoderMt)
    {
      RINOK(setCoderMt->SetNumberOfThreads(numThreads));
    }
  }
  #endif
  
  {
    HRESULT result = S_OK;
    CMyComPtr<ISequentialInStream> inStreamNew;
	
	//已经加密
    if (item.IsEncrypted())
    {
      if (!filterStream)
      {
		//  printf("hahahahahahaha\n");
        filterStreamSpec = new CFilterCoder;	//这是个大麻烦
        filterStream = filterStreamSpec;
      }
      filterStreamSpec->Filter = cryptoFilter;			//前面步骤已经确定了他是哪个zip类型，547行已经定义了

	  //读取文件头
      if (wzAesMode)
      {
        result = _wzAesDecoderSpec->ReadHeader(inStream);
      }
      else if (pkAesMode)//Not
      {
        result =_pkAesDecoderSpec->ReadHeader(inStream, item.FileCRC, item.UnPackSize);
        if (result == S_OK)
        {
          bool passwOK;
          result = _pkAesDecoderSpec->CheckPassword(passwOK);
          if (result == S_OK && !passwOK)
            result = S_FALSE;
        }
      }
      else //Not
      {
        result = _zipCryptoDecoderSpec->ReadHeader(inStream);
      }

	  //如果读取文件头成功
      if (result == S_OK)
      {
	    printf("before gain 2 byte test\n\n");
		//产生2Byte校验值，调用了CBaseCoder的Init()方法，产生2字节验证值
        RINOK(filterStreamSpec->SetInStream(inStream));//将filterStreamSpec对CDecoder成员变量_key.pwdverifyValue进行了变换,inStream 在 541，已经定位好了数据和验证的位置
		printf("after  gain 2 byte test\n\n");

        inStreamReleaser.FilterCoder = filterStreamSpec;
        inStreamNew = filterStream;

		//如果是WinZip格式zip文件，验证2字节的校验值
        if (wzAesMode)
        {
		  printf("checking~~~~~~~~~~~~~~~~~\n");
          if (!_wzAesDecoderSpec->CheckPasswordVerifyCode())//比对2字节的校验值
            result = S_FALSE;
		   printf("checking~~~~~~~~~~~~~~~~~\n");
        }
      }
    }
    else
      inStreamNew = inStream;

	//密码二次校验
    if (result == S_OK)
	{
      printf("start the Code:\n");
	   
	  //影响10字节的校验,Code()在DeflateDecoder.cpp中310行
	  //在这里将是后续的主要东西！！！！&item.UnPackSize就是没打包之前的字节数
	 // UInt64 *a;*a=1;
      result = coder->Code(inStreamNew, outStream, NULL,&item.UnPackSize , compressProgress);  //第一个参数是定位好输入文件流的，
	}

	//密码错误
    if (result == S_FALSE)
	{
	  printf("dtch:wrong\n");//OK
      return S_OK;
	}

	//解压失败类型
    if (result == E_NOTIMPL)
    {
      res = NExtract::NOperationResult::kUnSupportedMethod;
      return S_OK;
    }

    RINOK(result);
  }
  bool crcOK = true;
  bool authOk = true;
  if (needCRC)
  {
	//not in
    printf("lvlv:need the crc\n");
	printf("item.FileCRC:%d\n",item.FileCRC);
    crcOK = (outStreamSpec->GetCRC() == item.FileCRC);
    if(crcOK)
	{ printf("crcOK\n");}//OK
  }
  //验证10 Bytes校验值
  if (wzAesMode)
  {
    printf("lvlv:wzAesMode\n");
	//必须通过下面一步，否则报CRC error in the file，且不继续执行下面的步骤

    inStream.Attach(archive.CreateLimitedStream(authenticationPos, NCrypto::NWzAes::kMacSize));//这步已经不需要了，没有改变

    if (_wzAesDecoderSpec->CheckMac(inStream, authOk) != S_OK)
      authOk = false;
	//add
	else
	{
		printf("authOK\n");
	}
  }
  
  res = ((crcOK && authOk) ?
    NExtract::NOperationResult::kOK :
    NExtract::NOperationResult::kCRCError);
  return S_OK;
}


STDMETHODIMP CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testMode, IArchiveExtractCallback *extractCallback)
{

  COM_TRY_BEGIN
	    printf("start the CHandler::Extract()\n");

  CZipDecoder myDecoder;
  UInt64 totalUnPacked = 0, totalPacked = 0;
  bool allFilesMode = (numItems == (UInt32)-1);
  if (allFilesMode)
    numItems = m_Items.Size();
  if(numItems == 0)
    return S_OK;
  UInt32 i;
  //std::cout<<"numItems in ZipHandler:"<<numItems<<std::endl;      确认有多少个文件=3
  for (i = 0; i < numItems; i++)
  {
    const CItemEx &item = m_Items[allFilesMode ? i : indices[i]];
    totalUnPacked += item.UnPackSize;
    totalPacked += item.PackSize;
  }
  RINOK(extractCallback->SetTotal(totalUnPacked));				//设置回馈的信息

  UInt64 currentTotalUnPacked = 0, currentTotalPacked = 0;
  UInt64 currentItemUnPacked, currentItemPacked;
  
  CLocalProgress *lps = new CLocalProgress;   //是个难点···
  CMyComPtr<ICompressProgressInfo> progress = lps;
  lps->Init(extractCallback, false);   //等等回馈内容记录  把extractCallback考进去而已

  for (i = 0; i < numItems; i++, currentTotalUnPacked += currentItemUnPacked,
      currentTotalPacked += currentItemPacked)
  {
    currentItemUnPacked = 0;
    currentItemPacked = 0;

    lps->InSize = currentTotalPacked;
    lps->OutSize = currentTotalUnPacked;
    RINOK(lps->SetCur());			//会到SetRatio ,这个有点像偏移！！！危险！！！   这里面发现重要东西，传说18B的附加信息！

    CMyComPtr<ISequentialOutStream> realOutStream;   //输出方式？？？为了不丢错误出来？

    Int32 askMode = testMode ?
        NExtract::NAskMode::kTest :
        NExtract::NAskMode::kExtract;

    Int32 index = allFilesMode ? i : indices[i];

    RINOK(extractCallback->GetStream(index, &realOutStream, askMode));  //获得文件的输入流，连是否覆盖都是在这里！

    CItemEx item = m_Items[index];
    if (!item.FromLocal)
    { //std::cout<<"here or not"<<std::endl;      I'm in
      HRESULT res = m_Archive.ReadLocalItemAfterCdItem(item);		//加载文件的信息！！！可以看看，就是检测头部信息完整与否
      if (res == S_FALSE)
      {
        if (item.IsDir() || realOutStream || testMode)
        {
			//std::cout<<"here or not"<<std::endl;      not in 
          RINOK(extractCallback->PrepareOperation(askMode));
          realOutStream.Release();
          RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kUnSupportedMethod));
        }
        continue;
      }
      RINOK(res);
    }

    if (item.IsDir() || item.IgnoreItem())
    {
      // if (!testMode)
      {
		
        RINOK(extractCallback->PrepareOperation(askMode));
        realOutStream.Release();
        RINOK(extractCallback->SetOperationResult(NExtract::NOperationResult::kOK));
      }
      continue;
    }

    currentItemUnPacked = item.UnPackSize;			//分别是压缩前和压缩后的大小,压缩后包括头部
    currentItemPacked = item.PackSize;
	std::cout<<"UnPackSize："<<item.UnPackSize<<"      PackSize："<<item.PackSize<<std::endl;  
    if (!testMode && !realOutStream)
      continue;

    RINOK(extractCallback->PrepareOperation(askMode));  //一些小操作估计，还没细看

    Int32 res;

	//此处调用解码函数Decode（）
	printf("\nbefore the CZipDecoder::Decode()\n");
	//真正的工作才刚刚开始！！！   realOutStream是个问题
    HRESULT hres = myDecoder.Decode(
        EXTERNAL_CODECS_VARS
        m_Archive, item, realOutStream, extractCallback,
        progress,
        #ifndef _7ZIP_ST
        _props.NumThreads,
        #endif
        res);
    RINOK(hres);
    realOutStream.Release();
    
    RINOK(extractCallback->SetOperationResult(res))
  }
  lps->InSize = currentTotalPacked;
  lps->OutSize = currentTotalUnPacked;
  return lps->SetCur();
  COM_TRY_END
}

IMPL_ISetCompressCodecsInfo

}}
