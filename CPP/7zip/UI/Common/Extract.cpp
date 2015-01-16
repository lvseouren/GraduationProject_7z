// Extract.cpp

#include "StdAfx.h"
#include "iostream"
#include <stdio.h>

#include "Windows/FileDir.h"
#include "Windows/PropVariant.h"
#include "Windows/PropVariantConversions.h"

#include "../Common/ExtractingFilePath.h"

#include "Extract.h"
#include "SetProperties.h"

using namespace NWindows;

static HRESULT DecompressArchive(
    const CArc &arc,
    UInt64 packSize,
    const NWildcard::CCensorNode &wildcardCensor,
    const CExtractOptions &options,
    IExtractCallbackUI *callback,
    CArchiveExtractCallback *extractCallbackSpec,
    UString &errorMessage,
    UInt64 &stdInProcessed)
{
  stdInProcessed = 0;

  //在哪实现了抽象结构体的纯虚函数？？？
  IInArchive *archive = arc.Archive;   //选中压缩文件
  CRecordVector<UInt32> realIndices;
  if (!options.StdInMode)
  {
    UInt32 numItems;

	//获取单个压缩包中文件的个数
    RINOK(archive->GetNumberOfItems(&numItems));
    
	//压缩包中文件的个数,numitems就是文件数量    numItems=3
    for (UInt32 i = 0; i < numItems; i++)
    {
	 // std::cout<<"numItems!!!!!!!!!!!!!"<<numItems<<std::endl;
      UString filePath;
      RINOK(arc.GetItemPath(i, filePath));    //其实在合格PATH将会是每个文件的文件名
	  //std::wcout<<"PATH！！！！！！"<<*filePath<<std::endl;
      bool isFolder;
      RINOK(IsArchiveItemFolder(archive, i, isFolder));
      if (!wildcardCensor.CheckPath(filePath, !isFolder))
        continue;
      realIndices.Add(i);
    }
    if (realIndices.Size() == 0)
    {
      callback->ThereAreNoFiles();
      return S_OK;
    }
  }

  UStringVector removePathParts;

  FString outDir = options.OutputDir;
  outDir.Replace(FSTRING_ANY_MASK, us2fs(GetCorrectFsPath(arc.DefaultName)));   //设置输出目录而已
  #ifdef _WIN32
  // GetCorrectFullFsPath doesn't like "..".
  // outDir.TrimRight();
  // outDir = GetCorrectFullFsPath(outDir);
  #endif

  if (!outDir.IsEmpty())
	  //未执行，创建输出目录而已
    if (!NFile::NDirectory::CreateComplexDirectory(outDir))
    {
      HRESULT res = ::GetLastError();
      if (res == S_OK)
        res = E_FAIL;
      errorMessage = ((UString)L"Can not create output directory ") + fs2us(outDir);
      return res;
    }


	
  //执行了，用于等等返回时候给出相关信息的
  extractCallbackSpec->Init(
      options.StdInMode ? &wildcardCensor : NULL,
      &arc,
      callback,
      options.StdOutMode, options.TestMode, options.CalcCrc,
      outDir,
      removePathParts,
      packSize);    

  //here!!!!
  #if !defined(_7ZIP_ST) && !defined(_SFX)
 // std::cout<<"aaaaaa"<<std::endl;
  RINOK(SetProperties(archive, options.Properties));
  #endif

  HRESULT result;
  Int32 testMode = (options.TestMode && !options.CalcCrc) ? 1: 0;

  //没有执行
  if (options.StdInMode)
  {	
	//   std::cout<<"333333333333!!!!!!!!!!!!!"<<std::endl;
	//Extract方法在哪里被定义了
    result = archive->Extract(NULL, (UInt32)(Int32)-1, testMode, extractCallbackSpec);
    NCOM::CPropVariant prop;
    if (archive->GetArchiveProperty(kpidPhySize, &prop) == S_OK)
      if (prop.vt == VT_UI8 || prop.vt == VT_UI4)
        stdInProcessed = ConvertPropVariantToUInt64(prop);
  }
  else
	//goto the CArchiveExtractCallback::CryptoGetTextPassword进行3次获取明文密码，并提示密码已错
    result = archive->Extract(&realIndices.Front(), realIndices.Size(), testMode, extractCallbackSpec);

  return callback->ExtractResult(result);
}

HRESULT DecompressArchives(
    CCodecs *codecs, const CIntVector &formatIndices,
    UStringVector &arcPaths, UStringVector &arcPathsFull,
    const NWildcard::CCensorNode &wildcardCensor,
    const CExtractOptions &options,
    IOpenCallbackUI *openCallback,
    IExtractCallbackUI *extractCallback,
    UString &errorMessage,
    CDecompressStat &stat)
{
  stat.Clear();
  int i;
  UInt64 totalPackSize = 0;
  CRecordVector<UInt64> archiveSizes;

  int numArcs = options.StdInMode ? 1 : arcPaths.Size();
  printf("the numArcs is %d\n",numArcs);//感觉是不是表示从标准输入给出文件名，一个文件

  //if(options.StdInMode) std::cout<<"i guess it appear here"<<std::endl;

  for (i = 0; i < numArcs; i++)
  {
    NFile::NFind::CFileInfo fi;
    fi.Size = 0;
    if (!options.StdInMode)
    {
      const FString &arcPath = us2fs(arcPaths[i]);
      if (!fi.Find(arcPath))	//在这里把文件打开了
        throw "there is no such archive";
      if (fi.IsDir())
        throw "can't decompress folder";
    }
	std::cout<<"fi.Size :"<<fi.Size<<std::endl;   //真个压缩文件的大小
    archiveSizes.Add(fi.Size);
    totalPackSize += fi.Size;
  }
  CArchiveExtractCallback *extractCallbackSpec = new CArchiveExtractCallback;   //一个包含了各项信息的指针
  CMyComPtr<IArchiveExtractCallback> ec(extractCallbackSpec);  //CMyComPtr就是一个指针···能指向各自东西的指针，自己写的模板类
 
  bool multi = (numArcs > 1);  //是否有多个文件，当然不是啦
  extractCallbackSpec->InitForMulti(multi, options.PathMode, options.OverwriteMode);
  if (multi)
  {
    RINOK(extractCallback->SetTotal(totalPackSize));
  }

  //循环提取压缩包
  for (i = 0; i < numArcs; i++)    //一个压缩包
  {
	  std::cout<<"loop~"<<std::endl;
    const UString &arcPath = arcPaths[i];
    NFile::NFind::CFileInfo fi;
    if (options.StdInMode)
    {
	  //std::cout<<"i guess it appear here"<<std::endl;
      fi.Size = 0;
      fi.Attrib = 0;
    }
    else
    {
	   //	  std::cout<<"another way~"<<std::endl;
      if (!fi.Find(us2fs(arcPath)) || fi.IsDir())   //在这里打开了文件
        throw "there is no such archive";
    }

    #ifndef _NO_CRYPTO
    openCallback->Open_ClearPasswordWasAskedFlag();
    #endif
	//这里会输出proseccing archive
	///////////////////////////////////////////////////////////////////////////////////////////////////////

    RINOK(extractCallback->BeforeOpen(arcPath));
    CArchiveLink archiveLink;  //也是一个存压缩文件信息的东西，理解为压缩文件链？

    CIntVector formatIndices2 = formatIndices;
    #ifndef _SFX
	
    if (formatIndices.IsEmpty())
    {	
		//in 这里是有的！
      int pos = arcPath.ReverseFind(L'.');
      if (pos >= 0)
      {
        UString s = arcPath.Mid(pos + 1);
		//std::wcout<<*(s+1)<<std::endl;
        int index = codecs->FindFormatForExtension(s);  //根据后缀名找到对应种类

        if (index >= 0 && s == L"001")
        { //not in
          s = arcPath.Left(pos);
          pos = s.ReverseFind(L'.');
          if (pos >= 0)
          {
            int index2 = codecs->FindFormatForExtension(s.Mid(pos + 1));
            if (index2 >= 0 && s.CompareNoCase(L"rar") != 0)
            {
              formatIndices2.Add(index2);
              formatIndices2.Add(index);
            }
          }
        }
      }
    }
    #endif
    HRESULT result = archiveLink.Open2(codecs, formatIndices2, options.StdInMode, NULL, arcPath, openCallback);  //里面比较复杂，但是总的来说就是获取文件的信息
    //std::cout<<"check result:"<<result<<std::endl;    
	if (result == E_ABORT)
      return result;
	//暂时看到这里！
    bool crypted = false;
    #ifndef _NO_CRYPTO
    crypted = openCallback->Open_WasPasswordAsked();  //返回是否加密
    #endif

    RINOK(extractCallback->OpenResult(arcPath, result, crypted));  //查看密码处！这里有点不一样，因为他是针对其他输入方式适合判断的。
    if (result != S_OK)
      continue;

    if (!options.StdInMode)
    for (int v = 0; v < archiveLink.VolumePaths.Size(); v++)   //size 是 1， 目测是有几个文件
    {
		//std::cout<<"here i m:"<<archiveLink.VolumePaths.Size()<<std::endl;
      int index = arcPathsFull.FindInSorted(archiveLink.VolumePaths[v]);  //看样子应该是找到这个文件放在数据结构的何处
	 // std::cout<<"index:"<<index<<std::endl;
      if (index >= 0 && index > i)
      {
		//  std::cout<<"here i m:"<<archiveLink.VolumePaths.Size()<<std::endl;  //not in
        arcPaths.Delete(index);
        arcPathsFull.Delete(index);
        totalPackSize -= archiveSizes[index];
        archiveSizes.Delete(index);
        numArcs = arcPaths.Size();
      }
    }
    if (archiveLink.VolumePaths.Size() != 0)
    {
      totalPackSize += archiveLink.VolumesSize;
      RINOK(extractCallback->SetTotal(totalPackSize));
    }

    #ifndef _NO_CRYPTO
    UString password;
    RINOK(openCallback->Open_GetPasswordIfAny(password));//获取输入的密码
	//std::wcout<<" password here:"<<*password<<std::endl;     this is an empty password
    if (!password.IsEmpty())
    {
	  //std::cout<<"get password here"<<std::endl;
      RINOK(extractCallback->SetPassword(password));
    }
    #endif

	//循环的次数为压缩包的数量
    for (int v = 0; v < archiveLink.Arcs.Size(); v++)          //size = 1
    {
	//	std::cout<<"Arcs.Size!!!!!!!!!!!!!"<<std::endl;
      const UString &s = archiveLink.Arcs[v].ErrorMessage;     //估计看打开有没有问题
      if (!s.IsEmpty())
      {
        RINOK(extractCallback->MessageError(s));
      }
    }

    CArc &arc = archiveLink.Arcs.Back();  //返回最后一个元素
    arc.MTimeDefined = (!options.StdInMode && !fi.IsDevice);
    arc.MTime = fi.MTime;

    UInt64 packProcessed;




	//提取单个压缩文件包
    RINOK(DecompressArchive(arc,
        fi.Size + archiveLink.VolumesSize,
        wildcardCensor, options, extractCallback, extractCallbackSpec, errorMessage, packProcessed));





    if (!options.StdInMode)
      packProcessed = fi.Size + archiveLink.VolumesSize;
    extractCallbackSpec->LocalProgressSpec->InSize += packProcessed;   //文件的总大小
    extractCallbackSpec->LocalProgressSpec->OutSize = extractCallbackSpec->UnpackSize;    //每个文件原始大小加起来的和！
	//std::cout<<"INSIZE "<<packProcessed<<" AND OUTSIZE："<<extractCallbackSpec->UnpackSize<<std::endl;


    if (!errorMessage.IsEmpty())
      return E_FAIL;
  }
  stat.NumFolders = extractCallbackSpec->NumFolders;
  stat.NumFiles = extractCallbackSpec->NumFiles;
  stat.UnpackSize = extractCallbackSpec->UnpackSize;
  stat.CrcSum = extractCallbackSpec->CrcSum;

  stat.NumArchives = arcPaths.Size();
  stat.PackSize = extractCallbackSpec->LocalProgressSpec->InSize;
  return S_OK;
}
