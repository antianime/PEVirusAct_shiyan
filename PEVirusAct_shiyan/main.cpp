#include"fh.h"  

using namespace std;

#define STRING(X) #X


int main()
{
	
	//IMAGE_SECTION_HEADER ish;
	IMAGE_IMPORT_DESCRIPTOR iid;	//导入描述符
	IMAGE_IMPORT_BY_NAME iibn;		
	IMAGE_THUNK_DATA itd;
	IMAGE_BASE_RELOCATION ibr;
	IMAGE_BASE_RELOCATION ibr2;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_IMPORT_DESCRIPTOR iid2;


	//string FileName;
	//cin >> FileName;
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	//PathFileExistsA(FileName.c_str());	// 检查文件是否存在

	PETamper pt(FileName);

	HANDLE hpFile = CreateFileA("TestFile", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hpFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateFile failed with error code " << GetLastError() << std::endl;
		return 1;
	}

	pt.Assembly(hpFile);

	CloseHandle(hpFile);	// 关闭文件句柄







	/*
	
	
	
	unsigned long NumberOfBytesRead;	// 读取字节数计数
	unsigned char MZSignal[2];			// 用于检查"MZ"签名的缓冲区

	// 打开PE文件，获取文件句柄
	HANDLE hFile = CreateFileA(
		(LPCSTR)FileName.c_str(), 	      // 文件名
		GENERIC_READ | GENERIC_WRITE,	  // 读写权限
		 0,								 // 不共享
		 NULL,
		 OPEN_EXISTING,					 // 打开已存在的文件
		 FILE_ATTRIBUTE_NORMAL, 		 // 普通文件属性
		 NULL
	);


	// 读取整个文件内容到内存缓冲区
	char* allbuffer = new char[GetFileSize(hFile, NULL)];
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// 将读取的文件内容写入到新文件"TestFile"中（用于测试或备份)
	HANDLE hpFile = CreateFileA(
		"TestFile" ,						// 新文件名
		GENERIC_READ | GENERIC_WRITE, 0, NULL, 
		CREATE_ALWAYS, 						// 总是创建新文件
		FILE_ATTRIBUTE_NORMAL, NULL);

	//WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	
	delete[] allbuffer;			// 释放内存缓冲
	//cout << hFile << endl;



	// 检查PE文件开头的"MZ"签名（DOS头签名）
	SetFilePointer(hFile, 0, NULL, 0);		// 将文件指针移动到文件开头
	if (!ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at MZSignal!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')		// 检查签名是否正确
	{
		cout << "This is not a PE file!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// 读取DOS头（IMAGE_DOS_HEADER结构）
	SetFilePointer(hFile,0,NULL,0);			// 重置文件指针到开头
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// 读取DOS存根,  其中e_lfanew是从DOS头到PE签名的偏移量
	//char* stubbuffer = new char[idh.e_lfanew - sizeof(IMAGE_DOS_HEADER)];
	stubbuffer.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));

	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// 移动到DOS头之后

	if (!ReadFile(hFile, stubbuffer.data(), stubbuffer.size(), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at stubbuffer!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
		

	// 读取NT头（PE签名和头信息),  其中e_lfanew是从DOS头到PE签名的偏移量
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// 从文件头获取节区数量（存储在文件头的NumberOfSections字段）
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);		// 调整节区头向量大小
	SectionNames.resize(NumberOfSections);			// 调整节区名称向量大小
	
	// 计算节区头的位置：
    // DOS头 + PE签名(4字节) + 文件头(20字节) + 可选头大小
	SetFilePointer(hFile, idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader, NULL, 0);
	
	// 读取所有节区头信息
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!ReadFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesRead, NULL))
		{
			cout << "ReadFile failed at SectionHeaders " << i << endl;
			cout << "GetLastError: " << GetLastError() << endl;
			return 0;
		}

		// 打印节区名称（8字节以null填充的字符串）
		cout << "Section Name: ";
		for (int j = 0; j < 8; j++)
		{
			SectionNames[i].resize(NumberOfSections);
			SectionNames[i][j] = SectionHeaders[i].Name[j];
			cout << SectionNames[i][j];
		}
		cout << endl;
		
	}
	
	Assembly(hpFile);	// 组装文件，写入DOS头、DOS存根、NT头和节区头
	



	
	for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++)
	{
		cout << hex << (int)((unsigned char*)&idh)[i] << " ";
	}
	
	*/
	
	return 0;
}