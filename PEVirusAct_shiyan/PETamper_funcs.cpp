#include"fh.h"

using namespace std;

unsigned char check[] = "CHECKCHECK";
/*
IMAGE_DOS_HEADER idh;           //DOS头（以"MZ"开头）
IMAGE_NT_HEADERS inh;			//NT头（PE签名、文件头、可选头）

WORD NumberOfSections;			// 节区数量

// 节区相关数据结构
std::vector<IMAGE_SECTION_HEADER> SectionHeaders;	// 存储所有节区头
//std::vector<BYTE[8]> SectionNames;
//std::vector<BYTE*> SectionNames;
std::vector<std::vector<BYTE>>SectionNames;			// 存储所有节区名称
std::vector<BYTE> stubbuffer;

*/

					// 存储DOS存根数据

unsigned char shellcode[];							// 存储shellcode代码

// DOS头字段信息（名称、大小、偏移量)
std::vector< FieldInfo>IMAGE_DOS_HEADER_INFO = {
	{"e_magic",2, },
	{"e_cblp",2,} ,                 // Bytes on last page of file
	{ "e_cp",2, },                       // Pages in file
	{ "e_crlc", 2,},                      // Relocations
	{ "e_cparhdr", 2,},                  // Size of header in paragraphs
	{ "e_minalloc",2, },                  // Minimum extra paragraphs needed
	{ "e_maxalloc",2, },                  // Maximum extra paragraphs needed
	{ "e_ss",2, },                       // Initial (relative) SS value
	{ "e_sp",2, },                        // Initial SP value
	{ "e_csum",2, },                     // Checksum
	{ "e_ip",2, },                      // Initial IP value
	{ "e_cs",2, },                     // Initial (relative) CS value
	{ "e_lfarlc",2, },                  // File address of relocation table
	{ "e_ovno",2, },                    // Overlay number
	{ "e_res", 8,},                // Reserved words
	{ "e_oemid",2, },                 // OEM identifier (for e_oeminfo)
	{ "e_oeminfo",2, },                // OEM information; e_oemid specific
	{ "e_res2",20, },               // Reserved words
	{ "e_lfanew",4, }
};

// NT头字段信息
std::vector< FieldInfo>IMAGE_NT_HEADER_INFO = {

};

PETamper::PETamper(string FileName)
{
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

	
	/*
	
	// 读取整个文件内容到内存缓冲区
	char* allbuffer = new char[GetFileSize(hFile, NULL)];
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}



	// 将读取的文件内容写入到新文件"TestFile"中（用于测试或备份)
	HANDLE hpFile = CreateFileA(
		"TestFile",						// 新文件名
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, 						// 总是创建新文件
		FILE_ATTRIBUTE_NORMAL, NULL);

	//WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	cout << "1 GetLastError:" << GetLastError() << endl;
	delete[] allbuffer;			// 释放内存缓冲
	//cout << hFile << endl;
	
	*/
	

	

	// 检查PE文件开头的"MZ"签名（DOS头签名）
	SetFilePointer(hFile, 0, NULL, 0);		// 将文件指针移动到文件开头
	if (!ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at MZSignal!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')		// 检查签名是否正确
	{
		cout << "This is not a PE file!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	// 读取DOS头（IMAGE_DOS_HEADER结构）
	SetFilePointer(hFile, 0, NULL, 0);			// 重置文件指针到开头
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	

	// 读取DOS存根,  其中e_lfanew是从DOS头到PE签名的偏移量
	//char* stubbuffer = new char[idh.e_lfanew - sizeof(IMAGE_DOS_HEADER)];
	stubbuffer.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));

	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// 移动到DOS头之后

	if (!ReadFile(hFile, stubbuffer.data(), stubbuffer.size(), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at stubbuffer!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}


	// 读取NT头（PE签名和头信息),  其中e_lfanew是从DOS头到PE签名的偏移量
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	// 从文件头获取节区数量（存储在文件头的NumberOfSections字段）
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);		// 调整节区头向量大小
	SectionNames.resize(NumberOfSections);			// 调整节区名称向量大小
	Sections.resize(NumberOfSections);				// 调整节区数据向量大小

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
			return;
		}

		// 打印节区名称（8字节以null填充的字符串）
		//cout << "Section Name: ";
		for (int j = 0; j < 8; j++)
		{
			SectionNames[i].resize(NumberOfSections);
			SectionNames[i][j] = SectionHeaders[i].Name[j];
			
			//cout << SectionNames[i][j];
		}
		
		//cout << endl;

	}
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		Sections[i].resize(SectionHeaders[i].SizeOfRawData);
		SetFilePointer(hFile, SectionHeaders[i].PointerToRawData, NULL, 0);	// 移动到节区数据的起始位置
		if (!ReadFile(hFile, Sections[i].data(), SectionHeaders[i].SizeOfRawData, &NumberOfBytesRead, NULL))
		{
			cout << "ReadFile failed at Sections " << i << " : " << SectionNames[i].data() << endl;
			cout << "GetLastError: " << GetLastError() << endl;
			return;
		}
	}

	

}



/*

bool ForConsole()
{
	string HeaderSelection, FieldSelection;
	do
	{
		system("cls");
		cout << "HEADER TAMPER" << endl << "input selection" << endl;
		cin >> HeaderSelection;
		if (HeaderSelection.size() != 1)
		{
			cout << "Input Error!" << endl;
			continue;
		}
		switch (HeaderSelection[0])
		{
		case 1:
			{
			cout << "input field selection" << endl;
			switch
			{
			case 1:
			}
		

			}
			break;
		case2:
		}
	} while (true);
	return true;
}
*/

/* 组装PE文件函数 */
bool PETamper::Assembly(HANDLE hFile)
{
	unsigned long NumberOfBytesRead;
	std::string FillStr;

	//cout << idh.e_magic << endl;



	// 1. 写入DOS头
	SetFilePointer(hFile, 0, NULL, 0);
	if (!WriteFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "WriteFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return false;
	}

	//cout << "NumberOfBytesRead" << NumberOfBytesRead << endl;
	//stubbuffer.data();

	// 2. 写入DOS存根
	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// 移动到DOS头之后
	WriteFile(hFile, stubbuffer.data(), stubbuffer.size(), NULL, NULL);
	
	// 3. 处理PE头对齐
	if (sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() > idh.e_lfanew)
	{
		// 计算4字节对齐的偏移量
		idh.e_lfanew += 4 * ((sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() + 3) % 4);//PE头按0x4对齐
	}

	// 4. 如果需要，填充空白区域
	if (sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() < idh.e_lfanew)//填充0x0
	{
		FillStr.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER) - stubbuffer.size());
		std::fill(FillStr.begin(), FillStr.end(), 0); // Fill the string with null characters
		WriteFile(hFile, FillStr.data(), FillStr.length(), NULL, NULL);
	}

	// 5. 写入NT头
	WriteFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), NULL, NULL);

	// 6. 写入所有节区头
	for (int i = 0; i < NumberOfSections; i++)
		WriteFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), NULL, NULL);
	//WriteFile(hFile, check, sizeof(check), NULL, NULL);
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		//cout << SectionNames[i] << endl;
		if (!strcmp((const char*)SectionNames[i].data(), ".text"))
		{
			if (SectionHeaders[i].PointerToRawData > idh.e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * NumberOfSections)
			{
				FillStr.resize(SectionHeaders[i].PointerToRawData - idh.e_lfanew - sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
				std::fill(FillStr.begin(), FillStr.end(), 0); // Fill the string with null characters
				WriteFile(hFile, FillStr.data(), FillStr.size(), NULL, NULL);
			}
			
		}
	}
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		WriteFile(hFile, Sections[i].data(), Sections[i].size(), NULL, NULL);
	}

	return true;
}

bool HeaderInfoIni(vector<FieldInfo>HEADER_INFO)
{
	for (int i = 0; i < HEADER_INFO.size(); i++)
	{
		if (i == 0)
			HEADER_INFO[i].offset = 0;
		else
			HEADER_INFO[i].offset = HEADER_INFO[i - 1].offset + HEADER_INFO[i - 1].size;
	}
	return true;

}

bool PETamper::EntryPointCover(HANDLE hpFile, DWORD EntryPoint)
{
	unsigned long NumberOfBytesRead;
	SetFilePointer(hpFile, inh.OptionalHeader.AddressOfEntryPoint, NULL, 0);
	WriteFile(hpFile, &EntryPoint, sizeof(EntryPoint), &NumberOfBytesRead, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cout << "ERROR:  " << GetLastError() << endl;
		return false;
	}
	else
		return true;
}

bool PETamper::SectionTamper(HANDLE hpFile, LONG Point, unsigned char* buffer)
{
	unsigned long NumberOfBytesRead;
	SetFilePointer(hpFile, Point, NULL, 0);
	WriteFile(hpFile, buffer, sizeof(buffer), &NumberOfBytesRead, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cout << "ERROR:  " << GetLastError() << endl;
		return false;
	}
	else
		return true;

}

bool PETamper::DOSFieldTamper(PVOID object, LONG Point, string buffer)
{
	if (Point > IMAGE_DOS_HEADER_INFO.size())
	{
		cout << "POINT ERROR! at DOSFieldTamper" << endl;
		return false;
	}
	if (IMAGE_DOS_HEADER_INFO[Point].size < buffer.size())
	{
		cout << "BUFFER LENGTH ERROR! at DOSFieldTamper" << endl;
		return false;
	}

	buffer.append(IMAGE_DOS_HEADER_INFO[Point].size - buffer.size(), 0); //填充0x0
	memmove(&idh + IMAGE_DOS_HEADER_INFO[Point].offset, buffer.c_str(), IMAGE_DOS_HEADER_INFO[Point].size);

	return true;
}

bool PETamper::FieldTamper(PVOID object, LONG Point, char* buffer)
{
	
	memmove((PVOID)((LONGLONG)object + (LONGLONG)Point), buffer, sizeof(buffer));

	return true;
}

bool PETamper::TextSectionTamper(HANDLE hpFile, unsigned char* buffer, DWORD EntryPoint)
{
	unsigned long NumberOfBytesRead;
	DWORD PointerToRawPointer;
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!strcmp((const char*)SectionNames[i].data(), ".text"))
		{
			SectionTamper(hpFile, SectionHeaders[i].PointerToRawData, buffer);
			EntryPointCover(hpFile, EntryPoint);
			return true;
		}
	}
	return false;
}

bool DisplaySection(WORD num)
{

	return true;
}

/*
bool AtomTamper(PVOID Struct, LONG Point, unsigned char* buffer, int size)  //obsolete
{
	memmove((PVOID)((LONGLONG)Struct + (LONGLONG)Point), buffer, size);
	if (GetLastError() != ERROR_SUCCESS)
	{
		cout << "ERROR at AtomTamper: " << GetLastError() << endl;
		return false;
	}
	else
		return true;

}

*/



