#include"fh.h"

using namespace std;

IMAGE_DOS_HEADER idh;           //DOS头（以"MZ"开头）
IMAGE_NT_HEADERS inh;			//NT头（PE签名、文件头、可选头）

WORD NumberOfSections;			// 节区数量

// 节区相关数据结构
std::vector<IMAGE_SECTION_HEADER> SectionHeaders;	// 存储所有节区头
//std::vector<BYTE[8]> SectionNames;
//std::vector<BYTE*> SectionNames;
std::vector<std::vector<BYTE>>SectionNames;			// 存储所有节区名称
std::vector<BYTE> stubbuffer;						// 存储DOS存根数据

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

/* 组装PE文件函数 */
bool Assembly(HANDLE hFile)
{
	std::string FillStr;

	// 1. 写入DOS头
	SetFilePointer(hFile, 0, NULL, 0);
	WriteFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
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
		WriteFile(hFile, &FillStr, FillStr.length(), NULL, NULL);
	}

	// 5. 写入NT头
	WriteFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), NULL, NULL);

	// 6. 写入所有节区头
	for (int i = 0; i < NumberOfSections; i++)
		WriteFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), NULL, NULL);

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

bool EntryPointCover(HANDLE hpFile, DWORD EntryPoint)
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

bool SectionTamper(HANDLE hpFile, LONG Point, unsigned char* buffer)
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

bool FieldTamper(LONG Point,char* buffer)
{
	return true;
}

bool TextSectionTamper(HANDLE hpFile, unsigned char* buffer, DWORD EntryPoint)
{
	unsigned long NumberOfBytesRead;
	DWORD PointerToRawPointer;
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!strcmp((const char*)&SectionNames[i], ".text"))
		{
			SectionTamper(hpFile, SectionHeaders[i].PointerToRawData, buffer);
			EntryPointCover(hpFile, EntryPoint);
			return true;
		}
	}
	return false;
}

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

/*

bool FileHeaderTamper(HANDLE hFile,unsigned char* buffer,int size,int ObjectFlag,int DecisionFlag)
{
	//Check fh.h

	switch(ObjectFlag)
	{
	case DOS_T:			//IMAGE_DOS_HEADER
		switch (DecisionFlag)
		{
		case e_magic_T:
			idh.e_magic = *(WORD*)buffer;
			break;
		case e_lfanew_T:
			idh.e_lfanew = *(DWORD*)buffer;
			break;
		}
		break;
	case NT_T:		//IMAGE_NT_HEADERS
		switch (DecisionFlag)
		{

		}
		break;
	}
	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cout << "ERROR:  " << GetLastError() << endl;
		return false;
	}
	else
		return true;
}

*/
