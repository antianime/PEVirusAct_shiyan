#include"fh.h"

using namespace std;

IMAGE_DOS_HEADER idh;           //DOSͷ����"MZ"��ͷ��
IMAGE_NT_HEADERS inh;			//NTͷ��PEǩ�����ļ�ͷ����ѡͷ��

WORD NumberOfSections;			// ��������

// ����������ݽṹ
std::vector<IMAGE_SECTION_HEADER> SectionHeaders;	// �洢���н���ͷ
//std::vector<BYTE[8]> SectionNames;
//std::vector<BYTE*> SectionNames;
std::vector<std::vector<BYTE>>SectionNames;			// �洢���н�������
std::vector<BYTE> stubbuffer;						// �洢DOS�������

unsigned char shellcode[];							// �洢shellcode����

// DOSͷ�ֶ���Ϣ�����ơ���С��ƫ����)
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

// NTͷ�ֶ���Ϣ
std::vector< FieldInfo>IMAGE_NT_HEADER_INFO = {

};

/* ��װPE�ļ����� */
bool Assembly(HANDLE hFile)
{
	std::string FillStr;

	// 1. д��DOSͷ
	SetFilePointer(hFile, 0, NULL, 0);
	WriteFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
	//stubbuffer.data();

	// 2. д��DOS���
	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// �ƶ���DOSͷ֮��
	WriteFile(hFile, stubbuffer.data(), stubbuffer.size(), NULL, NULL);
	
	// 3. ����PEͷ����
	if (sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() > idh.e_lfanew)
	{
		// ����4�ֽڶ����ƫ����
		idh.e_lfanew += 4 * ((sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() + 3) % 4);//PEͷ��0x4����
	}

	// 4. �����Ҫ�����հ�����
	if (sizeof(IMAGE_DOS_HEADER) + stubbuffer.size() < idh.e_lfanew)//���0x0
	{
		FillStr.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER) - stubbuffer.size());
		std::fill(FillStr.begin(), FillStr.end(), 0); // Fill the string with null characters
		WriteFile(hFile, &FillStr, FillStr.length(), NULL, NULL);
	}

	// 5. д��NTͷ
	WriteFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), NULL, NULL);

	// 6. д�����н���ͷ
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
