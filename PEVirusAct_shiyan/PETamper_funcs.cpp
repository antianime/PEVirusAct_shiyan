#include"fh.h"

using namespace std;

unsigned char check[] = "CHECKCHECK";
/*
IMAGE_DOS_HEADER idh;           //DOSͷ����"MZ"��ͷ��
IMAGE_NT_HEADERS inh;			//NTͷ��PEǩ�����ļ�ͷ����ѡͷ��

WORD NumberOfSections;			// ��������

// ����������ݽṹ
std::vector<IMAGE_SECTION_HEADER> SectionHeaders;	// �洢���н���ͷ
//std::vector<BYTE[8]> SectionNames;
//std::vector<BYTE*> SectionNames;
std::vector<std::vector<BYTE>>SectionNames;			// �洢���н�������
std::vector<BYTE> stubbuffer;

*/

					// �洢DOS�������

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

PETamper::PETamper(string FileName)
{
	unsigned long NumberOfBytesRead;	// ��ȡ�ֽ�������
	unsigned char MZSignal[2];			// ���ڼ��"MZ"ǩ���Ļ�����

	// ��PE�ļ�����ȡ�ļ����
	HANDLE hFile = CreateFileA(
		(LPCSTR)FileName.c_str(), 	      // �ļ���
		GENERIC_READ | GENERIC_WRITE,	  // ��дȨ��
		0,								 // ������
		NULL,
		OPEN_EXISTING,					 // ���Ѵ��ڵ��ļ�
		FILE_ATTRIBUTE_NORMAL, 		 // ��ͨ�ļ�����
		NULL
	);

	
	/*
	
	// ��ȡ�����ļ����ݵ��ڴ滺����
	char* allbuffer = new char[GetFileSize(hFile, NULL)];
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}



	// ����ȡ���ļ�����д�뵽���ļ�"TestFile"�У����ڲ��Ի򱸷�)
	HANDLE hpFile = CreateFileA(
		"TestFile",						// ���ļ���
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, 						// ���Ǵ������ļ�
		FILE_ATTRIBUTE_NORMAL, NULL);

	//WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	cout << "1 GetLastError:" << GetLastError() << endl;
	delete[] allbuffer;			// �ͷ��ڴ滺��
	//cout << hFile << endl;
	
	*/
	

	

	// ���PE�ļ���ͷ��"MZ"ǩ����DOSͷǩ����
	SetFilePointer(hFile, 0, NULL, 0);		// ���ļ�ָ���ƶ����ļ���ͷ
	if (!ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at MZSignal!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')		// ���ǩ���Ƿ���ȷ
	{
		cout << "This is not a PE file!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	// ��ȡDOSͷ��IMAGE_DOS_HEADER�ṹ��
	SetFilePointer(hFile, 0, NULL, 0);			// �����ļ�ָ�뵽��ͷ
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	

	// ��ȡDOS���,  ����e_lfanew�Ǵ�DOSͷ��PEǩ����ƫ����
	//char* stubbuffer = new char[idh.e_lfanew - sizeof(IMAGE_DOS_HEADER)];
	stubbuffer.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));

	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// �ƶ���DOSͷ֮��

	if (!ReadFile(hFile, stubbuffer.data(), stubbuffer.size(), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at stubbuffer!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}


	// ��ȡNTͷ��PEǩ����ͷ��Ϣ),  ����e_lfanew�Ǵ�DOSͷ��PEǩ����ƫ����
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return;
	}

	// ���ļ�ͷ��ȡ�����������洢���ļ�ͷ��NumberOfSections�ֶΣ�
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);		// ��������ͷ������С
	SectionNames.resize(NumberOfSections);			// ������������������С
	Sections.resize(NumberOfSections);				// ������������������С

	// �������ͷ��λ�ã�
	// DOSͷ + PEǩ��(4�ֽ�) + �ļ�ͷ(20�ֽ�) + ��ѡͷ��С
	SetFilePointer(hFile, idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader, NULL, 0);

	// ��ȡ���н���ͷ��Ϣ
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!ReadFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesRead, NULL))
		{
			cout << "ReadFile failed at SectionHeaders " << i << endl;
			cout << "GetLastError: " << GetLastError() << endl;
			return;
		}

		// ��ӡ�������ƣ�8�ֽ���null�����ַ�����
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
		SetFilePointer(hFile, SectionHeaders[i].PointerToRawData, NULL, 0);	// �ƶ����������ݵ���ʼλ��
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

/* ��װPE�ļ����� */
bool PETamper::Assembly(HANDLE hFile)
{
	unsigned long NumberOfBytesRead;
	std::string FillStr;

	//cout << idh.e_magic << endl;



	// 1. д��DOSͷ
	SetFilePointer(hFile, 0, NULL, 0);
	if (!WriteFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "WriteFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return false;
	}

	//cout << "NumberOfBytesRead" << NumberOfBytesRead << endl;
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
		WriteFile(hFile, FillStr.data(), FillStr.length(), NULL, NULL);
	}

	// 5. д��NTͷ
	WriteFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), NULL, NULL);

	// 6. д�����н���ͷ
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

	buffer.append(IMAGE_DOS_HEADER_INFO[Point].size - buffer.size(), 0); //���0x0
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



