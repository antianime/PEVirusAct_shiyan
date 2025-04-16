#include"fh.h"  

using namespace std;

#define STRING(X) #X


int main()
{
	
	//IMAGE_SECTION_HEADER ish;
	IMAGE_IMPORT_DESCRIPTOR iid;	//����������
	IMAGE_IMPORT_BY_NAME iibn;		
	IMAGE_THUNK_DATA itd;
	IMAGE_BASE_RELOCATION ibr;
	IMAGE_BASE_RELOCATION ibr2;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_IMPORT_DESCRIPTOR iid2;


	//string FileName;
	//cin >> FileName;
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	//PathFileExistsA(FileName.c_str());	// ����ļ��Ƿ����

	PETamper pt(FileName);

	HANDLE hpFile = CreateFileA("TestFile", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hpFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateFile failed with error code " << GetLastError() << std::endl;
		return 1;
	}

	pt.Assembly(hpFile);

	CloseHandle(hpFile);	// �ر��ļ����







	/*
	
	
	
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


	// ��ȡ�����ļ����ݵ��ڴ滺����
	char* allbuffer = new char[GetFileSize(hFile, NULL)];
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// ����ȡ���ļ�����д�뵽���ļ�"TestFile"�У����ڲ��Ի򱸷�)
	HANDLE hpFile = CreateFileA(
		"TestFile" ,						// ���ļ���
		GENERIC_READ | GENERIC_WRITE, 0, NULL, 
		CREATE_ALWAYS, 						// ���Ǵ������ļ�
		FILE_ATTRIBUTE_NORMAL, NULL);

	//WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	
	delete[] allbuffer;			// �ͷ��ڴ滺��
	//cout << hFile << endl;



	// ���PE�ļ���ͷ��"MZ"ǩ����DOSͷǩ����
	SetFilePointer(hFile, 0, NULL, 0);		// ���ļ�ָ���ƶ����ļ���ͷ
	if (!ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at MZSignal!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')		// ���ǩ���Ƿ���ȷ
	{
		cout << "This is not a PE file!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// ��ȡDOSͷ��IMAGE_DOS_HEADER�ṹ��
	SetFilePointer(hFile,0,NULL,0);			// �����ļ�ָ�뵽��ͷ
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// ��ȡDOS���,  ����e_lfanew�Ǵ�DOSͷ��PEǩ����ƫ����
	//char* stubbuffer = new char[idh.e_lfanew - sizeof(IMAGE_DOS_HEADER)];
	stubbuffer.resize(idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));

	SetFilePointer(hFile, sizeof(IMAGE_DOS_HEADER), NULL, 0);		// �ƶ���DOSͷ֮��

	if (!ReadFile(hFile, stubbuffer.data(), stubbuffer.size(), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at stubbuffer!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
		

	// ��ȡNTͷ��PEǩ����ͷ��Ϣ),  ����e_lfanew�Ǵ�DOSͷ��PEǩ����ƫ����
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// ���ļ�ͷ��ȡ�����������洢���ļ�ͷ��NumberOfSections�ֶΣ�
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);		// ��������ͷ������С
	SectionNames.resize(NumberOfSections);			// ������������������С
	
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
			return 0;
		}

		// ��ӡ�������ƣ�8�ֽ���null�����ַ�����
		cout << "Section Name: ";
		for (int j = 0; j < 8; j++)
		{
			SectionNames[i].resize(NumberOfSections);
			SectionNames[i][j] = SectionHeaders[i].Name[j];
			cout << SectionNames[i][j];
		}
		cout << endl;
		
	}
	
	Assembly(hpFile);	// ��װ�ļ���д��DOSͷ��DOS�����NTͷ�ͽ���ͷ
	



	
	for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++)
	{
		cout << hex << (int)((unsigned char*)&idh)[i] << " ";
	}
	
	*/
	
	return 0;
}