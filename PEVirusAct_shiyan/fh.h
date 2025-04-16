#pragma once            // ��ֹͷ�ļ����ظ�����

#include<iostream>
#include<windows.h>     // Windows APIͷ�ļ�
#include<fileapi.h>     // �ļ�����API
#include<vector>        // STL��������


//FileHeaderTamper : Object
#define DOS_T 1     // DOSͷ�۸�
#define NT_T 2      // NTͷ�۸�

//FileHeaderTamper : DOS - Decision
//#define 

//FileHeaderTamper : NT - Decision
#define e_magic_T 1     // �޸�PEǩ��
#define e_lfanew_T 2    // �޸�ָ��PEͷ��ƫ����

/*
std::string IMAGE_DOS_HEADER_NAME_INFO[] = {
    "e_magic",                     // Magic number
    "e_cblp",                    // Bytes on last page of file
    "e_cp",                        // Pages in file
    "e_crlc",                      // Relocations
    "e_cparhdr",                   // Size of header in paragraphs
    "e_minalloc",                  // Minimum extra paragraphs needed
    "e_maxalloc",                  // Maximum extra paragraphs needed
    "e_ss",                        // Initial (relative) SS value
    "e_sp",                        // Initial SP value
    "e_csum",                      // Checksum
    "e_ip",                        // Initial IP value
    "e_cs",                        // Initial (relative) CS value
    "e_lfarlc",                    // File address of relocation table
    "e_ovno",                      // Overlay number
    "e_res",                    // Reserved words
    "e_oemid",                     // OEM identifier (for e_oeminfo)
    "e_oeminfo",                   // OEM information; e_oemid specific
    "e_res2",                  // Reserved words
    "e_lfanew"
};

int IMAGE_DOS_HEADER_SIZE_INFO[] = {
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,8,2,2,20,4
};


*/


// �ֶ���Ϣ�ṹ��
typedef struct FieldInfo
{
    std::string field;  // �ֶ�����
    int size;           // �ֶδ�С(�ֽ�)

    int offset;         // �ֶ�ƫ����
}FieldInfo;




//std::vector< FieldInfo>IMAGE_DOS_HEADER_INFO;

//std::vector<std::tuple<std::string, int, int>>IMAGE_DOS_HEADER_INFO[19];
//std::vector<std::tuple<std::string, int, int>>IMAGE_NT_HEADER_INFOS[];


// DOS����ṹ�壨64�ֽڣ�
typedef struct IMAGE_DOS_STUB
{
    BYTE stub[64];      // DOS�������
}IMAGE_DOS_STUB;


//RICH_HEADER;
//extern char* stubbuffer;


// �ⲿ��������
extern std::vector<BYTE> stubbuffer;    // DOS���������
extern IMAGE_DOS_HEADER idh;           //DOSͷ����"MZ"��ͷ��
extern IMAGE_NT_HEADERS inh;			//NTͷ��PEǩ�����ļ�ͷ����ѡͷ��

extern WORD NumberOfSections;           // ��������
extern std::vector<IMAGE_SECTION_HEADER> SectionHeaders;    // ����ͷ����
extern std::vector<std::vector<BYTE>>SectionNames;          // ������������
extern std::vector < std::vector<char>>Sections;            // ������������


// ��������
bool FileHeaderTamper();        // �ļ�ͷ�۸ĺ���
bool SectionTamper(HANDLE, LONG, unsigned char*);       // �����۸�
bool TextSectionTamper(HANDLE, unsigned char*, int);    // .text�����۸�
bool EntryPointCover(HANDLE, DWORD);                     // ��ڵ㸲��

bool HeaderInfoIni(std::vector<FieldInfo>);         // ͷ��Ϣ��ʼ��
bool FieldTamper(LONG ,char* );                     // �ֶδ۸�
bool AtomTamper(PVOID , LONG , unsigned char* , int );  //obsolete

bool Assembly(HANDLE);              // �����ع���


extern unsigned char shellcode[];       // �ⲿ�����shellcode����

class PETamper
{
public:
	PETamper();
	~PETamper();
	bool FileHeaderTamper(HANDLE hFile, unsigned char* buffer, int size, int ObjectFlag, int DecisionFlag);
	bool SectionTamper(HANDLE hFile, LONG Point, unsigned char* buffer);
	bool TextSectionTamper(HANDLE hFile, unsigned char* buffer, DWORD EntryPoint);
	bool EntryPointCover(HANDLE hFile, DWORD EntryPoint);
	bool HeaderInfoIni(std::vector<FieldInfo> HEADER_INFO);
	bool FieldTamper(LONG Point, char* buffer);
	bool AtomTamper(PVOID Struct, LONG Point, unsigned char* buffer, int size);  //obsolete
};