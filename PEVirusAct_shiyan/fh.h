#pragma once            // 防止头文件被重复包含

#include<iostream>
#include<windows.h>     // Windows API头文件
#include<fileapi.h>     // 文件操作API
#include<vector>        // STL向量容器


//FileHeaderTamper : Object
#define DOS_T 1     // DOS头篡改
#define NT_T 2      // NT头篡改

//FileHeaderTamper : DOS - Decision
//#define 

//FileHeaderTamper : NT - Decision
#define e_magic_T 1     // 修改PE签名
#define e_lfanew_T 2    // 修改指向PE头的偏移量

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


// 字段信息结构体
typedef struct FieldInfo
{
    std::string field;  // 字段名称
    int size;           // 字段大小(字节)

    int offset;         // 字段偏移量
}FieldInfo;




//std::vector< FieldInfo>IMAGE_DOS_HEADER_INFO;

//std::vector<std::tuple<std::string, int, int>>IMAGE_DOS_HEADER_INFO[19];
//std::vector<std::tuple<std::string, int, int>>IMAGE_NT_HEADER_INFOS[];


// DOS存根结构体（64字节）
typedef struct IMAGE_DOS_STUB
{
    BYTE stub[64];      // DOS存根数据
}IMAGE_DOS_STUB;


//RICH_HEADER;
//extern char* stubbuffer;


// 外部变量声明
extern std::vector<BYTE> stubbuffer;    // DOS存根缓冲区
extern IMAGE_DOS_HEADER idh;           //DOS头（以"MZ"开头）
extern IMAGE_NT_HEADERS inh;			//NT头（PE签名、文件头、可选头）

extern WORD NumberOfSections;           // 节区数量
extern std::vector<IMAGE_SECTION_HEADER> SectionHeaders;    // 节区头向量
extern std::vector<std::vector<BYTE>>SectionNames;          // 节区名称向量
extern std::vector < std::vector<char>>Sections;            // 节区数据向量


// 函数声明
bool FileHeaderTamper();        // 文件头篡改函数
bool SectionTamper(HANDLE, LONG, unsigned char*);       // 节区篡改
bool TextSectionTamper(HANDLE, unsigned char*, int);    // .text节区篡改
bool EntryPointCover(HANDLE, DWORD);                     // 入口点覆盖

bool HeaderInfoIni(std::vector<FieldInfo>);         // 头信息初始化
bool FieldTamper(LONG ,char* );                     // 字段篡改
bool AtomTamper(PVOID , LONG , unsigned char* , int );  //obsolete

bool Assembly(HANDLE);              // 汇编相关功能


extern unsigned char shellcode[];       // 外部定义的shellcode数组

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