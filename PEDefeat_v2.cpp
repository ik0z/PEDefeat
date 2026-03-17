#define NOMINMAX
/*
 * PEDefeat v2.0 — Universal Detection Surface Analyzer & Defeat Engine
 * Author: Khaled M. Alshammri | @ik0z
 * Build: cl /std:c++17 /EHsc /O2 PEDefeat_v2.cpp /Fe:bin\PEDefeat.exe
 * Analyzes: PE(EXE/DLL/SYS), PS1, BAT, VBS, JS, HTA, WSF
 * Auto-detects tools — no manual paths needed.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winnt.h>
#include <imagehlp.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <functional>
#include <memory>
#include <regex>
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"imagehlp.lib")
#pragma comment(lib,"version.lib")
#pragma comment(lib,"advapi32.lib")
namespace fs=std::filesystem;
static const char*VER="2.0";
static const char*AUTHOR="Khaled M. Alshammri | @ik0z";

// ── Enums & Structs ──
enum Sev{S_INFO=0,S_LOW=1,S_MED=2,S_HIGH=3,S_CRIT=4};
static const char*SevStr(Sev s){const char*t[]={"INFO","LOW","MEDIUM","HIGH","CRITICAL"};return t[(int)s];}
static const char*SevClr(Sev s){const char*c[]={"37","36","33","93","91"};return c[(int)s];}
enum FType{FT_UNK=0,FT_PE_EXE,FT_PE_DLL,FT_PE_SYS,FT_PS1,FT_BAT,FT_VBS,FT_JS,FT_HTA,FT_WSF,FT_DOTNET};
static const char*FTStr(FType f){const char*t[]={"Unknown","PE/EXE","PE/DLL","PE/SYS","PowerShell","Batch","VBScript","JScript","HTA","WSF",".NET"};return t[(int)f];}
static bool IsPE(FType f){return f>=FT_PE_EXE&&f<=FT_PE_SYS||f==FT_DOTNET;}
static bool IsScript(FType f){return f>=FT_PS1&&f<=FT_WSF;}

struct Finding{Sev sev;std::string cat,title,detail,fix;int line=0;std::string file,lineText;DWORD foff=0;};
struct Cfg{
    std::string target,outDir,yaraDir,sigmaDir,pesieve,sysDir,plugDir,exeDir;
    Sev minSev=S_INFO;
    bool html=false,txt=true,json=false,dyn=false,amsi=false,defender=false;
    bool verb=false,color=true,quick=false,deep=false;
};
struct PEI{
    std::vector<BYTE>data;std::string path,name;DWORD fsize=0;std::string md5,sha256;FType ftype=FT_UNK;
    IMAGE_DOS_HEADER dos={};bool stub=false;DWORD stubSz=0;
    bool x64=false;IMAGE_NT_HEADERS32 nt32={};IMAGE_NT_HEADERS64 nt64={};
    WORD mach=0,nSec=0,chars=0,dllCh=0,subsys=0;
    DWORD ep=0,imgSz=0,hdrSz=0,ib32=0,chksum=0,calcChk=0,ts=0;ULONGLONG ib64=0;
    struct Sec{IMAGE_SECTION_HEADER h;double ent;bool ex,wr,rd;DWORD raw,virt;std::string nm;};
    std::vector<Sec>secs;
    struct Imp{std::string dll,fn;WORD ord;bool byOrd;};
    std::vector<Imp>imps;std::set<std::string>impDlls;
    struct Exp{std::string nm;WORD ord;DWORD rva;bool fwd;std::string fwNm;};
    std::vector<Exp>exps;std::string expDll;
    bool tls=false;int tlsCb=0;bool dbg=false;std::string pdb;DWORD dbgType=0;
    bool reloc=false;int relocN=0;bool res=false,verInfo=false,manifest=false;
    std::string ver,prod,comp,origFn,intNm,desc;
    bool rich=false;struct RE{WORD pid,bid;DWORD cnt;};std::vector<RE>richE;
    bool overlay=false;DWORD ovOff=0,ovSz=0;
    bool bndImp=false,delImp=false,clr=false,ldCfg=false,seh=false,cfg2=false;
    struct Str{std::string v;DWORD off;bool wide;};std::vector<Str>strs;
    std::vector<std::string>scriptLines;
};

// ── Console ──
static bool g_c=true;
#define CC(x) do{if(g_c)printf("\x1b[" x "m");}while(0)
static void cr(){CC("0");}static void cR(){CC("91");}static void cY(){CC("93");}
static void cG(){CC("92");}static void cC(){CC("96");}static void cW(){CC("97");}
static void cGr(){CC("90");}static void cB(){CC("1");}
static void banner(){
    cC();printf("\n  +===============================================================+\n");
    printf("  |       PEDefeat v2.0 - Universal Defeat Engine                 |\n");
    printf("  |  PE / PS1 / BAT / VBS / JS / HTA  Detection Analyzer         |\n");
    printf("  |       %s                |\n",AUTHOR);
    printf("  +===============================================================+\n");cr();printf("\n");
}
static void psec(const char*t){cW();cB();printf("\n  == %s ",t);for(int i=0;i<(int)(58-strlen(t));i++)printf("=");printf("\n");cr();}
static void pf(const Finding&f){
    printf("  ");if(g_c)printf("\x1b[%sm",SevClr(f.sev));
    printf("[%-8s]",SevStr(f.sev));cr();cW();printf(" %-14s",f.cat.c_str());cr();
    printf(" %s\n",f.title.c_str());
    if(!f.detail.empty()){cGr();printf("               %s\n",f.detail.c_str());cr();}
    if(f.line>0){cGr();printf("               Line %d",f.line);if(!f.file.empty())printf(" in %s",f.file.c_str());printf("\n");cr();}
    if(f.foff>0){cGr();printf("               @ Offset 0x%08X\n",f.foff);cr();}
    if(!f.fix.empty()){cG();printf("               FIX: %s\n",f.fix.c_str());cr();}
    if(!f.lineText.empty()){cGr();printf("               CODE: ");
        std::string lt=f.lineText;size_t fs2=lt.find_first_not_of(" \t");
        if(fs2!=std::string::npos)lt=lt.substr(fs2);if(lt.size()>120)lt=lt.substr(0,117)+"...";
        printf("%s\n",lt.c_str());cr();}
}
static void pinfo(const char*fmt,...){cGr();printf("  [*] ");va_list a;va_start(a,fmt);vprintf(fmt,a);va_end(a);printf("\n");cr();}
static void pok(const char*fmt,...){cG();printf("  [+] ");va_list a;va_start(a,fmt);vprintf(fmt,a);va_end(a);printf("\n");cr();}
static void perr(const char*fmt,...){cR();printf("  [-] ");va_list a;va_start(a,fmt);vprintf(fmt,a);va_end(a);printf("\n");cr();}

// ── Utilities ──
static std::vector<BYTE>ReadAll(const std::string&p){
    std::vector<BYTE>d;HANDLE h=CreateFileA(p.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE)return d;DWORD sz=GetFileSize(h,NULL);
    if(sz==INVALID_FILE_SIZE||!sz){CloseHandle(h);return d;}
    d.resize(sz);DWORD r=0;ReadFile(h,d.data(),sz,&r,NULL);CloseHandle(h);if(r!=sz)d.clear();return d;
}
static double Entropy(const BYTE*d,size_t n){
    if(!n)return 0;DWORD f[256]={};for(size_t i=0;i<n;i++)f[d[i]]++;
    double e=0;for(int i=0;i<256;i++){if(!f[i])continue;double p2=(double)f[i]/(double)n;e-=p2*log2(p2);}return e;
}
static std::string Hex(const BYTE*d,size_t n){std::string h;h.reserve(n*2);for(size_t i=0;i<n;i++){char b[4];sprintf(b,"%02x",d[i]);h+=b;}return h;}
static std::string Lo(const std::string&s){std::string r=s;std::transform(r.begin(),r.end(),r.begin(),::tolower);return r;}
static std::string TSs(DWORD t){time_t tt=(time_t)t;struct tm ti={};gmtime_s(&ti,&tt);char b[64];strftime(b,64,"%Y-%m-%d %H:%M:%S UTC",&ti);return b;}
static std::string Hash(const BYTE*d,DWORD n,ALG_ID a){
    HCRYPTPROV hp=0;HCRYPTHASH hh=0;std::string r;
    if(!CryptAcquireContextA(&hp,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))return r;
    if(CryptCreateHash(hp,a,0,0,&hh)){if(CryptHashData(hh,d,n,0)){
        DWORD hl=0,hs=sizeof(hl);CryptGetHashParam(hh,HP_HASHSIZE,(BYTE*)&hl,&hs,0);
        std::vector<BYTE>hb(hl);if(CryptGetHashParam(hh,HP_HASHVAL,hb.data(),&hl,0))r=Hex(hb.data(),hl);
    }CryptDestroyHash(hh);}CryptReleaseContext(hp,0);return r;
}
static DWORD R2O(const PEI&pe,DWORD rva){
    for(auto&s:pe.secs){DWORD va=s.h.VirtualAddress,rw=s.h.PointerToRawData,sz=s.h.SizeOfRawData;
        if(rva>=va&&rva<va+sz)return rw+(rva-va);}return 0;
}
static std::string RunCmd(const std::string&cmd,int tmo=30000){
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE hR=NULL,hW=NULL;
    if(!CreatePipe(&hR,&hW,&sa,0))return "";SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOA si={sizeof(si)};si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.hStdOutput=hW;si.hStdError=hW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={};std::string c=cmd;
    if(!CreateProcessA(NULL,&c[0],NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){CloseHandle(hR);CloseHandle(hW);return "";}
    CloseHandle(hW);std::string out;char buf[4096];DWORD br;
    while(ReadFile(hR,buf,sizeof(buf)-1,&br,NULL)&&br>0){buf[br]=0;out+=buf;}
    WaitForSingleObject(pi.hProcess,tmo);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);CloseHandle(hR);return out;
}
static std::string GetExeDir(){char b[MAX_PATH]={};GetModuleFileNameA(NULL,b,MAX_PATH);return fs::path(b).parent_path().string();}

// ── Auto-Detection ──
static std::string FindTool(const std::string&name,const Cfg&cfg,const std::string&sub=""){
    std::vector<std::string>sp;std::string td=fs::path(cfg.target).parent_path().string();
    std::string pd=fs::path(cfg.exeDir).parent_path().string();
    if(!sub.empty()){sp.push_back(cfg.exeDir+"\\tools\\"+sub+"\\"+name);sp.push_back(td+"\\tools\\"+sub+"\\"+name);sp.push_back(pd+"\\tools\\"+sub+"\\"+name);}
    sp.push_back(cfg.exeDir+"\\tools\\"+name);sp.push_back(cfg.exeDir+"\\"+name);sp.push_back(cfg.exeDir+"\\bin\\"+name);
    sp.push_back(td+"\\"+name);sp.push_back(pd+"\\tools\\"+name);sp.push_back(pd+"\\bin\\"+name);
    for(auto&p:sp)if(fs::exists(p))return p;
    std::string w=RunCmd("where "+name,5000);
    if(!w.empty()){size_t nl=w.find_first_of("\r\n");if(nl!=std::string::npos)w=w.substr(0,nl);if(fs::exists(w))return w;}
    return "";
}
static std::string FindDir(const std::string&dn,const Cfg&cfg){
    std::vector<std::string>sp;std::string td=fs::path(cfg.target).parent_path().string();
    std::string pd=fs::path(cfg.exeDir).parent_path().string();
    for(auto&base:{cfg.exeDir,td,pd}){sp.push_back(base+"\\tools\\"+dn);sp.push_back(base+"\\"+dn);sp.push_back(base+"\\rules\\"+dn);}
    for(auto&p:sp)if(fs::exists(p)&&fs::is_directory(p))return p;
    return "";
}

// ── File Type ──
static FType DetectType(const std::string&path,const std::vector<BYTE>&data){
    std::string ext=Lo(fs::path(path).extension().string());
    if(ext==".ps1"||ext==".psm1"||ext==".psd1")return FT_PS1;
    if(ext==".bat"||ext==".cmd")return FT_BAT;
    if(ext==".vbs"||ext==".vbe")return FT_VBS;
    if(ext==".js"||ext==".jse")return FT_JS;
    if(ext==".hta")return FT_HTA;if(ext==".wsf")return FT_WSF;
    if(data.size()>=64&&data[0]==0x4D&&data[1]==0x5A){
        DWORD po=*(DWORD*)(data.data()+0x3C);
        if(po+4<=data.size()&&*(DWORD*)(data.data()+po)==IMAGE_NT_SIGNATURE){
            IMAGE_FILE_HEADER*fh=(IMAGE_FILE_HEADER*)(data.data()+po+4);
            WORD om=*(WORD*)(data.data()+po+4+sizeof(IMAGE_FILE_HEADER));DWORD clr=0;
            if(om==IMAGE_NT_OPTIONAL_HDR64_MAGIC&&po+sizeof(IMAGE_NT_HEADERS64)<=data.size()){
                auto*nt=(IMAGE_NT_HEADERS64*)(data.data()+po);if(nt->OptionalHeader.NumberOfRvaAndSizes>14)clr=nt->OptionalHeader.DataDirectory[14].VirtualAddress;
            }else if(po+sizeof(IMAGE_NT_HEADERS32)<=data.size()){
                auto*nt=(IMAGE_NT_HEADERS32*)(data.data()+po);if(nt->OptionalHeader.NumberOfRvaAndSizes>14)clr=nt->OptionalHeader.DataDirectory[14].VirtualAddress;}
            if(clr)return FT_DOTNET;if(fh->Characteristics&IMAGE_FILE_DLL)return FT_PE_DLL;if(ext==".sys")return FT_PE_SYS;return FT_PE_EXE;}}
    if(data.size()>10){std::string h((char*)data.data(),std::min((size_t)500,data.size()));std::string lh=Lo(h);
        if(lh.find("param(")!=std::string::npos||lh.find("function ")!=std::string::npos)return FT_PS1;
        if(lh.find("@echo")!=std::string::npos)return FT_BAT;
        if(lh.find("createobject")!=std::string::npos)return FT_VBS;if(lh.find("<hta:")!=std::string::npos)return FT_HTA;}
    return FT_UNK;
}

// ════════════════════════════════════════════════════════════════
// PE PARSER
// ════════════════════════════════════════════════════════════════
static bool ParsePE(PEI&pe){
    if(pe.data.size()<sizeof(IMAGE_DOS_HEADER))return false;
    memcpy(&pe.dos,pe.data.data(),sizeof(IMAGE_DOS_HEADER));
    if(pe.dos.e_magic!=IMAGE_DOS_SIGNATURE)return false;
    DWORD po=pe.dos.e_lfanew;if(!po||po>pe.data.size()-4)return false;
    if(*(DWORD*)(pe.data.data()+po)!=IMAGE_NT_SIGNATURE)return false;
    pe.stub=(po>sizeof(IMAGE_DOS_HEADER));pe.stubSz=pe.stub?po-(DWORD)sizeof(IMAGE_DOS_HEADER):0;
    IMAGE_FILE_HEADER*fh=(IMAGE_FILE_HEADER*)(pe.data.data()+po+4);
    pe.mach=fh->Machine;pe.nSec=fh->NumberOfSections;pe.ts=fh->TimeDateStamp;pe.chars=fh->Characteristics;
    WORD om=*(WORD*)(pe.data.data()+po+4+sizeof(IMAGE_FILE_HEADER));pe.x64=(om==IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if(pe.x64){if(po+sizeof(IMAGE_NT_HEADERS64)>pe.data.size())return false;
        memcpy(&pe.nt64,pe.data.data()+po,sizeof(IMAGE_NT_HEADERS64));
        pe.ep=pe.nt64.OptionalHeader.AddressOfEntryPoint;pe.ib64=pe.nt64.OptionalHeader.ImageBase;
        pe.imgSz=pe.nt64.OptionalHeader.SizeOfImage;pe.hdrSz=pe.nt64.OptionalHeader.SizeOfHeaders;
        pe.dllCh=pe.nt64.OptionalHeader.DllCharacteristics;pe.subsys=pe.nt64.OptionalHeader.Subsystem;pe.chksum=pe.nt64.OptionalHeader.CheckSum;
    }else{if(po+sizeof(IMAGE_NT_HEADERS32)>pe.data.size())return false;
        memcpy(&pe.nt32,pe.data.data()+po,sizeof(IMAGE_NT_HEADERS32));
        pe.ep=pe.nt32.OptionalHeader.AddressOfEntryPoint;pe.ib32=pe.nt32.OptionalHeader.ImageBase;
        pe.imgSz=pe.nt32.OptionalHeader.SizeOfImage;pe.hdrSz=pe.nt32.OptionalHeader.SizeOfHeaders;
        pe.dllCh=pe.nt32.OptionalHeader.DllCharacteristics;pe.subsys=pe.nt32.OptionalHeader.Subsystem;pe.chksum=pe.nt32.OptionalHeader.CheckSum;}
    {DWORD hs=0,cs=0;CheckSumMappedFile(pe.data.data(),pe.fsize,&hs,&cs);pe.calcChk=cs;}
    DWORD so=po+4+sizeof(IMAGE_FILE_HEADER)+fh->SizeOfOptionalHeader;
    for(WORD i=0;i<pe.nSec;i++){if(so+sizeof(IMAGE_SECTION_HEADER)>pe.data.size())break;
        PEI::Sec s={};memcpy(&s.h,pe.data.data()+so,sizeof(IMAGE_SECTION_HEADER));
        char nm[9]={};memcpy(nm,s.h.Name,8);s.nm=nm;s.raw=s.h.SizeOfRawData;s.virt=s.h.Misc.VirtualSize;
        s.ex=(s.h.Characteristics&IMAGE_SCN_MEM_EXECUTE)!=0;s.wr=(s.h.Characteristics&IMAGE_SCN_MEM_WRITE)!=0;s.rd=(s.h.Characteristics&IMAGE_SCN_MEM_READ)!=0;
        if(s.raw>0&&s.h.PointerToRawData+s.raw<=pe.data.size())s.ent=Entropy(pe.data.data()+s.h.PointerToRawData,s.raw);
        pe.secs.push_back(s);so+=sizeof(IMAGE_SECTION_HEADER);}
    if(!pe.secs.empty()){DWORD last=0;for(auto&s:pe.secs){DWORD e=s.h.PointerToRawData+s.raw;if(e>last)last=e;}
        if(last<pe.fsize){pe.overlay=true;pe.ovOff=last;pe.ovSz=pe.fsize-last;}}
    {const BYTE*b=pe.data.data();
    for(DWORD i=0x80;i+4<po;i+=4){if(*(DWORD*)(b+i)==0x68636952){DWORD xk=*(DWORD*)(b+i+4);
        for(DWORD j=0x80;j<i;j+=4){if((*(DWORD*)(b+j)^xk)==0x536E6144){pe.rich=true;
            for(DWORD k=j+16;k+8<=i;k+=8){DWORD v1=*(DWORD*)(b+k)^xk,v2=*(DWORD*)(b+k+4)^xk;
                PEI::RE re;re.bid=(WORD)(v1&0xFFFF);re.pid=(WORD)(v1>>16);re.cnt=v2;
                if(re.pid||re.bid||re.cnt)pe.richE.push_back(re);}break;}}break;}}}
    return true;
}
static void ParseImps(PEI&pe){
    DWORD ir=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>1)ir=pe.nt64.OptionalHeader.DataDirectory[1].VirtualAddress;}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>1)ir=pe.nt32.OptionalHeader.DataDirectory[1].VirtualAddress;}
    if(!ir)return;DWORD io=R2O(pe,ir);if(!io)return;
    const BYTE*b=pe.data.data();DWORD fs2=(DWORD)pe.data.size();
    while(io+sizeof(IMAGE_IMPORT_DESCRIPTOR)<=fs2){
        IMAGE_IMPORT_DESCRIPTOR*id=(IMAGE_IMPORT_DESCRIPTOR*)(b+io);
        if(!id->Name&&!id->FirstThunk)break;
        DWORD no=R2O(pe,id->Name);if(!no||no>=fs2){io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);continue;}
        std::string dll=(const char*)(b+no);pe.impDlls.insert(Lo(dll));
        DWORD tr=id->OriginalFirstThunk?id->OriginalFirstThunk:id->FirstThunk;
        DWORD to2=R2O(pe,tr);if(!to2){io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);continue;}
        if(pe.x64){while(to2+8<=fs2){ULONGLONG tv=*(ULONGLONG*)(b+to2);if(!tv)break;
            PEI::Imp e;e.dll=dll;if(tv&0x8000000000000000ULL){e.byOrd=true;e.ord=(WORD)(tv&0xFFFF);}
            else{e.byOrd=false;DWORD ho=R2O(pe,(DWORD)(tv&0x7FFFFFFF));if(ho&&ho+2<fs2)e.fn=(const char*)(b+ho+2);}
            pe.imps.push_back(e);to2+=8;}}
        else{while(to2+4<=fs2){DWORD tv=*(DWORD*)(b+to2);if(!tv)break;
            PEI::Imp e;e.dll=dll;if(tv&0x80000000){e.byOrd=true;e.ord=(WORD)(tv&0xFFFF);}
            else{e.byOrd=false;DWORD ho=R2O(pe,tv);if(ho&&ho+2<fs2)e.fn=(const char*)(b+ho+2);}
            pe.imps.push_back(e);to2+=4;}}
        io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);}
}
static void ParseExps(PEI&pe){
    DWORD er=0,es=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>0){er=pe.nt64.OptionalHeader.DataDirectory[0].VirtualAddress;es=pe.nt64.OptionalHeader.DataDirectory[0].Size;}}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>0){er=pe.nt32.OptionalHeader.DataDirectory[0].VirtualAddress;es=pe.nt32.OptionalHeader.DataDirectory[0].Size;}}
    if(!er)return;DWORD eo=R2O(pe,er);if(!eo||eo+sizeof(IMAGE_EXPORT_DIRECTORY)>pe.data.size())return;
    IMAGE_EXPORT_DIRECTORY*ed=(IMAGE_EXPORT_DIRECTORY*)(pe.data.data()+eo);
    DWORD no=R2O(pe,ed->Name);if(no&&no<pe.data.size())pe.expDll=(const char*)(pe.data.data()+no);
    DWORD fo=R2O(pe,ed->AddressOfFunctions),nto=R2O(pe,ed->AddressOfNames),oto=R2O(pe,ed->AddressOfNameOrdinals);
    if(!fo)return;
    for(DWORD i=0;i<ed->NumberOfNames&&nto;i++){
        if(nto+i*4+4>pe.data.size())break;DWORD nr=*(DWORD*)(pe.data.data()+nto+i*4);DWORD n2=R2O(pe,nr);
        PEI::Exp e;if(n2&&n2<pe.data.size())e.nm=(const char*)(pe.data.data()+n2);
        if(oto&&oto+i*2+2<=pe.data.size()){WORD oi=*(WORD*)(pe.data.data()+oto+i*2);e.ord=oi+(WORD)ed->Base;
            if(fo+oi*4+4<=pe.data.size()){DWORD fr=*(DWORD*)(pe.data.data()+fo+oi*4);e.rva=fr;
                if(fr>=er&&fr<er+es){e.fwd=true;DWORD f2=R2O(pe,fr);if(f2&&f2<pe.data.size())e.fwNm=(const char*)(pe.data.data()+f2);}}}
        pe.exps.push_back(e);}
}
static void ParseTLS(PEI&pe){
    DWORD r=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>9)r=pe.nt64.OptionalHeader.DataDirectory[9].VirtualAddress;}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>9)r=pe.nt32.OptionalHeader.DataDirectory[9].VirtualAddress;}
    if(!r)return;pe.tls=true;DWORD o=R2O(pe,r);if(!o)return;
    if(pe.x64){if(o+sizeof(IMAGE_TLS_DIRECTORY64)>pe.data.size())return;
        auto*t=(IMAGE_TLS_DIRECTORY64*)(pe.data.data()+o);
        if(t->AddressOfCallBacks){DWORD co=R2O(pe,(DWORD)(t->AddressOfCallBacks-pe.ib64));
            if(co){while(co+8<=pe.data.size()){if(!*(ULONGLONG*)(pe.data.data()+co))break;pe.tlsCb++;co+=8;}}}}
    else{if(o+sizeof(IMAGE_TLS_DIRECTORY32)>pe.data.size())return;
        auto*t=(IMAGE_TLS_DIRECTORY32*)(pe.data.data()+o);
        if(t->AddressOfCallBacks){DWORD co=R2O(pe,t->AddressOfCallBacks-pe.ib32);
            if(co){while(co+4<=pe.data.size()){if(!*(DWORD*)(pe.data.data()+co))break;pe.tlsCb++;co+=4;}}}}
}
static void ParseDbg(PEI&pe){
    DWORD r=0,sz=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>6){r=pe.nt64.OptionalHeader.DataDirectory[6].VirtualAddress;sz=pe.nt64.OptionalHeader.DataDirectory[6].Size;}}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>6){r=pe.nt32.OptionalHeader.DataDirectory[6].VirtualAddress;sz=pe.nt32.OptionalHeader.DataDirectory[6].Size;}}
    if(!r)return;DWORD o=R2O(pe,r);if(!o)return;int n=(int)(sz/sizeof(IMAGE_DEBUG_DIRECTORY));
    for(int i=0;i<n;i++){DWORD eo=o+i*sizeof(IMAGE_DEBUG_DIRECTORY);if(eo+sizeof(IMAGE_DEBUG_DIRECTORY)>pe.data.size())break;
        auto*dd=(IMAGE_DEBUG_DIRECTORY*)(pe.data.data()+eo);pe.dbg=true;pe.dbgType=dd->Type;
        if(dd->Type==IMAGE_DEBUG_TYPE_CODEVIEW&&dd->PointerToRawData>0){DWORD co=dd->PointerToRawData;
            if(co+4<=pe.data.size()&&*(DWORD*)(pe.data.data()+co)==0x53445352&&co+24<pe.data.size())pe.pdb=(const char*)(pe.data.data()+co+24);}}
}
static void ParseReloc(PEI&pe){
    DWORD r=0,sz=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>5){r=pe.nt64.OptionalHeader.DataDirectory[5].VirtualAddress;sz=pe.nt64.OptionalHeader.DataDirectory[5].Size;}}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>5){r=pe.nt32.OptionalHeader.DataDirectory[5].VirtualAddress;sz=pe.nt32.OptionalHeader.DataDirectory[5].Size;}}
    if(!r)return;pe.reloc=true;DWORD o=R2O(pe,r);if(!o)return;
    DWORD p=0;while(p<sz){if(o+p+8>pe.data.size())break;auto*bl=(IMAGE_BASE_RELOCATION*)(pe.data.data()+o+p);if(!bl->SizeOfBlock)break;pe.relocN+=(bl->SizeOfBlock-8)/2;p+=bl->SizeOfBlock;}
}
static void ParseDD(PEI&pe){
    auto chk=[&](int i)->bool{if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>(DWORD)i)return pe.nt64.OptionalHeader.DataDirectory[i].VirtualAddress!=0;}
        else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>(DWORD)i)return pe.nt32.OptionalHeader.DataDirectory[i].VirtualAddress!=0;}return false;};
    pe.bndImp=chk(11);pe.delImp=chk(13);pe.clr=chk(14);pe.ldCfg=chk(10);pe.res=chk(2);
    pe.seh=(pe.dllCh&IMAGE_DLLCHARACTERISTICS_NO_SEH)==0;
    if(pe.ldCfg){DWORD lr=pe.x64?pe.nt64.OptionalHeader.DataDirectory[10].VirtualAddress:pe.nt32.OptionalHeader.DataDirectory[10].VirtualAddress;
        DWORD lo=R2O(pe,lr);if(lo&&pe.x64&&lo+sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)<=pe.data.size()){
            auto*lc=(IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe.data.data()+lo);pe.cfg2=(lc->GuardFlags&IMAGE_GUARD_CF_INSTRUMENTED)!=0;}}
}
static void ExtStrs(PEI&pe,int ml=5){
    const BYTE*d=pe.data.data();DWORD sz=pe.fsize;std::string cur;DWORD soff=0;
    for(DWORD i=0;i<sz;i++){char c=(char)d[i];
        if(c>=0x20&&c<=0x7E){if(cur.empty())soff=i;cur+=c;}
        else{if((int)cur.size()>=ml)pe.strs.push_back({cur,soff,false});cur.clear();}}
    if((int)cur.size()>=ml)pe.strs.push_back({cur,soff,false});
    std::string ws;soff=0;
    for(DWORD i=0;i+1<sz;i+=2){wchar_t w=*(wchar_t*)(d+i);
        if(w>=0x20&&w<=0x7E){if(ws.empty())soff=i;ws+=(char)w;}
        else{if((int)ws.size()>=ml)pe.strs.push_back({ws,soff,true});ws.clear();}}
    if((int)ws.size()>=ml)pe.strs.push_back({ws,soff,true});
}
static void ParseVer(PEI&pe){
    DWORD isz=GetFileVersionInfoSizeA(pe.path.c_str(),NULL);if(!isz)return;
    std::vector<BYTE>vb(isz);if(!GetFileVersionInfoA(pe.path.c_str(),0,isz,vb.data()))return;
    pe.verInfo=true;VS_FIXEDFILEINFO*fi=NULL;UINT fl=0;
    if(VerQueryValueA(vb.data(),"\\",(LPVOID*)&fi,&fl)&&fi){char b[64];sprintf(b,"%d.%d.%d.%d",HIWORD(fi->dwFileVersionMS),LOWORD(fi->dwFileVersionMS),HIWORD(fi->dwFileVersionLS),LOWORD(fi->dwFileVersionLS));pe.ver=b;}
    struct{const char*n;std::string*t;}flds[]={{"ProductName",&pe.prod},{"CompanyName",&pe.comp},{"OriginalFilename",&pe.origFn},{"InternalName",&pe.intNm},{"FileDescription",&pe.desc}};
    DWORD*lp=NULL;UINT ll=0;
    if(VerQueryValueA(vb.data(),"\\VarFileInfo\\Translation",(LPVOID*)&lp,&ll)&&ll>=4){WORD lg=LOWORD(*lp),cp=HIWORD(*lp);
        for(auto&f:flds){char p[256];sprintf(p,"\\StringFileInfo\\%04x%04x\\%s",lg,cp,f.n);char*v=NULL;UINT vl=0;if(VerQueryValueA(vb.data(),p,(LPVOID*)&v,&vl)&&v&&vl>0)*f.t=std::string(v,vl-1);}}
    HMODULE hm=LoadLibraryExA(pe.path.c_str(),NULL,LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if(hm){HRSRC hr=FindResourceA(hm,MAKEINTRESOURCEA(1),RT_MANIFEST);if(!hr)hr=FindResourceA(hm,MAKEINTRESOURCEA(2),RT_MANIFEST);pe.manifest=(hr!=NULL);FreeLibrary(hm);}
}

// ════════════════════════════════════════════════════════════════
// SIGNATURE DATABASES
// ════════════════════════════════════════════════════════════════
struct SA{const char*n,*c;Sev s;const char*r;};
static const SA g_api[]={
    {"VirtualAllocEx","inject",S_HIGH,"Remote memory allocation — process injection"},
    {"WriteProcessMemory","inject",S_HIGH,"Remote memory write — writes payload into target"},
    {"NtWriteVirtualMemory","inject",S_HIGH,"Native remote write — bypasses hooks"},
    {"CreateRemoteThread","inject",S_CRIT,"Remote thread — classic injection technique"},
    {"CreateRemoteThreadEx","inject",S_CRIT,"Extended remote thread creation"},
    {"NtCreateThreadEx","inject",S_CRIT,"Native thread creation — bypasses hooks"},
    {"QueueUserAPC","inject",S_HIGH,"APC injection — queues code in target thread"},
    {"NtQueueApcThread","inject",S_HIGH,"Native APC queue"},
    {"NtQueueApcThreadEx","inject",S_CRIT,"Special APC — early bird injection"},
    {"RtlCreateUserThread","inject",S_HIGH,"Undocumented thread creation"},
    {"SetThreadContext","inject",S_HIGH,"Thread hijacking via context manipulation"},
    {"NtSetContextThread","inject",S_HIGH,"Native thread context set"},
    {"VirtualProtect","memory",S_MED,"Memory protection change"},
    {"VirtualProtectEx","memory",S_HIGH,"Remote memory protection change"},
    {"NtProtectVirtualMemory","memory",S_HIGH,"Native memory protection — syscall"},
    {"NtAllocateVirtualMemory","memory",S_MED,"Native memory allocation"},
    {"NtMapViewOfSection","memory",S_HIGH,"Section mapping — hollowing technique"},
    {"NtUnmapViewOfSection","memory",S_HIGH,"Section unmapping — hollowing"},
    {"NtCreateSection","memory",S_MED,"Section object creation"},
    {"OpenProcess","process",S_MED,"Opens handle to another process"},
    {"CreateProcessInternalW","process",S_HIGH,"Internal undocumented process creation"},
    {"TerminateProcess","process",S_MED,"Process termination"},
    {"GetProcAddress","dynapi",S_MED,"Dynamic API resolution at runtime"},
    {"LoadLibraryA","dynapi",S_MED,"Dynamic DLL loading"},
    {"LoadLibraryW","dynapi",S_MED,"Dynamic DLL loading (wide)"},
    {"LoadLibraryExA","dynapi",S_MED,"Extended DLL loading"},
    {"LdrLoadDll","dynapi",S_HIGH,"Native DLL loader — bypasses hooks"},
    {"LdrGetProcedureAddress","dynapi",S_HIGH,"Native API resolver"},
    {"IsDebuggerPresent","antidebug",S_MED,"Debugger presence check"},
    {"CheckRemoteDebuggerPresent","antidebug",S_HIGH,"Remote debugger check"},
    {"NtQueryInformationProcess","antidebug",S_HIGH,"Process info query — anti-debug"},
    {"NtSetInformationThread","antidebug",S_HIGH,"Thread info hide from debugger"},
    {"NtQuerySystemInformation","antidebug",S_MED,"System info — sandbox detection"},
    {"CredEnumerateA","creds",S_HIGH,"Credential enumeration"},
    {"LsaEnumerateLogonSessions","creds",S_CRIT,"Logon session enum — cred theft"},
    {"LsaGetLogonSessionData","creds",S_CRIT,"Logon session data extraction"},
    {"SamConnect","creds",S_CRIT,"SAM database connection"},
    {"MiniDumpWriteDump","creds",S_CRIT,"Process minidump — LSASS dumping"},
    {"OpenProcessToken","token",S_MED,"Token access — privilege inspection"},
    {"AdjustTokenPrivileges","token",S_HIGH,"Privilege escalation"},
    {"ImpersonateLoggedOnUser","token",S_HIGH,"User impersonation"},
    {"DuplicateTokenEx","token",S_HIGH,"Token duplication"},
    {"SetThreadToken","token",S_HIGH,"Thread token manipulation"},
    {"CreateProcessWithTokenW","token",S_HIGH,"Process with stolen token"},
    {"AmsiScanBuffer","evasion",S_CRIT,"AMSI scan — bypass target"},
    {"AmsiScanString","evasion",S_CRIT,"AMSI scan string"},
    {"AmsiInitialize","evasion",S_HIGH,"AMSI initialization"},
    {"EtwEventWrite","evasion",S_CRIT,"ETW event — bypass target"},
    {"NtTraceEvent","evasion",S_HIGH,"Native ETW trace"},
    {"SetFileInformationByHandle","fileio",S_MED,"File info set — self-delete"},
    {"URLDownloadToFileA","network",S_HIGH,"Direct URL download"},
    {"InternetOpenA","network",S_MED,"Internet session init"},
    {"WinHttpOpen","network",S_MED,"WinHTTP session"},
    {"HttpSendRequestA","network",S_MED,"HTTP request"},
    {"WSAStartup","network",S_LOW,"Winsock init"},
    {"NtContinue","shellcode",S_HIGH,"Exec flow redirect"},
    {"NtTestAlert","shellcode",S_HIGH,"APC flush — triggers queued APCs"},
    {"RegSetValueExA","registry",S_MED,"Registry write — persistence/config"},
    {"BCryptEncrypt","crypto",S_LOW,"BCrypt encryption"},
    {"CryptEncrypt","crypto",S_LOW,"Legacy encryption"},
    {"CreateServiceA","service",S_HIGH,"Service creation — persistence"},
    {NULL,NULL,S_INFO,NULL}
};
struct SD{const char*d;Sev s;const char*r;};
static const SD g_dll[]={
    {"ntdll.dll",S_LOW,"Direct ntdll — native API"},{"winhttp.dll",S_LOW,"HTTP comms"},
    {"wininet.dll",S_LOW,"Internet access"},{"ws2_32.dll",S_LOW,"Winsock — raw net"},
    {"crypt32.dll",S_LOW,"Cryptography"},{"bcrypt.dll",S_LOW,"BCrypt crypto"},
    {"dbghelp.dll",S_HIGH,"Debug helper — MiniDump (LSASS)"},
    {"samlib.dll",S_CRIT,"SAM library — cred extraction"},
    {"vaultcli.dll",S_HIGH,"Credential vault"},
    {"amsi.dll",S_CRIT,"AMSI — loaded for bypass patching"},
    {"wldp.dll",S_HIGH,"Windows Lockdown Policy"},
    {"psapi.dll",S_MED,"Process enumeration"},{"secur32.dll",S_MED,"Auth"},
    {"taskschd.dll",S_MED,"Task scheduler — persistence"},
    {NULL,S_INFO,NULL}
};
struct SS{const char*p,*c;Sev s;const char*d;bool cs;};
static const SS g_str[]={
    {"AmsiScanBuffer","evasion",S_CRIT,"AMSI scan function — patch target",true},
    {"AmsiScanString","evasion",S_CRIT,"AMSI scan string in binary",true},
    {"EtwEventWrite","evasion",S_CRIT,"ETW event write — patch target",true},
    {"amsi.dll","evasion",S_CRIT,"AMSI DLL name string",false},
    {"Authorization: Bearer","c2",S_HIGH,"Bearer auth — C2 comms",false},
    {"api.notion.com","c2",S_CRIT,"Notion API — C2 channel",false},
    {"discord.com/api","c2",S_HIGH,"Discord API — C2",false},
    {"graph.microsoft.com","c2",S_HIGH,"MS Graph — C2",false},
    {"api.telegram.org","c2",S_HIGH,"Telegram — C2",false},
    {"slack.com/api","c2",S_HIGH,"Slack — C2",false},
    {"pastebin.com","c2",S_HIGH,"Pastebin — payload hosting",false},
    {"ngrok.io","c2",S_HIGH,"Ngrok tunnel — C2",false},
    {"-----BEGIN RSA","crypto",S_HIGH,"RSA private key embedded",false},
    {"-----BEGIN PUBLIC","crypto",S_HIGH,"Public key embedded",false},
    {"bitcoin","ransom",S_HIGH,"Bitcoin — ransom indicator",false},
    {"monero","ransom",S_HIGH,"Monero — ransom indicator",false},
    {"YOUR FILES","ransom",S_HIGH,"Ransom note pattern",false},
    {".onion","ransom",S_HIGH,"TOR address — ransom/C2",false},
    {"cmd.exe /c","shell",S_HIGH,"Command execution via cmd",false},
    {"powershell","shell",S_HIGH,"PowerShell invocation",false},
    {"vssadmin","shell",S_CRIT,"VSS admin — shadow copy manip",false},
    {"bcdedit","shell",S_HIGH,"Boot config — recovery disable",false},
    {"wmic shadowcopy","shell",S_CRIT,"Shadow copy deletion",false},
    {"schtasks /create","shell",S_HIGH,"Scheduled task — persistence",false},
    {"wbadmin delete","shell",S_HIGH,"Backup deletion",false},
    {"netsh advfirewall","shell",S_HIGH,"Firewall manipulation",false},
    {"wevtutil cl","shell",S_CRIT,"Event log clear — anti-forensics",false},
    {"mimikatz","tool",S_CRIT,"Mimikatz credential tool",false},
    {"cobalt","tool",S_HIGH,"Cobalt Strike indicator",false},
    {"meterpreter","tool",S_CRIT,"Metasploit Meterpreter",false},
    {"Rubeus","tool",S_CRIT,"Rubeus Kerberos tool",true},
    {"SharpHound","tool",S_CRIT,"BloodHound collector",true},
    {"ReflectiveLoader","tool",S_CRIT,"Reflective DLL loader",true},
    {"Invoke-Mimikatz","tool",S_CRIT,"PowerShell Mimikatz",false},
    {"SafetyKatz","tool",S_CRIT,"SafetyKatz tool",true},
    {"Seatbelt","tool",S_CRIT,"Seatbelt enumeration",true},
    {"IsDebuggerPresent","antidbg",S_MED,"Anti-debug API string",true},
    {"NtQueryInformationProcess","antidbg",S_HIGH,"Native anti-debug string",true},
    {"SbieDll.dll","sandbox",S_HIGH,"Sandboxie detection",false},
    {"vmware","antivm",S_MED,"VMware detection",false},
    {"VBoxService","antivm",S_MED,"VirtualBox detection",false},
    {"cuckoomon","antivm",S_HIGH,"Cuckoo sandbox detection",false},
    {"lsass.exe","cred",S_CRIT,"LSASS process — cred target",false},
    {"sekurlsa","cred",S_CRIT,"Mimikatz sekurlsa module",false},
    {"SAM\\Domains","cred",S_CRIT,"SAM registry path",false},
    {"fodhelper","uac",S_HIGH,"UAC bypass — fodhelper",false},
    {"DelegateExecute","uac",S_HIGH,"UAC DelegateExecute",true},
    {"CMSTPLUA","uac",S_HIGH,"CMSTPLUA COM elevation",true},
    {"CurrentVersion\\Run","persist",S_HIGH,"Run key persistence",false},
    {"AppInit_DLLs","persist",S_HIGH,"AppInit DLL injection",false},
    {"Image File Execution","persist",S_HIGH,"IFEO persistence",false},
    {"certutil","lolbin",S_HIGH,"Certutil LOLBin",false},
    {"bitsadmin","lolbin",S_HIGH,"BITSAdmin LOLBin",false},
    {NULL,NULL,S_INFO,NULL,false}
};
struct PK{const char*n,*s,*d;};
static const PK g_pk[]={
    {"UPX","UPX0","UPX packer"},{"UPX","UPX1","UPX packer"},
    {"ASPack",".aspack","ASPack"},{"Themida",".themida","Themida"},
    {"VMProtect",".vmp0","VMProtect"},{"VMProtect",".vmp1","VMProtect"},
    {"Enigma",".enigma1","Enigma"},{"Obsidium",".obsidium","Obsidium"},
    {"MPRESS",".MPRESS1","MPRESS"},{"MPRESS",".MPRESS2","MPRESS"},
    {"PEtite",".petite","PEtite"},{"PECompact","PEC2","PECompact"},{NULL,NULL,NULL}
};
// Script signatures
struct ScSig{const char*pat,*cat;Sev sev;const char*desc,*fix;bool cs;};
static const ScSig g_sc[]={
    {"[Ref].Assembly.GetType","amsi",S_CRIT,"AMSI bypass via .NET reflection","Obfuscate/split string",false},
    {"System.Management.Automation.AmsiUtils","amsi",S_CRIT,"AMSI Utils class reference","Split/encrypt string",false},
    {"amsiInitFailed","amsi",S_CRIT,"AMSI init fail variable — classic bypass","Rename variable",false},
    {"AmsiScanBuffer","amsi",S_CRIT,"AMSI scan buffer function","Resolve dynamically or encrypt",true},
    {"AmsiScanString","amsi",S_CRIT,"AMSI scan string function","Resolve dynamically",true},
    {"amsi.dll","amsi",S_CRIT,"AMSI DLL name in script","Encrypt/split string",false},
    {"Set-MpPreference","amsi",S_CRIT,"Defender preference modification","Obfuscate cmdlet",false},
    {"DisableRealtimeMonitoring","amsi",S_CRIT,"Disables Defender realtime","Obfuscate",false},
    {"Add-MpPreference","amsi",S_HIGH,"Defender exclusion","Obfuscate cmdlet",false},
    {"EtwEventWrite","etw",S_CRIT,"ETW event write — EDR target","Resolve dynamically",true},
    {"NtTraceEvent","etw",S_HIGH,"Native ETW trace","Resolve dynamically",true},
    {"Invoke-Expression","execution",S_HIGH,"Dynamic code execution (IEX)","Avoid direct IEX",false},
    {"New-Object System.Net.WebClient","execution",S_HIGH,"Web client download","Use alternative",false},
    {"DownloadString","execution",S_HIGH,"Download+execute pattern","Stage differently",false},
    {"DownloadFile","execution",S_MED,"File download","Review necessity",false},
    {"Net.Sockets.TCPClient","execution",S_HIGH,"TCP client — reverse shell","Encrypt comms",false},
    {"[System.Convert]::FromBase64String","execution",S_HIGH,"Base64 decode — payload","Review content",false},
    {"Add-Type -TypeDefinition","execution",S_HIGH,"Inline C# compilation","Review code",false},
    {"[DllImport","execution",S_HIGH,"P/Invoke in script","Review imports",false},
    {"-EncodedCommand","evasion",S_HIGH,"Encoded command — obfuscation","Use clear text",false},
    {"-Exec Bypass","evasion",S_HIGH,"Execution policy bypass","Review necessity",false},
    {"-WindowStyle Hidden","evasion",S_HIGH,"Hidden window execution","Review necessity",false},
    {"[System.Runtime.InteropServices.Marshal]","evasion",S_HIGH,"Marshal — memory ops","Review operations",false},
    {"VirtualAlloc","evasion",S_CRIT,"Memory alloc in script — shellcode","Review code",false},
    {"VirtualProtect","evasion",S_CRIT,"Mem protection in script","Review code",false},
    {"CreateThread","evasion",S_CRIT,"Thread creation in script","Review code",false},
    {"[Byte[]]","evasion",S_HIGH,"Byte array — shellcode pattern","Review content",false},
    {"0x4d,0x5a","evasion",S_CRIT,"MZ header bytes — embedded PE","Encrypt payload",false},
    {"sekurlsa","cred",S_CRIT,"Mimikatz module reference","Remove or encrypt",false},
    {"lsass","cred",S_HIGH,"LSASS reference","Obfuscate string",false},
    {"Register-ScheduledTask","persist",S_HIGH,"Task registration","Review necessity",false},
    {"CurrentVersion\\Run","persist",S_HIGH,"Run key persistence","Review necessity",false},
    {"sc.exe create","persist",S_HIGH,"Service creation","Review necessity",false},
    {"Enter-PSSession","lateral",S_MED,"PS remoting","Review necessity",false},
    {"Invoke-WmiMethod","lateral",S_HIGH,"WMI lateral movement","Review necessity",false},
    {"WScript.Shell","vbs_exec",S_HIGH,"Shell execution object","Review code",false},
    {"Shell.Application","vbs_exec",S_HIGH,"Shell application","Review code",false},
    {"ADODB.Stream","vbs_exec",S_HIGH,"Stream — file download","Review necessity",false},
    {"MSXML2.XMLHTTP","vbs_exec",S_HIGH,"HTTP request object","Review necessity",false},
    {"wevtutil cl","forensics",S_CRIT,"Event log clear — anti-forensics","Review necessity",false},
    {"certutil","lolbin",S_HIGH,"Certutil LOLBin","Obfuscate or alternative",false},
    {"bitsadmin","lolbin",S_HIGH,"BITSAdmin LOLBin","Obfuscate",false},
    {"mshta","lolbin",S_MED,"MSHTA — script proxy","Review necessity",false},
    {"rundll32","lolbin",S_MED,"Rundll32 — DLL proxy","Review necessity",false},
    {"regsvr32","lolbin",S_MED,"Regsvr32 — script proxy","Review necessity",false},
    {NULL,NULL,S_INFO,NULL,NULL,false}
};

// ════════════════════════════════════════════════════════════════
// PE STATIC ANALYSIS
// ════════════════════════════════════════════════════════════════
static void AnaHdr(const PEI&pe,std::vector<Finding>&F){
    time_t now=time(NULL);
    if(pe.ts==0)F.push_back({S_MED,"Header","Zero timestamp","Stripped intentionally — packed/modified binary. Defender flags this.","Set plausible date via /TIMESTAMP"});
    else if(pe.ts>(DWORD)now)F.push_back({S_MED,"Header","Future timestamp","Anomalous — indicates tampering.","Set build date"});
    else if(pe.ts<946684800)F.push_back({S_LOW,"Header","Ancient timestamp (<2000)","Forged or very old.","Set plausible date"});
    if(pe.chksum==0)F.push_back({S_LOW,"Header","Missing PE checksum","Checksum zero. Drivers require valid checksum.","EDITBIN /RELEASE"});
    else if(pe.chksum!=pe.calcChk){char b[256];sprintf(b,"Stored 0x%08X != calculated 0x%08X — binary modified post-build.",pe.chksum,pe.calcChk);
        F.push_back({S_HIGH,"Header","Invalid checksum",b,"Recalculate checksum"});}
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))F.push_back({S_HIGH,"Header","ASLR disabled","No DYNAMIC_BASE flag — Defender heavily flags this.","Link with /DYNAMICBASE"});
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_NX_COMPAT))F.push_back({S_HIGH,"Header","DEP/NX disabled","No NX_COMPAT — allows data execution. Strong malware indicator.","Link with /NXCOMPAT"});
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_GUARD_CF))F.push_back({S_MED,"Header","CFG not enabled","No Control Flow Guard — modern binaries should have it.","Link with /guard:cf"});
    if(pe.x64&&!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA))F.push_back({S_LOW,"Header","High-entropy VA not set","64-bit without HIGHENTROPYVA.","Link with /HIGHENTROPYVA"});
    bool epOk=false;
    for(auto&s:pe.secs){if(pe.ep>=s.h.VirtualAddress&&pe.ep<s.h.VirtualAddress+s.virt){epOk=true;
        if(s.nm!=".text"&&s.nm!=".code"&&s.nm!="CODE"){char b[256];sprintf(b,"EP 0x%08X in '%s' — should be in .text. Packer/modification indicator.",pe.ep,s.nm.c_str());
            F.push_back({S_HIGH,"Header","EP in non-code section",b,"Unpack or rebuild"});}break;}}
    if(!epOk&&pe.ep){char b[128];sprintf(b,"EP 0x%08X outside all sections — very strong packer indicator.",pe.ep);F.push_back({S_CRIT,"Header","EP outside sections",b,"Unpack binary"});}
    if((pe.chars&IMAGE_FILE_DLL)&&pe.exps.empty())F.push_back({S_MED,"Header","DLL with no exports","Unusual for legitimate DLLs.","Add exports"});
    if(pe.dbg&&!pe.pdb.empty())F.push_back({S_MED,"Debug","PDB path: "+pe.pdb,"Leaks build env, username, project. Forensics use this to ID developer.","Link with /PDBALTPATH:%_PDB%"});
    if(!pe.rich)F.push_back({S_MED,"Header","No Rich header","Stripped — custom linker or packer.","Normal for custom builds"});
    if(pe.overlay){char b[256];sprintf(b,"Overlay: %u bytes (%.1f KB) @ 0x%X — data after last section. May contain embedded payloads.",pe.ovSz,pe.ovSz/1024.0,pe.ovOff);
        F.push_back({S_MED,"Structure",b,"Investigate overlay content",""});}
    if(pe.clr)F.push_back({S_INFO,"Runtime",".NET CLR present — use dnSpy/ILSpy for decompilation.",""});
}
static void AnaSec(const PEI&pe,std::vector<Finding>&F){
    for(auto&s:pe.secs){
        if(s.ent>7.0&&s.raw>512){char b[256];sprintf(b,"'%s' entropy %.2f — encrypted/compressed data. Packer indicator.",s.nm.c_str(),s.ent);
            F.push_back({S_HIGH,"Section","High entropy: "+s.nm,b,"Investigate/unpack"});}
        else if(s.ent>6.5&&s.raw>512){char b[256];sprintf(b,"'%s' entropy %.2f — possibly encoded.",s.nm.c_str(),s.ent);
            F.push_back({S_MED,"Section","Elevated entropy: "+s.nm,b,""});}
        if(s.raw==0&&s.virt>0x10000){char b[256];sprintf(b,"'%s' raw=0 virt=0x%X — runtime unpack.",s.nm.c_str(),s.virt);
            F.push_back({S_HIGH,"Section","Empty+large virtual: "+s.nm,b,""});}
        if(s.ex&&s.wr){char b[256];sprintf(b,"'%s' is RWX — self-modifying code. Critical AV trigger.",s.nm.c_str());
            F.push_back({S_CRIT,"Section","RWX section: "+s.nm,b,"Split R+X and R+W"});}
        for(int i=0;g_pk[i].n;i++){if(g_pk[i].s[0]&&s.nm==g_pk[i].s)
            F.push_back({S_CRIT,"Packer",std::string(g_pk[i].n)+" ("+s.nm+")",std::string(g_pk[i].d)+" — packed binaries are heavily scrutinized.","Unpack or change packer"});}
        bool std2=false;const char*sn[]={".text",".rdata",".data",".bss",".rsrc",".reloc",".edata",".idata",".pdata",".tls",".gfids",".00cfg",".CRT",NULL};
        for(int i=0;sn[i];i++)if(s.nm==sn[i]){std2=true;break;}
        if(!std2){bool pk=false;for(int i=0;g_pk[i].n;i++)if(g_pk[i].s[0]&&s.nm==g_pk[i].s){pk=true;break;}
            if(!pk)F.push_back({S_LOW,"Section","Non-standard: '"+s.nm+"'","Increases suspicion.","Use standard names"});}
        if(s.virt>s.raw*4&&s.raw>0&&s.virt>0x10000){char b[256];sprintf(b,"'%s' virt(0x%X)>>raw(0x%X) — runtime expansion.",s.nm.c_str(),s.virt,s.raw);
            F.push_back({S_MED,"Section","Virt>>Raw: "+s.nm,b,""});}
    }
    if(pe.nSec<=1)F.push_back({S_HIGH,"Section","Only 1 section","Strong packer indicator. Normal: 3-7 sections.",""});
    if(pe.nSec>10){char b[64];sprintf(b,"%d sections — unusually high.",pe.nSec);F.push_back({S_LOW,"Section",b,"",""});}
}
static void AnaImp(const PEI&pe,std::vector<Finding>&F){
    if(pe.imps.empty()){F.push_back({S_HIGH,"IAT","No imports","Empty IAT = dynamic resolution or packed. Major red flag.","Unpack"});return;}
    if(pe.imps.size()<5){char b[128];sprintf(b,"Only %d import(s) — minimal IAT. Packed or custom loader.",(int)pe.imps.size());F.push_back({S_HIGH,"IAT",b,"",""});}
    for(auto&imp:pe.imps){if(imp.byOrd)continue;
        for(int i=0;g_api[i].n;i++){if(imp.fn==g_api[i].n){F.push_back({g_api[i].s,"IAT",imp.dll+"!"+imp.fn,g_api[i].r,"Remove from IAT — hash-resolve or syscall"});break;}}}
    for(auto&dll:pe.impDlls){for(int i=0;g_dll[i].d;i++){if(dll==Lo(g_dll[i].d)){F.push_back({g_dll[i].s,"IAT","DLL: "+dll,g_dll[i].r,""});break;}}}
    bool gpa=false,ll=false;
    for(auto&i:pe.imps){if(i.fn=="GetProcAddress")gpa=true;if(i.fn=="LoadLibraryA"||i.fn=="LoadLibraryW")ll=true;}
    if(gpa&&ll)F.push_back({S_HIGH,"IAT","GetProcAddress+LoadLibrary combo","Dynamic API resolution pattern — AV specifically looks for this.","Use API hashing"});
    int oc=0;for(auto&i:pe.imps)if(i.byOrd)oc++;
    if(oc>5){char b[128];sprintf(b,"%d ordinal imports — hides function names.",oc);F.push_back({S_MED,"IAT",b,"",""});}
}
static void AnaExp(const PEI&pe,std::vector<Finding>&F){
    const char*sus[]={"ReflectiveLoader","_ReflectiveLoader@4","ServiceMain","SvchostPushServiceGlobals",NULL};
    for(auto&e:pe.exps){for(int i=0;sus[i];i++){if(e.nm==sus[i]){
        Sev sv=(e.nm.find("Reflective")!=std::string::npos)?S_CRIT:S_MED;
        F.push_back({sv,"EAT","Suspicious export: "+e.nm,"Known indicator. ReflectiveLoader=reflective DLL injection.","Rename or remove"});}}}
    if(!pe.expDll.empty()&&!pe.name.empty()&&Lo(pe.expDll)!=Lo(pe.name))
        F.push_back({S_MED,"EAT","Export name '"+pe.expDll+"' != file '"+pe.name+"'","Binary renamed or masquerading.","Match names"});
}
static void AnaTLS(const PEI&pe,std::vector<Finding>&F){
    if(pe.tls)F.push_back({S_HIGH,"TLS","TLS directory present","Callbacks run before EP — used for anti-debug and early init.",""});
    if(pe.tlsCb>0){char b[128];sprintf(b,"%d TLS callback(s) — audit each for anti-debug/payload decryption.",pe.tlsCb);F.push_back({S_HIGH,"TLS",b,"",""});}
}
static void AnaStr(const PEI&pe,std::vector<Finding>&F){
    std::set<std::string>seen;
    for(auto&str:pe.strs){for(int i=0;g_str[i].p;i++){auto&p2=g_str[i];bool m=false;
        if(p2.cs)m=(str.v.find(p2.p)!=std::string::npos);
        else{std::string l=Lo(str.v),pl=Lo(p2.p);m=(l.find(pl)!=std::string::npos);}
        if(m){std::string k=std::string(p2.p)+"|"+p2.c;if(seen.count(k))continue;seen.insert(k);
            char d[512];sprintf(d,"@ 0x%X (%s): \"%.80s%s\"",str.off,str.wide?"wide":"ascii",str.v.c_str(),str.v.size()>80?"...":"");
            F.push_back({p2.s,"String",std::string(p2.d)+" ["+p2.c+"]",d,"Encrypt with XOR/AES or hash-resolve"});}
    }}
}
static void AnaVer(const PEI&pe,std::vector<Finding>&F){
    if(!pe.verInfo)F.push_back({S_MED,"VerInfo","No version info","Missing version info — AV flags this more aggressively.","Add .rc resource"});
    else{if(pe.comp.find("Microsoft")!=std::string::npos)F.push_back({S_HIGH,"VerInfo","Claims Microsoft","Masquerading — not signed by MS.","Use own company name"});
        if(!pe.origFn.empty()&&!pe.name.empty()&&Lo(pe.origFn)!=Lo(pe.name))
            F.push_back({S_MED,"VerInfo","OriginalFilename '"+pe.origFn+"' != '"+pe.name+"'","Defender checks this.","Match names"});}
    if(!pe.manifest)F.push_back({S_LOW,"Resources","No manifest","Modern apps need manifests.","Add manifest"});
}

// ════════════════════════════════════════════════════════════════
// SCRIPT ANALYSIS
// ════════════════════════════════════════════════════════════════
static void AnaScript(const PEI&pe,std::vector<Finding>&F){
    if(pe.scriptLines.empty())return;
    std::string fname=fs::path(pe.path).filename().string();
    int lineNum=0;std::set<std::string>seen;
    for(auto&line:pe.scriptLines){lineNum++;
        std::string tl=line;size_t fs2=tl.find_first_not_of(" \t");if(fs2!=std::string::npos)tl=tl.substr(fs2);
        if(tl.empty())continue;
        if(pe.ftype==FT_PS1&&tl[0]=='#')continue;
        if(pe.ftype==FT_BAT&&(Lo(tl).substr(0,3)=="rem"||tl.substr(0,2)=="::"))continue;
        if(pe.ftype==FT_VBS&&tl[0]=='\'')continue;
        std::string ll=Lo(line);
        for(int i=0;g_sc[i].pat;i++){auto&sig=g_sc[i];
            std::string sp=sig.cs?std::string(sig.pat):Lo(sig.pat);
            std::string sl=sig.cs?line:ll;
            size_t pos=sl.find(sp);
            if(pos!=std::string::npos){
                std::string key=std::string(sig.pat)+"|"+std::to_string(lineNum);
                if(seen.count(key))continue;seen.insert(key);
                Finding fd;fd.sev=sig.sev;fd.cat=sig.cat;fd.title=sig.desc;
                fd.detail=std::string("Pattern: \"")+sig.pat+"\" found in "+fname;
                fd.fix=sig.fix?sig.fix:"";fd.line=lineNum;fd.file=fname;fd.lineText=line;
                F.push_back(fd);}}
    }
    // Script-level heuristics
    double totalEnt=Entropy(pe.data.data(),(size_t)pe.fsize);
    if(totalEnt>5.5){char b[128];sprintf(b,"Script entropy %.2f — may be obfuscated/encoded.",totalEnt);
        F.push_back({S_MED,"Heuristic",b,"High entropy scripts often use base64 or encoding.","Review obfuscation"});}
    // Check for very long lines (obfuscation indicator)
    for(int i=0;i<(int)pe.scriptLines.size();i++){
        if(pe.scriptLines[i].size()>2000){char b[128];sprintf(b,"Line %d has %d chars — very long line indicates obfuscation/encoded payload.",i+1,(int)pe.scriptLines[i].size());
            F.push_back({S_HIGH,"Heuristic",b,"","Review long line content"});break;}}
    // Base64 detection
    int b64count=0;
    std::regex b64re("[A-Za-z0-9+/=]{50,}");
    for(int i=0;i<(int)pe.scriptLines.size();i++){
        if(std::regex_search(pe.scriptLines[i],b64re)){b64count++;
            if(b64count==1){char b[128];sprintf(b,"Base64-like string on line %d — possible encoded payload.",i+1);
                F.push_back({S_HIGH,"Heuristic",b,"","Decode and inspect"});}}}
    if(b64count>3){char b[64];sprintf(b,"%d base64-like strings found.",b64count);F.push_back({S_HIGH,"Heuristic",b,"Multiple encoded blocks.",""});}
}

// ════════════════════════════════════════════════════════════════
// AMSI SCANNER (DefenderCheck-style)
// ════════════════════════════════════════════════════════════════
typedef HRESULT(WINAPI*pAmsiInit)(LPCWSTR,void**);
typedef void(WINAPI*pAmsiUninit)(void*);
typedef HRESULT(WINAPI*pAmsiScan)(void*,PVOID,ULONG,LPCWSTR,void*,int*);
static pAmsiInit fnAI=nullptr;static pAmsiUninit fnAU=nullptr;static pAmsiScan fnAS=nullptr;

static bool LoadAmsi(){
    HMODULE h=LoadLibraryA("amsi.dll");if(!h)return false;
    fnAI=(pAmsiInit)GetProcAddress(h,"AmsiInitialize");
    fnAU=(pAmsiUninit)GetProcAddress(h,"AmsiUninitialize");
    fnAS=(pAmsiScan)GetProcAddress(h,"AmsiScanBuffer");
    return fnAI&&fnAU&&fnAS;
}
static bool AmsiDetects(void*ctx,const BYTE*d,size_t n){
    int r=0;HRESULT hr=fnAS(ctx,(PVOID)d,(ULONG)n,L"ScanSample",nullptr,&r);
    return SUCCEEDED(hr)&&r>=32768;
}
static void RunAmsiScan(const PEI&pe,std::vector<Finding>&F){
    if(!LoadAmsi()){F.push_back({S_INFO,"AMSI","Cannot load amsi.dll — AMSI not available","",""});return;}
    void*ctx=nullptr;
    HRESULT hr=fnAI(L"PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0.19041.1",&ctx);
    if(FAILED(hr)){F.push_back({S_INFO,"AMSI","AmsiInitialize failed","",""});return;}
    // Verify AMSI active
    const char*test="Invoke-Mimikatz";
    if(!AmsiDetects(ctx,(const BYTE*)test,(size_t)strlen(test))){
        F.push_back({S_INFO,"AMSI","AMSI not active — real-time protection may be disabled","",""});fnAU(ctx);return;}
    pinfo("AMSI active — scanning for trigger regions...");
    // First: does whole file trigger?
    bool wholeTrig=AmsiDetects(ctx,pe.data.data(),std::min((size_t)pe.fsize,(size_t)65536));
    if(!wholeTrig){F.push_back({S_INFO,"AMSI","No AMSI detection on file","Binary appears clean to AMSI.",""});fnAU(ctx);return;}
    F.push_back({S_HIGH,"AMSI","File triggers AMSI detection","Defender would flag/quarantine this binary.",""});
    // Binary search for trigger regions
    int chunkSz=4096,minSig=6,trigCount=0;
    size_t offset=0;
    while(offset<pe.fsize&&trigCount<20){
        size_t rem=pe.fsize-offset;size_t chunk=std::min((size_t)chunkSz,rem);
        if(AmsiDetects(ctx,pe.data.data()+offset,chunk)){
            // Narrow down: find trigger end
            size_t trigEnd=0;
            for(size_t probe=minSig;probe<=chunk;probe+=minSig){
                if(AmsiDetects(ctx,pe.data.data()+offset,probe)){
                    for(int back=0;back<minSig&&(int)probe-back>0;back++){
                        if(!AmsiDetects(ctx,pe.data.data()+offset,probe-back)){trigEnd=probe-back;break;}}
                    if(!trigEnd)trigEnd=probe-minSig+1;break;}}
            // Find trigger start
            size_t trigStart=0;
            if(trigEnd>0){for(size_t st=trigEnd>1?trigEnd-1:0;st>0;st--){
                if(AmsiDetects(ctx,pe.data.data()+offset+st,trigEnd-st)){trigStart=st;}else break;}}
            if(trigEnd>trigStart){
                size_t absOff=offset+trigStart;size_t len=trigEnd-trigStart;
                std::string ctx_str;
                for(size_t i=trigStart;i<trigEnd&&i<trigStart+80;i++){
                    BYTE c=pe.data.data()[offset+i];ctx_str+=(c>=0x20&&c<0x7F)?(char)c:'.';}
                std::string hex_str;char hb[4];
                for(size_t i=trigStart;i<trigEnd&&i<trigStart+48;i++){sprintf(hb,"%02X ",pe.data.data()[offset+i]);hex_str+=hb;}
                if(trigEnd-trigStart>48)hex_str+="...";
                char det[512];sprintf(det,"Offset: 0x%08zX | Length: %zu bytes | Context: %.80s | Hex: %s",absOff,len,ctx_str.c_str(),hex_str.c_str());
                Finding fd;fd.sev=S_CRIT;fd.cat="AMSI";fd.title="AMSI trigger region #"+std::to_string(trigCount+1);fd.detail=det;
                fd.fix="Encrypt/obfuscate the flagged bytes, or restructure the code at this offset";fd.foff=(DWORD)absOff;
                F.push_back(fd);trigCount++;offset+=trigEnd;continue;}
        }
        offset+=(chunk>2048)?chunk-2048:chunk;
    }
    if(trigCount>0){char b[64];sprintf(b,"Total AMSI triggers found: %d",trigCount);F.push_back({S_CRIT,"AMSI",b,"Each trigger must be addressed to avoid detection.",""});}
    fnAU(ctx);
}

// ════════════════════════════════════════════════════════════════
// DEFENDER SPLIT SCAN
// ════════════════════════════════════════════════════════════════
static void RunDefenderScan(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    // Use MpCmdRun.exe to scan file halves
    std::string mp="C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
    if(!fs::exists(mp)){mp="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform";
        if(fs::exists(mp)){for(auto&e:fs::directory_iterator(mp)){if(e.is_directory()){
            std::string t=e.path().string()+"\\MpCmdRun.exe";if(fs::exists(t)){mp=t;break;}}}}}
    if(!fs::exists(mp)){F.push_back({S_INFO,"Defender","MpCmdRun.exe not found — cannot do Defender split scan","",""});return;}
    pinfo("Running Defender split scan...");
    // Write temp file and scan
    std::string tmpDir=cfg.outDir.empty()?".\\reports":cfg.outDir;
    fs::create_directories(tmpDir);
    std::string tmpFile=tmpDir+"\\__pedefeat_scan_tmp";
    // Binary split: scan first half, second half
    DWORD mid=pe.fsize/2;
    for(int half=0;half<2;half++){
        std::string hf=tmpFile+(half==0?"_1.bin":"_2.bin");
        {std::ofstream ofs(hf,std::ios::binary);
            if(half==0)ofs.write((char*)pe.data.data(),mid);
            else ofs.write((char*)pe.data.data()+mid,pe.fsize-mid);}
        std::string cmd="\""+mp+"\" -Scan -ScanType 3 -File \""+hf+"\" -DisableRemediation";
        std::string out=RunCmd(cmd,30000);
        bool detected=(out.find("found")!=std::string::npos||out.find("Threat")!=std::string::npos);
        if(detected){char b[256];sprintf(b,"Defender flags %s half (offset 0x%X-0x%X, %u bytes)",
            half==0?"first":"second",half==0?0:mid,half==0?mid:pe.fsize,half==0?mid:pe.fsize-mid);
            F.push_back({S_CRIT,"Defender",b,"Defender signature matches in this region.","Focus evasion efforts on this half"});}
        DeleteFileA(hf.c_str());
    }
}

// ════════════════════════════════════════════════════════════════
// EXTERNAL TOOLS (YARA, Sigma, Sysinternals, PE-sieve)
// ════════════════════════════════════════════════════════════════
static void RunYARA(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.yaraDir.empty()||!fs::exists(cfg.yaraDir))return;
    std::string ye=FindTool("yara64.exe",cfg,"yara");
    if(ye.empty())ye=FindTool("yara32.exe",cfg,"yara");
    if(ye.empty()){F.push_back({S_INFO,"YARA","yara64.exe not found — place in tools/yara/ or install globally","",""});return;}
    pinfo("YARA scanning with rules from: %s",cfg.yaraDir.c_str());
    int rn=0,mn=0;
    for(auto&e:fs::recursive_directory_iterator(cfg.yaraDir)){
        if(!e.is_regular_file())continue;std::string ext=Lo(e.path().extension().string());
        if(ext!=".yar"&&ext!=".yara")continue;rn++;
        std::string out=RunCmd("\""+ye+"\" \""+e.path().string()+"\" \""+pe.path+"\"",15000);
        if(!out.empty()&&out.find("error")==std::string::npos){
            std::istringstream iss(out);std::string line;
            while(std::getline(iss,line)){if(line.empty()||line[0]=='0')continue;
                size_t sp=line.find(' ');if(sp!=std::string::npos){
                    F.push_back({S_HIGH,"YARA","Match: "+line.substr(0,sp)+" ("+e.path().filename().string()+")",e.path().string(),"Address matched pattern"});mn++;}}}}
    if(cfg.verb)pinfo("YARA: %d rules scanned, %d matches",rn,mn);
}
static void RunSigma(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.sigmaDir.empty()||!fs::exists(cfg.sigmaDir))return;
    pinfo("Sigma scanning with rules from: %s",cfg.sigmaDir.c_str());
    int rn=0,mn=0;
    for(auto&e:fs::recursive_directory_iterator(cfg.sigmaDir)){
        if(!e.is_regular_file())continue;std::string ext=Lo(e.path().extension().string());
        if(ext!=".yml"&&ext!=".yaml"&&ext!=".sigma")continue;rn++;
        std::ifstream ifs(e.path());std::string ct((std::istreambuf_iterator<char>(ifs)),std::istreambuf_iterator<char>());
        std::string lc=Lo(ct);std::string title=e.path().stem().string();
        size_t tp=lc.find("title:");if(tp!=std::string::npos){size_t nl=ct.find('\n',tp);if(nl!=std::string::npos){title=ct.substr(tp+6,nl-tp-6);while(!title.empty()&&(title[0]==' '||title[0]=='\t'))title.erase(0,1);}}
        size_t dp=lc.find("detection:");if(dp==std::string::npos)continue;
        std::string det=lc.substr(dp);bool matched=false;
        for(auto&imp:pe.imps){if(!imp.fn.empty()&&det.find(Lo(imp.fn))!=std::string::npos){matched=true;break;}}
        if(!matched){for(auto&str:pe.strs){if(str.v.size()>6&&det.find(Lo(str.v.substr(0,50)))!=std::string::npos){matched=true;break;}}}
        if(matched){F.push_back({S_MED,"Sigma","Rule: "+title,e.path().string(),"Review detection"});mn++;}
    }
    if(cfg.verb)pinfo("Sigma: %d rules, %d matches",rn,mn);
}
static void RunSysint(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.quick)return;
    std::string td=cfg.sysDir;
    if(td.empty())td=FindDir("sysinternals",cfg);
    if(td.empty())return;
    pinfo("Sysinternals tools from: %s",td.c_str());
    std::string sc=td+"\\sigcheck.exe";if(!fs::exists(sc))sc=td+"\\sigcheck64.exe";
    if(fs::exists(sc)){std::string out=RunCmd("\""+sc+"\" -accepteula -nobanner \""+pe.path+"\"",15000);
        if(!out.empty()){if(out.find("Unsigned")!=std::string::npos||out.find("not signed")!=std::string::npos)
            F.push_back({S_HIGH,"Signing","Binary is UNSIGNED","Unsigned binaries are heavily scrutinized by AV. Defender gives extra weight to unsigned files.","Sign with valid certificate"});
            else if(out.find("Signed")!=std::string::npos)F.push_back({S_INFO,"Signing","Binary is signed",out.substr(0,200),""});}}
    std::string se=td+"\\strings.exe";if(!fs::exists(se))se=td+"\\strings64.exe";
    if(fs::exists(se)){std::string out=RunCmd("\""+se+"\" -accepteula -n 8 \""+pe.path+"\"",20000);
        int urls=0,ips=0,paths=0;std::istringstream iss(out);std::string line;
        while(std::getline(iss,line)){
            if(line.find("http://")!=std::string::npos||line.find("https://")!=std::string::npos)urls++;
            if(std::regex_search(line,std::regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")))ips++;
            if(line.find(":\\")!=std::string::npos)paths++;}
        if(urls>0){char b[64];sprintf(b,"%d URLs found in strings",urls);F.push_back({S_MED,"ExtStrings",b,"URLs expose C2/targets.","Encrypt URLs"});}
        if(ips>0){char b[64];sprintf(b,"%d IP addresses found",ips);F.push_back({S_MED,"ExtStrings",b,"IPs expose infrastructure.","Encrypt IPs"});}
        if(paths>3){char b[64];sprintf(b,"%d file paths found",paths);F.push_back({S_LOW,"ExtStrings",b,"Paths expose environment.",""});}}
}

// ════════════════════════════════════════════════════════════════
// DYNAMIC ANALYSIS
// ════════════════════════════════════════════════════════════════
static void RunDynamic(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(!cfg.dyn||!IsPE(pe.ftype))return;
    pinfo("Dynamic analysis — creating suspended process...");
    STARTUPINFOA si={sizeof(si)};si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={};
    if(!CreateProcessA(pe.path.c_str(),NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        F.push_back({S_INFO,"Dynamic","CreateProcess failed — may need admin or file is blocked","",""});return;}
    char buf[128];sprintf(buf,"PID %u suspended",pi.dwProcessId);F.push_back({S_INFO,"Dynamic",buf,"",""});
    typedef struct{DWORD x[6];PVOID PebBaseAddress;}PBI;
    typedef LONG(WINAPI*NtQIP_t)(HANDLE,DWORD,PVOID,ULONG,PULONG);
    HMODULE hNt=GetModuleHandleA("ntdll.dll");
    if(hNt){NtQIP_t nq=(NtQIP_t)GetProcAddress(hNt,"NtQueryInformationProcess");
        if(nq){PBI pbi={};ULONG rl=0;if(nq(pi.hProcess,0,&pbi,sizeof(pbi),&rl)==0){
            sprintf(buf,"PEB @ %p",pbi.PebBaseAddress);F.push_back({S_INFO,"Dynamic",buf,"",""});
            BYTE pb[0x100]={};SIZE_T rd=0;
            if(ReadProcessMemory(pi.hProcess,pbi.PebBaseAddress,pb,sizeof(pb),&rd)){
                sprintf(buf,"BeingDebugged=%d NtGlobalFlag=0x%X",pb[2],pe.x64?*(DWORD*)(pb+0xBC):*(DWORD*)(pb+0x68));
                F.push_back({S_INFO,"Dynamic",buf,"Initial PEB state — check for anti-debug at runtime",""});}}}}
    // PE-sieve on live process
    std::string psPath=cfg.pesieve;
    if(psPath.empty())psPath=FindTool("pe-sieve64.exe",cfg,"pe-sieve");
    if(psPath.empty())psPath=FindTool("pe-sieve32.exe",cfg,"pe-sieve");
    if(!psPath.empty()&&fs::exists(psPath)){
        char cmd[512];sprintf(cmd,"\"%s\" /pid %u /json",psPath.c_str(),pi.dwProcessId);
        std::string out=RunCmd(cmd,15000);
        if(!out.empty()){if(out.find("\"replaced\"")!=std::string::npos||out.find("\"implanted\"")!=std::string::npos)
            F.push_back({S_CRIT,"PE-sieve","Hooks/hollowing detected in process memory",out.substr(0,300),""});
            else F.push_back({S_INFO,"PE-sieve","Clean scan — no hooks detected",out.substr(0,200),""});}}
    TerminateProcess(pi.hProcess,0);WaitForSingleObject(pi.hProcess,5000);
    CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
    F.push_back({S_INFO,"Dynamic","Process terminated — analysis complete","",""});
}

// ════════════════════════════════════════════════════════════════
// PLUGIN SYSTEM
// ════════════════════════════════════════════════════════════════
typedef void(*PlugFn)(const char*,const unsigned char*,unsigned int,void*);
struct Plug{std::string nm;HMODULE h;PlugFn fn;};
static std::vector<Plug>LoadPlugs(const std::string&dir){
    std::vector<Plug>pl;if(dir.empty()||!fs::exists(dir))return pl;
    for(auto&e:fs::directory_iterator(dir)){if(!e.is_regular_file())continue;
        if(Lo(e.path().extension().string())!=".dll")continue;
        HMODULE h=LoadLibraryA(e.path().string().c_str());if(!h)continue;
        PlugFn fn=(PlugFn)GetProcAddress(h,"PluginAnalyze");if(!fn){FreeLibrary(h);continue;}
        typedef const char*(*PNFn)();PNFn pn=(PNFn)GetProcAddress(h,"PluginName");
        pl.push_back({pn?pn():e.path().stem().string(),h,fn});}
    return pl;
}

// ════════════════════════════════════════════════════════════════
// TXT REPORT
// ════════════════════════════════════════════════════════════════
static void GenTxt(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    std::string od=cfg.outDir.empty()?".\\reports":cfg.outDir;
    fs::create_directories(od);std::string p=od+"\\"+pe.name+"_defeat.txt";
    FILE*f=fopen(p.c_str(),"w");if(!f){perr("Cannot write %s",p.c_str());return;}
    fprintf(f,"=======================================================================\n");
    fprintf(f," PEDefeat v%s — Universal Detection Surface Report\n",VER);
    fprintf(f," Author: %s\n",AUTHOR);
    fprintf(f," Generated: %s\n",TSs((DWORD)time(NULL)).c_str());
    fprintf(f,"=======================================================================\n\n");
    fprintf(f,"FILE INFORMATION:\n");
    fprintf(f,"  Path:      %s\n",pe.path.c_str());
    fprintf(f,"  Type:      %s\n",FTStr(pe.ftype));
    fprintf(f,"  Size:      %u bytes (%.1f KB)\n",pe.fsize,pe.fsize/1024.0);
    fprintf(f,"  MD5:       %s\n",pe.md5.c_str());
    fprintf(f,"  SHA256:    %s\n",pe.sha256.c_str());
    if(IsPE(pe.ftype)){
        fprintf(f,"  Arch:      %s\n",pe.x64?"x64":"x86");
        fprintf(f,"  Subsystem: %s\n",pe.subsys==3?"CONSOLE":pe.subsys==2?"GUI":"OTHER");
        fprintf(f,"  Timestamp: %s (0x%08X)\n",TSs(pe.ts).c_str(),pe.ts);
        fprintf(f,"  EP RVA:    0x%08X\n",pe.ep);
        fprintf(f,"  Sections:  %d\n",pe.nSec);
        fprintf(f,"  Imports:   %d funcs from %d DLLs\n",(int)pe.imps.size(),(int)pe.impDlls.size());
        fprintf(f,"  Exports:   %d funcs\n",(int)pe.exps.size());
        if(pe.verInfo){fprintf(f,"\nVERSION INFO:\n  Version: %s\n",pe.ver.c_str());
            if(!pe.prod.empty())fprintf(f,"  Product: %s\n",pe.prod.c_str());
            if(!pe.comp.empty())fprintf(f,"  Company: %s\n",pe.comp.c_str());
            if(!pe.origFn.empty())fprintf(f,"  OrigFile: %s\n",pe.origFn.c_str());
            if(!pe.desc.empty())fprintf(f,"  Desc: %s\n",pe.desc.c_str());}
        fprintf(f,"\nSECTIONS:\n  %-8s %-10s %-10s %-7s %-5s\n","Name","RawSize","VirtSize","Entropy","Flags");
        fprintf(f,"  %-8s %-10s %-10s %-7s %-5s\n","--------","----------","----------","-------","-----");
        for(auto&s:pe.secs){char fl[8]="";if(s.rd)strcat(fl,"R");if(s.wr)strcat(fl,"W");if(s.ex)strcat(fl,"X");
            fprintf(f,"  %-8s 0x%08X 0x%08X  %.2f   %s\n",s.nm.c_str(),s.raw,s.virt,s.ent,fl);}
        fprintf(f,"\nSECURITY FLAGS:\n");
        fprintf(f,"  ASLR: %s  DEP: %s  CFG: %s  SEH: %s  Manifest: %s  Rich: %s  TLS: %s\n",
            (pe.dllCh&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)?"Yes":"NO",
            (pe.dllCh&IMAGE_DLLCHARACTERISTICS_NX_COMPAT)?"Yes":"NO",
            (pe.dllCh&IMAGE_DLLCHARACTERISTICS_GUARD_CF)?"Yes":"NO",
            pe.seh?"Yes":"NO",pe.manifest?"Yes":"No",pe.rich?"Yes":"No",pe.tls?"Yes":"No");
        if(!pe.impDlls.empty()){fprintf(f,"\nIMPORTED DLLs:\n");for(auto&d:pe.impDlls)fprintf(f,"  %s\n",d.c_str());}
        if(!pe.imps.empty()){fprintf(f,"\nALL IMPORTS (%d):\n",(int)pe.imps.size());
            for(auto&i:pe.imps){if(i.byOrd)fprintf(f,"  %s!Ordinal_%d\n",i.dll.c_str(),i.ord);
                else fprintf(f,"  %s!%s\n",i.dll.c_str(),i.fn.c_str());}}
    }else if(IsScript(pe.ftype)){
        fprintf(f,"  Lines:     %d\n",(int)pe.scriptLines.size());
        double ent=Entropy(pe.data.data(),(size_t)pe.fsize);
        fprintf(f,"  Entropy:   %.2f\n",ent);
    }
    int cnt[5]={};for(auto&fi:F)if(fi.sev>=cfg.minSev)cnt[(int)fi.sev]++;
    int total=cnt[0]+cnt[1]+cnt[2]+cnt[3]+cnt[4];
    fprintf(f,"\n=======================================================================\n");
    fprintf(f," DETECTION POINTS: CRIT=%d HIGH=%d MED=%d LOW=%d INFO=%d TOTAL=%d\n",cnt[4],cnt[3],cnt[2],cnt[1],cnt[0],total);
    fprintf(f,"=======================================================================\n\n");
    fprintf(f,"%-3s  %-8s   %-14s  %s\n","#","SEVERITY","CATEGORY","FINDING");
    fprintf(f,"-----------------------------------------------------------------------\n");
    int n=1;for(auto&fi:F){if(fi.sev<cfg.minSev)continue;
        fprintf(f,"%-3d  %-8s   %-14s  %s\n",n++,SevStr(fi.sev),fi.cat.c_str(),fi.title.c_str());
        if(!fi.detail.empty())fprintf(f,"                               %s\n",fi.detail.c_str());
        if(fi.line>0)fprintf(f,"                               Line %d%s%s\n",fi.line,fi.file.empty()?"":" in ",fi.file.c_str());
        if(fi.foff>0)fprintf(f,"                               @ Offset 0x%08X\n",fi.foff);
        if(!fi.fix.empty())fprintf(f,"                               FIX: %s\n",fi.fix.c_str());
        if(!fi.lineText.empty()){std::string lt=fi.lineText;size_t fs2=lt.find_first_not_of(" \t");
            if(fs2!=std::string::npos)lt=lt.substr(fs2);if(lt.size()>150)lt=lt.substr(0,147)+"...";
            fprintf(f,"                               CODE: %s\n",lt.c_str());}
        fprintf(f,"\n");}
    fclose(f);pok("TXT report: %s",p.c_str());
}

// ════════════════════════════════════════════════════════════════
// HTML REPORT
// ════════════════════════════════════════════════════════════════
static std::string HtmlEsc(const std::string&s){
    std::string r;for(char c:s){switch(c){case'<':r+="&lt;";break;case'>':r+="&gt;";break;case'&':r+="&amp;";break;case'"':r+="&quot;";break;default:r+=c;}}return r;
}
static void GenHtml(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    std::string od=cfg.outDir.empty()?".\\reports":cfg.outDir;
    fs::create_directories(od);std::string p=od+"\\"+pe.name+"_defeat.html";
    FILE*f=fopen(p.c_str(),"w");if(!f)return;
    int cnt[5]={};for(auto&fi:F)cnt[(int)fi.sev]++;
    const char*sc[]={"#6c757d","#17a2b8","#ffc107","#fd7e14","#dc3545"};
    fprintf(f,"<!DOCTYPE html><html><head><meta charset='utf-8'><title>PEDefeat v2: %s</title>\n",HtmlEsc(pe.name).c_str());
    fprintf(f,"<style>*{box-sizing:border-box;}body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e0e0e0;margin:0;padding:20px;}");
    fprintf(f,".ctr{max-width:1400px;margin:0 auto;}h1{color:#ff6b6b;border-bottom:2px solid #ff6b6b;padding-bottom:10px;}");
    fprintf(f,"h2{color:#7fdbca;margin-top:30px;}.card{background:#161b22;border-radius:8px;padding:20px;margin:10px 0;border:1px solid #30363d;}");
    fprintf(f,".stats{display:flex;gap:15px;flex-wrap:wrap;}.stat{background:#21262d;border-radius:8px;padding:15px 25px;text-align:center;min-width:100px;}");
    fprintf(f,".stat .num{font-size:2em;font-weight:bold;}.stat .lbl{font-size:0.85em;color:#8b949e;}");
    fprintf(f,"table{width:100%%;border-collapse:collapse;margin:10px 0;}th{background:#21262d;padding:10px;text-align:left;}");
    fprintf(f,"td{padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top;}tr:hover{background:#1c2128;}");
    fprintf(f,".sev{padding:3px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;color:#fff;white-space:nowrap;}");
    fprintf(f,".fix{color:#7fdbca;font-style:italic;}.det{color:#8b949e;font-size:0.9em;}.code{font-family:monospace;font-size:0.85em;background:#21262d;padding:2px 6px;border-radius:3px;}");
    fprintf(f,".author{color:#8b949e;font-size:0.9em;}.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.75em;margin:2px;}</style></head>\n");
    fprintf(f,"<body><div class='ctr'><h1>PEDefeat v%s — Universal Defeat Engine</h1>\n",VER);
    fprintf(f,"<p class='author'>%s | %s | Target: <b>%s</b> (%s)</p>\n",AUTHOR,TSs((DWORD)time(NULL)).c_str(),HtmlEsc(pe.name).c_str(),FTStr(pe.ftype));
    // Target info
    fprintf(f,"<div class='card'><h2>Target Information</h2><table>\n");
    fprintf(f,"<tr><td><b>File</b></td><td>%s</td></tr>\n",HtmlEsc(pe.name).c_str());
    fprintf(f,"<tr><td><b>Type</b></td><td>%s</td></tr>\n",FTStr(pe.ftype));
    fprintf(f,"<tr><td><b>Size</b></td><td>%u bytes (%.1f KB)</td></tr>\n",pe.fsize,pe.fsize/1024.0);
    fprintf(f,"<tr><td><b>MD5</b></td><td><code>%s</code></td></tr>\n",pe.md5.c_str());
    fprintf(f,"<tr><td><b>SHA256</b></td><td><code>%s</code></td></tr>\n",pe.sha256.c_str());
    if(IsPE(pe.ftype)){
        fprintf(f,"<tr><td><b>Arch</b></td><td>%s</td></tr>\n",pe.x64?"x64":"x86");
        fprintf(f,"<tr><td><b>Timestamp</b></td><td>%s</td></tr>\n",TSs(pe.ts).c_str());
        fprintf(f,"<tr><td><b>EP</b></td><td>0x%08X</td></tr>\n",pe.ep);
        if(pe.verInfo){if(!pe.ver.empty())fprintf(f,"<tr><td><b>Version</b></td><td>%s</td></tr>\n",HtmlEsc(pe.ver).c_str());
            if(!pe.prod.empty())fprintf(f,"<tr><td><b>Product</b></td><td>%s</td></tr>\n",HtmlEsc(pe.prod).c_str());
            if(!pe.comp.empty())fprintf(f,"<tr><td><b>Company</b></td><td>%s</td></tr>\n",HtmlEsc(pe.comp).c_str());
            if(!pe.desc.empty())fprintf(f,"<tr><td><b>Description</b></td><td>%s</td></tr>\n",HtmlEsc(pe.desc).c_str());}
    }else{fprintf(f,"<tr><td><b>Lines</b></td><td>%d</td></tr>\n",(int)pe.scriptLines.size());}
    fprintf(f,"</table></div>\n");
    // Stats
    fprintf(f,"<h2>Detection Summary</h2><div class='stats'>\n");
    const char*lb[]={"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    for(int i=4;i>=0;i--)fprintf(f,"<div class='stat'><div class='num' style='color:%s'>%d</div><div class='lbl'>%s</div></div>\n",sc[i],cnt[i],lb[i]);
    fprintf(f,"<div class='stat'><div class='num' style='color:#ff6b6b'>%d</div><div class='lbl'>TOTAL</div></div></div>\n",(int)F.size());
    // Sections (PE only)
    if(IsPE(pe.ftype)&&!pe.secs.empty()){
        fprintf(f,"<div class='card'><h2>Sections</h2><table><tr><th>Name</th><th>Raw</th><th>Virt</th><th>Entropy</th><th>Perm</th></tr>\n");
        for(auto&s:pe.secs){char fl[8]="";if(s.rd)strcat(fl,"R");if(s.wr)strcat(fl,"W");if(s.ex)strcat(fl,"X");
            const char*ec=s.ent>7.0?"#dc3545":s.ent>6.5?"#ffc107":"#7fdbca";
            fprintf(f,"<tr><td><b>%s</b></td><td>0x%08X</td><td>0x%08X</td><td style='color:%s'>%.2f</td><td>%s</td></tr>\n",HtmlEsc(s.nm).c_str(),s.raw,s.virt,ec,s.ent,fl);}
        fprintf(f,"</table></div>\n");}
    // All findings
    fprintf(f,"<div class='card'><h2>All Findings (%d)</h2><table><tr><th>#</th><th>Sev</th><th>Category</th><th>Finding</th></tr>\n",(int)F.size());
    int n=1;for(auto&fi:F){
        fprintf(f,"<tr><td>%d</td><td><span class='sev' style='background:%s'>%s</span></td><td>%s</td><td><b>%s</b>",
            n++,sc[(int)fi.sev],SevStr(fi.sev),HtmlEsc(fi.cat).c_str(),HtmlEsc(fi.title).c_str());
        if(!fi.detail.empty())fprintf(f,"<br><span class='det'>%s</span>",HtmlEsc(fi.detail).c_str());
        if(fi.line>0)fprintf(f,"<br><span class='det'>Line %d%s%s</span>",fi.line,fi.file.empty()?"":" in ",HtmlEsc(fi.file).c_str());
        if(fi.foff>0)fprintf(f,"<br><span class='det'>@ Offset 0x%08X</span>",fi.foff);
        if(!fi.lineText.empty()){std::string lt=HtmlEsc(fi.lineText);size_t fs2=lt.find_first_not_of(" \t");
            if(fs2!=std::string::npos)lt=lt.substr(fs2);if(lt.size()>150)lt=lt.substr(0,147)+"...";
            fprintf(f,"<br><span class='code'>%s</span>",lt.c_str());}
        if(!fi.fix.empty())fprintf(f,"<br><span class='fix'>FIX: %s</span>",HtmlEsc(fi.fix).c_str());
        fprintf(f,"</td></tr>\n");}
    fprintf(f,"</table></div></div></body></html>\n");
    fclose(f);pok("HTML report: %s",p.c_str());
}

// ════════════════════════════════════════════════════════════════
// JSON REPORT
// ════════════════════════════════════════════════════════════════
static std::string JsonEsc(const std::string&s){
    std::string r;for(char c:s){if(c=='"')r+="\\\"";else if(c=='\\')r+="\\\\";else if(c=='\n')r+="\\n";else if(c=='\r')r+="\\r";else if(c=='\t')r+="\\t";else r+=c;}return r;
}
static void GenJson(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    std::string od=cfg.outDir.empty()?".\\reports":cfg.outDir;
    fs::create_directories(od);std::string p=od+"\\"+pe.name+"_defeat.json";
    FILE*f=fopen(p.c_str(),"w");if(!f)return;
    fprintf(f,"{\n  \"tool\": \"PEDefeat v%s\",\n  \"author\": \"%s\",\n",VER,AUTHOR);
    fprintf(f,"  \"generated\": \"%s\",\n",TSs((DWORD)time(NULL)).c_str());
    fprintf(f,"  \"target\": {\n    \"path\": \"%s\",\n    \"name\": \"%s\",\n",JsonEsc(pe.path).c_str(),JsonEsc(pe.name).c_str());
    fprintf(f,"    \"type\": \"%s\",\n    \"size\": %u,\n",FTStr(pe.ftype),pe.fsize);
    fprintf(f,"    \"md5\": \"%s\",\n    \"sha256\": \"%s\"\n  },\n",pe.md5.c_str(),pe.sha256.c_str());
    int cnt[5]={};for(auto&fi:F)cnt[(int)fi.sev]++;
    fprintf(f,"  \"summary\": {\"critical\": %d, \"high\": %d, \"medium\": %d, \"low\": %d, \"info\": %d, \"total\": %d},\n",cnt[4],cnt[3],cnt[2],cnt[1],cnt[0],(int)F.size());
    fprintf(f,"  \"findings\": [\n");
    for(int i=0;i<(int)F.size();i++){auto&fi=F[i];
        fprintf(f,"    {\"severity\": \"%s\", \"category\": \"%s\", \"title\": \"%s\"",SevStr(fi.sev),JsonEsc(fi.cat).c_str(),JsonEsc(fi.title).c_str());
        if(!fi.detail.empty())fprintf(f,", \"detail\": \"%s\"",JsonEsc(fi.detail).c_str());
        if(!fi.fix.empty())fprintf(f,", \"fix\": \"%s\"",JsonEsc(fi.fix).c_str());
        if(fi.line>0)fprintf(f,", \"line\": %d",fi.line);
        if(!fi.file.empty())fprintf(f,", \"file\": \"%s\"",JsonEsc(fi.file).c_str());
        if(fi.foff>0)fprintf(f,", \"offset\": %u",fi.foff);
        if(!fi.lineText.empty()){std::string lt=fi.lineText;if(lt.size()>200)lt=lt.substr(0,200);fprintf(f,", \"code\": \"%s\"",JsonEsc(lt).c_str());}
        fprintf(f,"}%s\n",i+1<(int)F.size()?",":"");}
    fprintf(f,"  ]\n}\n");
    fclose(f);pok("JSON report: %s",p.c_str());
}

// ════════════════════════════════════════════════════════════════
// CONSOLE OUTPUT
// ════════════════════════════════════════════════════════════════
static void PrintConsole(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    psec("TARGET");
    cGr();printf("  File:      ");cW();printf("%s\n",pe.name.c_str());
    cGr();printf("  Type:      %s\n",FTStr(pe.ftype));
    printf("  Size:      %u bytes (%.1f KB)\n",pe.fsize,pe.fsize/1024.0);
    printf("  MD5:       %s\n",pe.md5.c_str());
    printf("  SHA256:    %s\n",pe.sha256.c_str());
    if(IsPE(pe.ftype)){
        printf("  Arch:      %s | Subsys: %s\n",pe.x64?"x64":"x86",pe.subsys==3?"Console":pe.subsys==2?"GUI":"Other");
        printf("  Timestamp: %s\n",TSs(pe.ts).c_str());
        printf("  EP:        0x%08X\n",pe.ep);cr();
        if(pe.verInfo){cGr();printf("  Version:   %s",pe.ver.c_str());if(!pe.prod.empty())printf(" | %s",pe.prod.c_str());
            if(!pe.comp.empty())printf(" | %s",pe.comp.c_str());printf("\n");cr();}
        psec("SECTIONS");
        cGr();printf("  %-8s %-10s %-10s %-7s %-5s\n","Name","RawSize","VirtSize","Entropy","Perm");
        for(auto&s:pe.secs){char fl[8]="";if(s.rd)strcat(fl,"R");if(s.wr)strcat(fl,"W");if(s.ex)strcat(fl,"X");
            const char*ec=s.ent>7.0?"\x1b[91m":s.ent>6.5?"\x1b[93m":"\x1b[92m";
            printf("  %-8s 0x%08X 0x%08X %s%.2f\x1b[0m   %s\n",s.nm.c_str(),s.raw,s.virt,g_c?ec:"",s.ent,fl);}
        cr();
        psec("SECURITY");
        auto yn=[](bool v)->const char*{return v?"\x1b[92mYes\x1b[0m":"\x1b[91mNO\x1b[0m";};
        printf("  ASLR: %s  DEP: %s  CFG: %s  SEH: %s  Manifest: %s  Rich: %s  TLS: %s\n",
            yn(pe.dllCh&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),yn(pe.dllCh&IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
            yn(pe.dllCh&IMAGE_DLLCHARACTERISTICS_GUARD_CF),yn(pe.seh),yn(pe.manifest),yn(pe.rich),yn(!pe.tls));
        psec("IAT");
        cGr();printf("  %d functions from %d DLLs\n",(int)pe.imps.size(),(int)pe.impDlls.size());
        if(!pe.impDlls.empty()){printf("  DLLs: ");for(auto&d:pe.impDlls)printf("%s ",d.c_str());printf("\n");}cr();
        if(!pe.exps.empty()){psec("EXPORTS");cGr();printf("  %d exports",(int)pe.exps.size());
            if(!pe.expDll.empty())printf(" (name: %s)",pe.expDll.c_str());printf("\n");cr();}
    }else if(IsScript(pe.ftype)){
        printf("  Lines:     %d\n",(int)pe.scriptLines.size());
        double ent=Entropy(pe.data.data(),(size_t)pe.fsize);
        printf("  Entropy:   %.2f\n",ent);cr();
    }
    int cnt[5]={};for(auto&fi:F)if(fi.sev>=cfg.minSev)cnt[(int)fi.sev]++;
    psec("DETECTION POINTS");
    printf("  ");cR();printf("CRIT:%d ",cnt[4]);cY();printf("HIGH:%d ",cnt[3]);
    printf("MED:%d ",cnt[2]);cC();printf("LOW:%d ",cnt[1]);cGr();printf("INFO:%d ",cnt[0]);
    cW();printf("TOTAL:%d\n",(int)F.size());cr();printf("\n");
    std::vector<const Finding*>sorted;
    for(auto&fi:F)sorted.push_back(&fi);
    std::sort(sorted.begin(),sorted.end(),[](const Finding*a,const Finding*b){return a->sev>b->sev;});
    for(auto*fp:sorted){if(fp->sev<cfg.minSev)continue;pf(*fp);}
}

// ════════════════════════════════════════════════════════════════
// USAGE & MAIN
// ════════════════════════════════════════════════════════════════
static void ShowUsage(){
    printf("  Usage: PEDefeat.exe <target> [options]\n\n");
    printf("  Supported: EXE, DLL, SYS, PS1, BAT, CMD, VBS, JS, HTA, WSF\n\n");
    printf("  Options:\n");
    printf("    --output=<dir>       Report output dir (default: .\\reports)\n");
    printf("    --html               HTML report\n");
    printf("    --txt                TXT report (default)\n");
    printf("    --json               JSON report\n");
    printf("    --all                All report formats\n");
    printf("    --yara=<dir>         YARA rules dir (auto-detected)\n");
    printf("    --sigma=<dir>        Sigma rules dir (auto-detected)\n");
    printf("    --pesieve=<path>     pe-sieve path (auto-detected)\n");
    printf("    --sysinternals=<dir> Sysinternals dir (auto-detected)\n");
    printf("    --dynamic            Dynamic analysis (suspended process + PEB)\n");
    printf("    --amsi               AMSI-based trigger finder\n");
    printf("    --defender           Defender signature split scan\n");
    printf("    --plugins=<dir>      Plugin DLLs dir (auto-detected)\n");
    printf("    --severity=<level>   Min: critical|high|medium|low|info\n");
    printf("    --verbose            Detailed output\n");
    printf("    --no-color           Disable colors\n");
    printf("    --quick              Skip external tools\n");
    printf("    --deep               Enable ALL analysis (amsi+defender+dynamic)\n\n");
    printf("  Examples:\n");
    printf("    PEDefeat.exe payload.exe --all --deep\n");
    printf("    PEDefeat.exe script.ps1 --html --verbose\n");
    printf("    PEDefeat.exe implant.dll --amsi --severity=high\n");
    printf("    PEDefeat.exe loader.bat --all\n\n");
}

int main(int argc,char*argv[]){
    HANDLE hOut=GetStdHandle(STD_OUTPUT_HANDLE);DWORD mode=0;
    GetConsoleMode(hOut,&mode);SetConsoleMode(hOut,mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
    banner();
    if(argc<2){ShowUsage();return 1;}
    Cfg cfg;cfg.target=argv[1];cfg.exeDir=GetExeDir();
    for(int i=2;i<argc;i++){std::string a=argv[i];
        if(a.substr(0,9)=="--output=")cfg.outDir=a.substr(9);
        else if(a=="--html")cfg.html=true;
        else if(a=="--txt")cfg.txt=true;
        else if(a=="--json")cfg.json=true;
        else if(a=="--all"){cfg.html=true;cfg.txt=true;cfg.json=true;}
        else if(a.substr(0,7)=="--yara=")cfg.yaraDir=a.substr(7);
        else if(a.substr(0,8)=="--sigma=")cfg.sigmaDir=a.substr(8);
        else if(a.substr(0,10)=="--pesieve=")cfg.pesieve=a.substr(10);
        else if(a.substr(0,16)=="--sysinternals=")cfg.sysDir=a.substr(16);
        else if(a=="--dynamic")cfg.dyn=true;
        else if(a=="--amsi")cfg.amsi=true;
        else if(a=="--defender")cfg.defender=true;
        else if(a.substr(0,10)=="--plugins=")cfg.plugDir=a.substr(10);
        else if(a.substr(0,11)=="--severity="){std::string s=Lo(a.substr(11));
            if(s=="critical")cfg.minSev=S_CRIT;else if(s=="high")cfg.minSev=S_HIGH;
            else if(s=="medium")cfg.minSev=S_MED;else if(s=="low")cfg.minSev=S_LOW;else cfg.minSev=S_INFO;}
        else if(a=="--verbose")cfg.verb=true;
        else if(a=="--no-color"){cfg.color=false;g_c=false;}
        else if(a=="--quick")cfg.quick=true;
        else if(a=="--deep"){cfg.deep=true;cfg.amsi=true;cfg.defender=true;cfg.dyn=true;}
    }
    if(cfg.outDir.empty())cfg.outDir=cfg.exeDir+"\\reports";

    // Auto-detect tools dirs
    if(cfg.yaraDir.empty()){std::string d=FindDir("yara",cfg);if(!d.empty())cfg.yaraDir=d;}
    if(cfg.sigmaDir.empty()){std::string d=FindDir("sigma",cfg);if(!d.empty())cfg.sigmaDir=d;}
    if(cfg.sysDir.empty()){std::string d=FindDir("sysinternals",cfg);if(!d.empty())cfg.sysDir=d;}
    if(cfg.plugDir.empty()){std::string d=FindDir("plugins",cfg);if(!d.empty())cfg.plugDir=d;}

    pinfo("Loading: %s",cfg.target.c_str());
    PEI pe;pe.path=cfg.target;pe.name=fs::path(cfg.target).filename().string();
    pe.data=ReadAll(cfg.target);
    if(pe.data.empty()){perr("Failed to read: %s",cfg.target.c_str());return 1;}
    pe.fsize=(DWORD)pe.data.size();
    pe.md5=Hash(pe.data.data(),pe.fsize,CALG_MD5);
    pe.sha256=Hash(pe.data.data(),pe.fsize,CALG_SHA_256);
    pe.ftype=DetectType(pe.path,pe.data);
    pinfo("Detected type: %s",FTStr(pe.ftype));

    // Show auto-detected tools
    if(cfg.verb){
        if(!cfg.yaraDir.empty())pinfo("YARA rules: %s",cfg.yaraDir.c_str());
        if(!cfg.sigmaDir.empty())pinfo("Sigma rules: %s",cfg.sigmaDir.c_str());
        if(!cfg.sysDir.empty())pinfo("Sysinternals: %s",cfg.sysDir.c_str());
        if(!cfg.plugDir.empty())pinfo("Plugins: %s",cfg.plugDir.c_str());
    }

    std::vector<Finding>F;

    if(IsPE(pe.ftype)){
        pinfo("Parsing PE structure...");
        if(!ParsePE(pe)){perr("Not a valid PE file");return 1;}
        ParseImps(pe);ParseExps(pe);ParseTLS(pe);ParseDbg(pe);ParseReloc(pe);ParseDD(pe);ParseVer(pe);
        pinfo("Extracting strings...");ExtStrs(pe);
        pinfo("%d strings found",(int)pe.strs.size());
        pinfo("Analyzing detection surface...");
        AnaHdr(pe,F);AnaSec(pe,F);AnaImp(pe,F);AnaExp(pe,F);AnaTLS(pe,F);AnaStr(pe,F);AnaVer(pe,F);
    }else if(IsScript(pe.ftype)){
        pinfo("Parsing script content...");
        std::string content((char*)pe.data.data(),pe.fsize);
        std::istringstream iss(content);std::string line;
        while(std::getline(iss,line)){
            while(!line.empty()&&(line.back()=='\r'||line.back()=='\n'))line.pop_back();
            pe.scriptLines.push_back(line);}
        pinfo("%d lines loaded",(int)pe.scriptLines.size());
        pinfo("Analyzing script detection surface...");
        AnaScript(pe,F);
    }else{
        pinfo("Unknown file type — running basic string analysis...");
        ExtStrs(pe);AnaStr(pe,F);
    }

    // External tools
    if(!cfg.quick){
        pinfo("Running external tool analysis...");
        RunYARA(pe,cfg,F);RunSigma(pe,cfg,F);
        if(IsPE(pe.ftype))RunSysint(pe,cfg,F);
    }

    // AMSI scan
    if(cfg.amsi){pinfo("Running AMSI trigger scan...");RunAmsiScan(pe,F);}

    // Defender scan
    if(cfg.defender){pinfo("Running Defender split scan...");RunDefenderScan(pe,cfg,F);}

    // Dynamic analysis
    if(cfg.dyn&&IsPE(pe.ftype))RunDynamic(pe,cfg,F);

    // Plugins
    auto plugs=LoadPlugs(cfg.plugDir);
    if(!plugs.empty()){pinfo("%d plugin(s) loaded",(int)plugs.size());
        for(auto&pl:plugs)pl.fn(pe.path.c_str(),pe.data.data(),(unsigned int)pe.fsize,nullptr);}

    // Sort by severity
    std::sort(F.begin(),F.end(),[](const Finding&a,const Finding&b){return a.sev>b.sev;});

    // Output
    PrintConsole(pe,F,cfg);
    if(cfg.txt)GenTxt(pe,F,cfg);
    if(cfg.html)GenHtml(pe,F,cfg);
    if(cfg.json)GenJson(pe,F,cfg);

    cGr();printf("\n  Analysis complete. %d detection points found.\n\n",(int)F.size());cr();
    return 0;
}
