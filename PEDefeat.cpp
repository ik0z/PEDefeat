/*
 * ============================================================================
 *  PEDefeat v1.0 — PE Detection Surface Analyzer & Defeat Engine
 *  Author: Khaled M. Alshammri | @ik0z
 *
 *  Purpose: Malware development & forensics — identify real detection points
 *           in PE files with minimal false positives. Provides actionable
 *           fixes to reduce detection surface for offensive tooling.
 *
 *  Build:   cl /std:c++17 /EHsc /O2 PEDefeat.cpp /Fe:bin\PEDefeat.exe
 *  Usage:   PEDefeat.exe <target.exe|dll|sys> [options]
 *  Options:
 *    --output=<dir>       Report output dir (default: .\reports)
 *    --html               Generate HTML report
 *    --txt                Generate TXT report (default)
 *    --all                All report formats
 *    --yara=<dir>         YARA/Loki rules directory
 *    --sigma=<dir>        Sigma/YAML rules directory
 *    --pesieve=<path>     Path to pe-sieve64.exe
 *    --sysinternals=<dir> Sysinternals tools directory
 *    --dynamic            Dynamic analysis (suspended process + PEB)
 *    --plugins=<dir>      Plugin DLLs directory
 *    --severity=<level>   Min: critical|high|medium|low|info
 *    --verbose            Detailed output
 *    --no-color           Disable colors
 *    --quick              Skip dynamic + external tools
 * ============================================================================
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
static const char* VER="1.0";
static const char* AUTHOR="Khaled M. Alshammri | @ik0z";

enum Sev{S_INFO=0,S_LOW=1,S_MED=2,S_HIGH=3,S_CRIT=4};
static const char* SevStr(Sev s){const char*t[]={"INFO","LOW","MEDIUM","HIGH","CRITICAL"};return t[(int)s];}

struct Finding{Sev sev;std::string cat,title,detail,fix;};
struct Cfg{
    std::string target,outDir=".\\reports",yaraDir,sigmaDir,pesieve,sysDir,plugDir;
    Sev minSev=S_INFO; bool html=false,txt=true,dyn=false,verb=false,color=true,quick=false;
};
struct PEI{
    std::vector<BYTE> data; std::string path,name;
    DWORD fsize=0; std::string md5,sha256;
    IMAGE_DOS_HEADER dos={}; bool stub=false; DWORD stubSz=0;
    bool x64=false; IMAGE_NT_HEADERS32 nt32={}; IMAGE_NT_HEADERS64 nt64={};
    WORD mach=0,nSec=0,chars=0,dllCh=0,subsys=0;
    DWORD ep=0,imgSz=0,hdrSz=0,ib32=0,chksum=0,calcChk=0,ts=0;
    ULONGLONG ib64=0;
    struct Sec{IMAGE_SECTION_HEADER h;double ent;bool ex,wr,rd;DWORD raw,virt;std::string nm;};
    std::vector<Sec> secs;
    struct Imp{std::string dll,fn;WORD ord;bool byOrd;};
    std::vector<Imp> imps; std::set<std::string> impDlls;
    struct Exp{std::string nm;WORD ord;DWORD rva;bool fwd;std::string fwNm;};
    std::vector<Exp> exps; std::string expDll;
    bool tls=false;int tlsCb=0;
    bool dbg=false;std::string pdb;DWORD dbgType=0;
    bool reloc=false;int relocN=0;
    bool res=false,verInfo=false,manifest=false;
    std::string ver,prod,comp,origFn,intNm;
    bool rich=false; struct RE{WORD pid,bid;DWORD cnt;}; std::vector<RE> richE;
    bool overlay=false;DWORD ovOff=0,ovSz=0;
    bool bndImp=false,delImp=false,clr=false,ldCfg=false,seh=false,cfg=false;
    struct Str{std::string v;DWORD off;bool wide;};
    std::vector<Str> strs;
};

// Console
static bool g_c=true;
#define C(x) do{if(g_c)printf("\x1b[" x "m");}while(0)
static void cr(){C("0");}static void cR(){C("91");}static void cY(){C("93");}
static void cG(){C("92");}static void cC(){C("96");}static void cW(){C("97");}
static void cGr(){C("90");}static void cB(){C("1");}
static void banner(){
    cC();
    printf("\n  +===============================================================+\n");
    printf("  |              PEDefeat - PE Detection Defeat Engine             |\n");
    printf("  |                        Version %-6s                          |\n",VER);
    printf("  |          %s                |\n",AUTHOR);
    printf("  +===============================================================+\n");
    cr();printf("\n");
}
static void psec(const char*t){cW();cB();printf("\n  == %s ",t);for(int i=0;i<(int)(58-strlen(t));i++)printf("=");printf("\n");cr();}
static void pf(const Finding&f){
    const char*cl[]={"37","36","33","93","91"};
    printf("  ");if(g_c)printf("\x1b[%sm",cl[(int)f.sev]);
    printf("[%-8s]",SevStr(f.sev));cr();cW();printf(" %-14s",f.cat.c_str());cr();
    printf(" %s\n",f.title.c_str());
    if(!f.detail.empty()){cGr();printf("               %s\n",f.detail.c_str());cr();}
    if(!f.fix.empty()){cG();printf("               FIX: %s\n",f.fix.c_str());cr();}
}

// Utilities
static std::vector<BYTE> ReadAll(const std::string&p){
    std::vector<BYTE>d;HANDLE h=CreateFileA(p.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE)return d;DWORD sz=GetFileSize(h,NULL);
    if(sz==INVALID_FILE_SIZE||!sz){CloseHandle(h);return d;}
    d.resize(sz);DWORD r=0;ReadFile(h,d.data(),sz,&r,NULL);CloseHandle(h);if(r!=sz)d.clear();return d;
}
static double Entropy(const BYTE*d,size_t n){
    if(!n)return 0;DWORD f[256]={};for(size_t i=0;i<n;i++)f[d[i]]++;
    double e=0;for(int i=0;i<256;i++){if(!f[i])continue;double p=(double)f[i]/(double)n;e-=p*log2(p);}return e;
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

// PE Parser
static bool ParsePE(PEI&pe){
    if(pe.data.size()<sizeof(IMAGE_DOS_HEADER))return false;
    memcpy(&pe.dos,pe.data.data(),sizeof(IMAGE_DOS_HEADER));
    if(pe.dos.e_magic!=IMAGE_DOS_SIGNATURE)return false;
    DWORD po=pe.dos.e_lfanew;
    if(!po||po>pe.data.size()-4)return false;
    if(*(DWORD*)(pe.data.data()+po)!=IMAGE_NT_SIGNATURE)return false;
    pe.stub=(po>sizeof(IMAGE_DOS_HEADER));pe.stubSz=pe.stub?po-(DWORD)sizeof(IMAGE_DOS_HEADER):0;
    IMAGE_FILE_HEADER*fh=(IMAGE_FILE_HEADER*)(pe.data.data()+po+4);
    pe.mach=fh->Machine;pe.nSec=fh->NumberOfSections;pe.ts=fh->TimeDateStamp;pe.chars=fh->Characteristics;
    WORD om=*(WORD*)(pe.data.data()+po+4+sizeof(IMAGE_FILE_HEADER));
    pe.x64=(om==IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if(pe.x64){
        if(po+sizeof(IMAGE_NT_HEADERS64)>pe.data.size())return false;
        memcpy(&pe.nt64,pe.data.data()+po,sizeof(IMAGE_NT_HEADERS64));
        pe.ep=pe.nt64.OptionalHeader.AddressOfEntryPoint;pe.ib64=pe.nt64.OptionalHeader.ImageBase;
        pe.imgSz=pe.nt64.OptionalHeader.SizeOfImage;pe.hdrSz=pe.nt64.OptionalHeader.SizeOfHeaders;
        pe.dllCh=pe.nt64.OptionalHeader.DllCharacteristics;pe.subsys=pe.nt64.OptionalHeader.Subsystem;
        pe.chksum=pe.nt64.OptionalHeader.CheckSum;
    }else{
        if(po+sizeof(IMAGE_NT_HEADERS32)>pe.data.size())return false;
        memcpy(&pe.nt32,pe.data.data()+po,sizeof(IMAGE_NT_HEADERS32));
        pe.ep=pe.nt32.OptionalHeader.AddressOfEntryPoint;pe.ib32=pe.nt32.OptionalHeader.ImageBase;
        pe.imgSz=pe.nt32.OptionalHeader.SizeOfImage;pe.hdrSz=pe.nt32.OptionalHeader.SizeOfHeaders;
        pe.dllCh=pe.nt32.OptionalHeader.DllCharacteristics;pe.subsys=pe.nt32.OptionalHeader.Subsystem;
        pe.chksum=pe.nt32.OptionalHeader.CheckSum;
    }
    {DWORD hs=0,cs=0;CheckSumMappedFile(pe.data.data(),pe.fsize,&hs,&cs);pe.calcChk=cs;}
    DWORD so=po+4+sizeof(IMAGE_FILE_HEADER)+fh->SizeOfOptionalHeader;
    for(WORD i=0;i<pe.nSec;i++){
        if(so+sizeof(IMAGE_SECTION_HEADER)>pe.data.size())break;
        PEI::Sec s={};memcpy(&s.h,pe.data.data()+so,sizeof(IMAGE_SECTION_HEADER));
        char nm[9]={};memcpy(nm,s.h.Name,8);s.nm=nm;
        s.raw=s.h.SizeOfRawData;s.virt=s.h.Misc.VirtualSize;
        s.ex=(s.h.Characteristics&IMAGE_SCN_MEM_EXECUTE)!=0;
        s.wr=(s.h.Characteristics&IMAGE_SCN_MEM_WRITE)!=0;
        s.rd=(s.h.Characteristics&IMAGE_SCN_MEM_READ)!=0;
        if(s.raw>0&&s.h.PointerToRawData+s.raw<=pe.data.size())
            s.ent=Entropy(pe.data.data()+s.h.PointerToRawData,s.raw);
        pe.secs.push_back(s);so+=sizeof(IMAGE_SECTION_HEADER);
    }
    if(!pe.secs.empty()){DWORD last=0;for(auto&s:pe.secs){DWORD e=s.h.PointerToRawData+s.raw;if(e>last)last=e;}
        if(last<pe.fsize){pe.overlay=true;pe.ovOff=last;pe.ovSz=pe.fsize-last;}}
    // Rich header
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
    const BYTE*b=pe.data.data();DWORD fs=(DWORD)pe.data.size();
    while(io+sizeof(IMAGE_IMPORT_DESCRIPTOR)<=fs){
        IMAGE_IMPORT_DESCRIPTOR*id=(IMAGE_IMPORT_DESCRIPTOR*)(b+io);
        if(!id->Name&&!id->FirstThunk)break;
        DWORD no=R2O(pe,id->Name);if(!no||no>=fs){io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);continue;}
        std::string dll=(const char*)(b+no);pe.impDlls.insert(Lo(dll));
        DWORD tr=id->OriginalFirstThunk?id->OriginalFirstThunk:id->FirstThunk;
        DWORD to=R2O(pe,tr);if(!to){io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);continue;}
        if(pe.x64){while(to+8<=fs){ULONGLONG tv=*(ULONGLONG*)(b+to);if(!tv)break;
            PEI::Imp e;e.dll=dll;if(tv&0x8000000000000000ULL){e.byOrd=true;e.ord=(WORD)(tv&0xFFFF);}
            else{e.byOrd=false;DWORD ho=R2O(pe,(DWORD)(tv&0x7FFFFFFF));if(ho&&ho+2<fs)e.fn=(const char*)(b+ho+2);}
            pe.imps.push_back(e);to+=8;}}
        else{while(to+4<=fs){DWORD tv=*(DWORD*)(b+to);if(!tv)break;
            PEI::Imp e;e.dll=dll;if(tv&0x80000000){e.byOrd=true;e.ord=(WORD)(tv&0xFFFF);}
            else{e.byOrd=false;DWORD ho=R2O(pe,tv);if(ho&&ho+2<fs)e.fn=(const char*)(b+ho+2);}
            pe.imps.push_back(e);to+=4;}}
        io+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
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
        if(nto+i*4+4>pe.data.size())break;
        DWORD nr=*(DWORD*)(pe.data.data()+nto+i*4);DWORD n2=R2O(pe,nr);
        PEI::Exp e;if(n2&&n2<pe.data.size())e.nm=(const char*)(pe.data.data()+n2);
        if(oto&&oto+i*2+2<=pe.data.size()){WORD oi=*(WORD*)(pe.data.data()+oto+i*2);e.ord=oi+(WORD)ed->Base;
            if(fo+oi*4+4<=pe.data.size()){DWORD fr=*(DWORD*)(pe.data.data()+fo+oi*4);e.rva=fr;
                if(fr>=er&&fr<er+es){e.fwd=true;DWORD f2=R2O(pe,fr);if(f2&&f2<pe.data.size())e.fwNm=(const char*)(pe.data.data()+f2);}}}
        pe.exps.push_back(e);
    }
}

static void ParseTLS(PEI&pe){
    DWORD r=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>9)r=pe.nt64.OptionalHeader.DataDirectory[9].VirtualAddress;}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>9)r=pe.nt32.OptionalHeader.DataDirectory[9].VirtualAddress;}
    if(!r)return;pe.tls=true;DWORD o=R2O(pe,r);if(!o)return;
    if(pe.x64){if(o+sizeof(IMAGE_TLS_DIRECTORY64)>pe.data.size())return;
        IMAGE_TLS_DIRECTORY64*t=(IMAGE_TLS_DIRECTORY64*)(pe.data.data()+o);
        if(t->AddressOfCallBacks){DWORD co=R2O(pe,(DWORD)(t->AddressOfCallBacks-pe.ib64));
            if(co){while(co+8<=pe.data.size()){if(!*(ULONGLONG*)(pe.data.data()+co))break;pe.tlsCb++;co+=8;}}}}
    else{if(o+sizeof(IMAGE_TLS_DIRECTORY32)>pe.data.size())return;
        IMAGE_TLS_DIRECTORY32*t=(IMAGE_TLS_DIRECTORY32*)(pe.data.data()+o);
        if(t->AddressOfCallBacks){DWORD co=R2O(pe,t->AddressOfCallBacks-pe.ib32);
            if(co){while(co+4<=pe.data.size()){if(!*(DWORD*)(pe.data.data()+co))break;pe.tlsCb++;co+=4;}}}}
}

static void ParseDbg(PEI&pe){
    DWORD r=0,sz=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>6){r=pe.nt64.OptionalHeader.DataDirectory[6].VirtualAddress;sz=pe.nt64.OptionalHeader.DataDirectory[6].Size;}}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>6){r=pe.nt32.OptionalHeader.DataDirectory[6].VirtualAddress;sz=pe.nt32.OptionalHeader.DataDirectory[6].Size;}}
    if(!r)return;DWORD o=R2O(pe,r);if(!o)return;
    int n=sz/sizeof(IMAGE_DEBUG_DIRECTORY);
    for(int i=0;i<n;i++){DWORD eo=o+i*sizeof(IMAGE_DEBUG_DIRECTORY);
        if(eo+sizeof(IMAGE_DEBUG_DIRECTORY)>pe.data.size())break;
        IMAGE_DEBUG_DIRECTORY*dd=(IMAGE_DEBUG_DIRECTORY*)(pe.data.data()+eo);pe.dbg=true;pe.dbgType=dd->Type;
        if(dd->Type==IMAGE_DEBUG_TYPE_CODEVIEW&&dd->PointerToRawData>0){DWORD co=dd->PointerToRawData;
            if(co+4<=pe.data.size()&&*(DWORD*)(pe.data.data()+co)==0x53445352&&co+24<pe.data.size())
                pe.pdb=(const char*)(pe.data.data()+co+24);}}
}

static void ParseReloc(PEI&pe){
    DWORD r=0,sz=0;
    if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>5){r=pe.nt64.OptionalHeader.DataDirectory[5].VirtualAddress;sz=pe.nt64.OptionalHeader.DataDirectory[5].Size;}}
    else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>5){r=pe.nt32.OptionalHeader.DataDirectory[5].VirtualAddress;sz=pe.nt32.OptionalHeader.DataDirectory[5].Size;}}
    if(!r)return;pe.reloc=true;DWORD o=R2O(pe,r);if(!o)return;
    DWORD p=0;while(p<sz){if(o+p+8>pe.data.size())break;
        IMAGE_BASE_RELOCATION*bl=(IMAGE_BASE_RELOCATION*)(pe.data.data()+o+p);
        if(!bl->SizeOfBlock)break;pe.relocN+=(bl->SizeOfBlock-8)/2;p+=bl->SizeOfBlock;}
}

static void ParseDD(PEI&pe){
    auto chk=[&](int i)->bool{
        if(pe.x64){if(pe.nt64.OptionalHeader.NumberOfRvaAndSizes>(DWORD)i)return pe.nt64.OptionalHeader.DataDirectory[i].VirtualAddress!=0;}
        else{if(pe.nt32.OptionalHeader.NumberOfRvaAndSizes>(DWORD)i)return pe.nt32.OptionalHeader.DataDirectory[i].VirtualAddress!=0;}
        return false;};
    pe.bndImp=chk(11);pe.delImp=chk(13);pe.clr=chk(14);pe.ldCfg=chk(10);pe.res=chk(2);
    pe.seh=(pe.dllCh&IMAGE_DLLCHARACTERISTICS_NO_SEH)==0;
    if(pe.ldCfg){DWORD lr=0;
        if(pe.x64)lr=pe.nt64.OptionalHeader.DataDirectory[10].VirtualAddress;
        else lr=pe.nt32.OptionalHeader.DataDirectory[10].VirtualAddress;
        DWORD lo=R2O(pe,lr);
        if(lo&&pe.x64&&lo+sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)<=pe.data.size()){
            IMAGE_LOAD_CONFIG_DIRECTORY64*lc=(IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe.data.data()+lo);
            pe.cfg=(lc->GuardFlags&IMAGE_GUARD_CF_INSTRUMENTED)!=0;}}
}

static void ExtStrs(PEI&pe,int ml=5){
    const BYTE*d=pe.data.data();DWORD sz=pe.fsize;
    std::string cur;DWORD soff=0;
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
    if(VerQueryValueA(vb.data(),"\\",(LPVOID*)&fi,&fl)&&fi){
        char b[64];sprintf(b,"%d.%d.%d.%d",HIWORD(fi->dwFileVersionMS),LOWORD(fi->dwFileVersionMS),HIWORD(fi->dwFileVersionLS),LOWORD(fi->dwFileVersionLS));pe.ver=b;}
    struct{const char*n;std::string*t;}fs[]={{"ProductName",&pe.prod},{"CompanyName",&pe.comp},{"OriginalFilename",&pe.origFn},{"InternalName",&pe.intNm}};
    DWORD*lp=NULL;UINT ll=0;
    if(VerQueryValueA(vb.data(),"\\VarFileInfo\\Translation",(LPVOID*)&lp,&ll)&&ll>=4){
        WORD lg=LOWORD(*lp),cp=HIWORD(*lp);
        for(auto&f:fs){char p[256];sprintf(p,"\\StringFileInfo\\%04x%04x\\%s",lg,cp,f.n);
            char*v=NULL;UINT vl=0;if(VerQueryValueA(vb.data(),p,(LPVOID*)&v,&vl)&&v&&vl>0)*f.t=std::string(v,vl-1);}}
    HMODULE hm=LoadLibraryExA(pe.path.c_str(),NULL,LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if(hm){HRSRC hr=FindResourceA(hm,MAKEINTRESOURCEA(1),RT_MANIFEST);
        if(!hr)hr=FindResourceA(hm,MAKEINTRESOURCEA(2),RT_MANIFEST);pe.manifest=(hr!=NULL);FreeLibrary(hm);}
}

// ═══════════════════════════════════════════════════════════════════
// Detection Signature Databases (Maldev + Forensics focused)
// ═══════════════════════════════════════════════════════════════════
struct SA{const char*n,*c;Sev s;const char*r;};
static const SA g_api[]={
    {"VirtualAllocEx","inject",S_HIGH,"Remote mem alloc"},
    {"WriteProcessMemory","inject",S_HIGH,"Remote write"},
    {"NtWriteVirtualMemory","inject",S_HIGH,"Native remote write"},
    {"CreateRemoteThread","inject",S_CRIT,"Remote thread"},
    {"CreateRemoteThreadEx","inject",S_CRIT,"Remote thread ext"},
    {"NtCreateThreadEx","inject",S_CRIT,"Native remote thread"},
    {"QueueUserAPC","inject",S_HIGH,"APC injection"},
    {"NtQueueApcThread","inject",S_HIGH,"Native APC"},
    {"NtQueueApcThreadEx","inject",S_CRIT,"Special user APC"},
    {"RtlCreateUserThread","inject",S_HIGH,"Native thread create"},
    {"SetThreadContext","inject",S_HIGH,"Thread hijacking"},
    {"NtSetContextThread","inject",S_HIGH,"Native thread ctx"},
    {"VirtualProtect","memory",S_MED,"Mem protect change"},
    {"VirtualProtectEx","memory",S_HIGH,"Remote mem protect"},
    {"NtProtectVirtualMemory","memory",S_HIGH,"Native mem protect"},
    {"NtAllocateVirtualMemory","memory",S_MED,"Native mem alloc"},
    {"NtMapViewOfSection","memory",S_HIGH,"Section mapping"},
    {"NtUnmapViewOfSection","memory",S_HIGH,"Section unmapping"},
    {"OpenProcess","process",S_MED,"Opens another process"},
    {"CreateProcessInternalW","process",S_HIGH,"Internal proc create"},
    {"TerminateProcess","process",S_MED,"Proc termination"},
    {"GetProcAddress","dynapi",S_MED,"Dynamic API resolution"},
    {"LoadLibraryA","dynapi",S_MED,"Dynamic DLL load"},
    {"LoadLibraryW","dynapi",S_MED,"Dynamic DLL load"},
    {"LoadLibraryExA","dynapi",S_MED,"Dynamic DLL load ext"},
    {"LdrLoadDll","dynapi",S_HIGH,"Native DLL load"},
    {"LdrGetProcedureAddress","dynapi",S_HIGH,"Native API resolve"},
    {"IsDebuggerPresent","antidebug",S_MED,"Debugger detect"},
    {"CheckRemoteDebuggerPresent","antidebug",S_HIGH,"Remote dbg check"},
    {"NtQueryInformationProcess","antidebug",S_HIGH,"Anti-debug query"},
    {"NtSetInformationThread","antidebug",S_HIGH,"Thread info hide"},
    {"CredEnumerateA","creds",S_HIGH,"Credential enum"},
    {"LsaEnumerateLogonSessions","creds",S_CRIT,"Logon enum"},
    {"LsaGetLogonSessionData","creds",S_CRIT,"Logon data get"},
    {"SamConnect","creds",S_CRIT,"SAM DB connect"},
    {"OpenProcessToken","token",S_MED,"Token access"},
    {"AdjustTokenPrivileges","token",S_HIGH,"Priv escalation"},
    {"ImpersonateLoggedOnUser","token",S_HIGH,"Impersonation"},
    {"DuplicateTokenEx","token",S_HIGH,"Token dup"},
    {"SetThreadToken","token",S_HIGH,"Thread token"},
    {"AmsiScanBuffer","evasion",S_CRIT,"AMSI bypass target"},
    {"EtwEventWrite","evasion",S_CRIT,"ETW bypass target"},
    {"NtTraceEvent","evasion",S_HIGH,"ETW native bypass"},
    {"SetFileInformationByHandle","fileio",S_MED,"Self-delete tech"},
    {"URLDownloadToFileA","network",S_HIGH,"Direct download"},
    {"InternetOpenA","network",S_MED,"Internet access"},
    {"WinHttpOpen","network",S_MED,"HTTP access"},
    {"HttpSendRequestA","network",S_MED,"HTTP request"},
    {"WSAStartup","network",S_LOW,"Winsock init"},
    {"NtContinue","shellcode",S_HIGH,"Exec flow redirect"},
    {"NtTestAlert","shellcode",S_HIGH,"APC flush"},
    {"RegSetValueExA","registry",S_MED,"Registry write"},
    {"BCryptEncrypt","crypto",S_LOW,"Encryption API"},
    {"CryptEncrypt","crypto",S_LOW,"Encryption API"},
    {NULL,NULL,S_INFO,NULL}
};
struct SD{const char*d;Sev s;const char*r;};
static const SD g_dll[]={
    {"ntdll.dll",S_LOW,"Direct ntdll"},{"winhttp.dll",S_LOW,"HTTP"},
    {"wininet.dll",S_LOW,"Internet"},{"ws2_32.dll",S_LOW,"Winsock"},
    {"crypt32.dll",S_LOW,"Crypto"},{"bcrypt.dll",S_LOW,"BCrypt"},
    {"dbghelp.dll",S_HIGH,"Minidump"},{"samlib.dll",S_CRIT,"SAM lib"},
    {"vaultcli.dll",S_HIGH,"Cred vault"},{"amsi.dll",S_CRIT,"AMSI lib"},
    {"wldp.dll",S_HIGH,"WLDP"},{"psapi.dll",S_MED,"Proc enum"},
    {"secur32.dll",S_MED,"Auth"},
    {NULL,S_INFO,NULL}
};
struct SS{const char*p,*c;Sev s;const char*d;bool cs;};
static const SS g_str[]={
    {"AmsiScanBuffer","evasion",S_CRIT,"AMSI func in binary",true},
    {"EtwEventWrite","evasion",S_CRIT,"ETW func in binary",true},
    {"amsi.dll","evasion",S_CRIT,"AMSI DLL name",false},
    {"Authorization: Bearer","c2",S_HIGH,"Auth bearer token",false},
    {"api.notion.com","c2",S_CRIT,"Notion API C2",false},
    {"discord.com/api","c2",S_HIGH,"Discord API C2",false},
    {"graph.microsoft.com","c2",S_HIGH,"MS Graph API",false},
    {"api.telegram.org","c2",S_HIGH,"Telegram API C2",false},
    {"-----BEGIN RSA","crypto",S_HIGH,"RSA key in binary",false},
    {"-----BEGIN PUBLIC","crypto",S_HIGH,"Public key",false},
    {"bitcoin","ransom",S_HIGH,"Bitcoin ref",false},
    {"monero","ransom",S_HIGH,"Monero ref",false},
    {"YOUR FILES","ransom",S_HIGH,"Ransom note",false},
    {"cmd.exe /c","shell",S_HIGH,"Cmd exec",false},
    {"powershell","shell",S_HIGH,"PowerShell",false},
    {"vssadmin","shell",S_CRIT,"VSS delete",false},
    {"bcdedit","shell",S_HIGH,"Boot config",false},
    {"wmic shadowcopy","shell",S_CRIT,"Shadow copy del",false},
    {"schtasks /create","shell",S_HIGH,"Sched task",false},
    {"wbadmin delete","shell",S_HIGH,"Backup del",false},
    {"netsh advfirewall","shell",S_HIGH,"Firewall manip",false},
    {"mimikatz","tool",S_CRIT,"Mimikatz",false},
    {"cobalt","tool",S_HIGH,"CobaltStrike",false},
    {"meterpreter","tool",S_CRIT,"Metasploit",false},
    {"Rubeus","tool",S_CRIT,"Rubeus",true},
    {"SharpHound","tool",S_CRIT,"BloodHound",true},
    {"ReflectiveLoader","tool",S_CRIT,"Reflective loader",true},
    {"Invoke-Mimikatz","tool",S_CRIT,"PS Mimikatz",false},
    {"IsDebuggerPresent","antidbg",S_MED,"Anti-debug API",true},
    {"NtQueryInformationProcess","antidbg",S_HIGH,"Anti-debug native",true},
    {"SbieDll.dll","sandbox",S_HIGH,"Sandboxie detect",false},
    {"vmware","antivm",S_MED,"VMware detect",false},
    {"VBoxService","antivm",S_MED,"VBox detect",false},
    {"User-Agent:","net",S_LOW,"HTTP UA header",false},
    {"Content-Type:","net",S_LOW,"HTTP CT header",false},
    {NULL,NULL,S_INFO,NULL,false}
};
struct PS{const char*n,*s,*d;};
static const PS g_pk[]={
    {"UPX","UPX0","UPX packer"},{"UPX","UPX1","UPX packer"},
    {"ASPack",".aspack","ASPack"},{"Themida",".themida","Themida"},
    {"VMProtect",".vmp0","VMProtect"},{"VMProtect",".vmp1","VMProtect"},
    {"Enigma",".enigma1","Enigma"},{"Obsidium",".obsidium","Obsidium"},
    {"MPRESS",".MPRESS1","MPRESS"},{"MPRESS",".MPRESS2","MPRESS"},
    {"NSPack",".nsp0","NSPack"},{"PEtite",".petite","PEtite"},
    {"PECompact","PEC2","PECompact"},
    {NULL,NULL,NULL}
};

// ═══════════════════════════════════════════════════════════════════
// Static Analysis Engine
// ═══════════════════════════════════════════════════════════════════
static void AnaHdr(const PEI&pe,std::vector<Finding>&F){
    time_t now=time(NULL);
    if(pe.ts==0) F.push_back({S_MED,"Header","Zero timestamp","Stripped intentionally","Set plausible date"});
    else if(pe.ts>(DWORD)now) F.push_back({S_MED,"Header","Future timestamp","Anomalous","Set build date"});
    else if(pe.ts<946684800) F.push_back({S_LOW,"Header","Ancient timestamp (<2000)","May be forged","Set plausible date"});
    if(pe.chksum==0) F.push_back({S_LOW,"Header","Missing PE checksum","","EDITBIN /RELEASE"});
    else if(pe.chksum!=pe.calcChk) F.push_back({S_HIGH,"Header","Invalid checksum","Stored!=calculated - modified post-build","Recalculate"});
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) F.push_back({S_HIGH,"Header","ASLR disabled","No DYNAMIC_BASE flag","/DYNAMICBASE"});
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) F.push_back({S_HIGH,"Header","DEP/NX disabled","No NX_COMPAT flag","/NXCOMPAT"});
    if(!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_GUARD_CF)) F.push_back({S_MED,"Header","CFG not enabled","No Control Flow Guard","/guard:cf"});
    if(pe.x64&&!(pe.dllCh&IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) F.push_back({S_LOW,"Header","High-entropy VA not set","64-bit without it","/HIGHENTROPYVA"});
    bool epOk=false;
    for(auto&s:pe.secs){if(pe.ep>=s.h.VirtualAddress&&pe.ep<s.h.VirtualAddress+s.virt){epOk=true;
        if(s.nm!=".text"&&s.nm!=".code"&&s.nm!="CODE")F.push_back({S_HIGH,"Header","EP in non-code section '"+s.nm+"'","Usually in .text","Packer indicator"});break;}}
    if(!epOk&&pe.ep) F.push_back({S_CRIT,"Header","EP outside all sections","Strong packer/malware indicator",""});
    if((pe.chars&IMAGE_FILE_DLL)&&pe.exps.empty()) F.push_back({S_MED,"Header","DLL with no exports","Unusual","Add exports"});
    if(pe.dbg&&!pe.pdb.empty()) F.push_back({S_MED,"Debug","PDB path: "+pe.pdb,"Exposes build env","/PDBALTPATH:%_PDB%"});
    if(!pe.rich) F.push_back({S_MED,"Header","No Rich header","Stripped by packer/custom linker",""});
    if(pe.overlay){char b[128];sprintf(b,"Overlay: %u bytes @ 0x%X",pe.ovSz,pe.ovOff);F.push_back({S_MED,"Structure",b,"Data after last section",""});}
    if(pe.clr) F.push_back({S_INFO,"Runtime",".NET CLR present","Use dnSpy/ILSpy",""});
}
static void AnaSec(const PEI&pe,std::vector<Finding>&F){
    for(auto&s:pe.secs){
        if(s.ent>7.0&&s.raw>512){char b[256];sprintf(b,"'%s' entropy %.2f (very high)",s.nm.c_str(),s.ent);
            F.push_back({S_HIGH,"Section",b,"Encrypted/compressed - packer","Investigate"});}
        else if(s.ent>6.5&&s.raw>512){char b[256];sprintf(b,"'%s' entropy %.2f (elevated)",s.nm.c_str(),s.ent);
            F.push_back({S_MED,"Section",b,"May be encoded",""});}
        if(s.raw==0&&s.virt>0x10000){char b[256];sprintf(b,"'%s' raw=0 virt=0x%X",s.nm.c_str(),s.virt);
            F.push_back({S_HIGH,"Section",b,"Runtime unpack indicator",""});}
        if(s.ex&&s.wr){char b[128];sprintf(b,"'%s' is RWX",s.nm.c_str());
            F.push_back({S_CRIT,"Section",b,"Self-modifying code/shellcode","Remove W or X"});}
        for(int i=0;g_pk[i].n;i++){if(g_pk[i].s[0]&&s.nm==g_pk[i].s)
            F.push_back({S_CRIT,"Packer",std::string(g_pk[i].n)+" ("+s.nm+")",g_pk[i].d,"Unpack or change packer"});}
        bool std=false;
        const char*sn[]={".text",".rdata",".data",".bss",".rsrc",".reloc",".edata",".idata",".pdata",".tls",".gfids",".00cfg",".CRT",".fptable",".didat",".debug",NULL};
        for(int i=0;sn[i];i++)if(s.nm==sn[i]){std=true;break;}
        if(!std){bool pk=false;for(int i=0;g_pk[i].n;i++)if(g_pk[i].s[0]&&s.nm==g_pk[i].s){pk=true;break;}
            if(!pk)F.push_back({S_LOW,"Section","Non-standard: '"+s.nm+"'","Increases suspicion","Use standard names"});}
        if(s.virt>s.raw*4&&s.raw>0&&s.virt>0x10000){char b[256];sprintf(b,"'%s' virt(0x%X)>>raw(0x%X)",s.nm.c_str(),s.virt,s.raw);
            F.push_back({S_MED,"Section",b,"Runtime decompression",""});}
    }
    if(pe.nSec<=1) F.push_back({S_HIGH,"Section","Only 1 section","Strong packer indicator",""});
    if(pe.nSec>10){char b[64];sprintf(b,"%d sections",pe.nSec);F.push_back({S_LOW,"Section",b,"May be manual PE edit",""});}
}
static void AnaImp(const PEI&pe,std::vector<Finding>&F){
    if(pe.imps.empty()){F.push_back({S_HIGH,"IAT","No imports","Packed or static linked","Unpack"});return;}
    if(pe.imps.size()<5){char b[64];sprintf(b,"Only %d imports",(int)pe.imps.size());F.push_back({S_HIGH,"IAT",b,"Minimal IAT","Investigate"});}
    for(auto&imp:pe.imps){if(imp.byOrd)continue;
        for(int i=0;g_api[i].n;i++){if(imp.fn==g_api[i].n){
            F.push_back({g_api[i].s,"IAT",imp.dll+"!"+imp.fn,g_api[i].r,"Hash-resolve or remove from IAT"});break;}}}
    for(auto&dll:pe.impDlls){for(int i=0;g_dll[i].d;i++){if(dll==Lo(g_dll[i].d)){F.push_back({g_dll[i].s,"IAT","DLL: "+dll,g_dll[i].r,""});break;}}}
    bool gpa=false,ll=false;
    for(auto&i:pe.imps){if(i.fn=="GetProcAddress")gpa=true;if(i.fn=="LoadLibraryA"||i.fn=="LoadLibraryW"||i.fn=="LoadLibraryExA")ll=true;}
    if(gpa&&ll) F.push_back({S_HIGH,"IAT","GetProcAddress+LoadLibrary combo","Dynamic API resolution pattern","Use hash resolution to avoid in IAT"});
    int oc=0;for(auto&i:pe.imps)if(i.byOrd)oc++;
    if(oc>5){char b[64];sprintf(b,"%d ordinal imports",oc);F.push_back({S_MED,"IAT",b,"Hides API names",""});}
}
static void AnaExp(const PEI&pe,std::vector<Finding>&F){
    const char*sus[]={"ReflectiveLoader","_ReflectiveLoader@4","ServiceMain","SvchostPushServiceGlobals",NULL};
    for(auto&e:pe.exps){for(int i=0;sus[i];i++){if(e.nm==sus[i]){
        Sev sv=(e.nm.find("Reflective")!=std::string::npos)?S_CRIT:S_MED;
        F.push_back({sv,"EAT","Export: "+e.nm,"","Rename or remove"});}}}
    if(!pe.expDll.empty()&&!pe.name.empty()&&Lo(pe.expDll)!=Lo(pe.name))
        F.push_back({S_MED,"EAT","Export name '"+pe.expDll+"' != file '"+pe.name+"'","Masquerading","Match names"});
}
static void AnaTLS(const PEI&pe,std::vector<Finding>&F){
    if(pe.tls) F.push_back({S_HIGH,"TLS","TLS directory present","Callbacks run before EP",""});
    if(pe.tlsCb>0){char b[64];sprintf(b,"%d TLS callbacks",pe.tlsCb);F.push_back({S_HIGH,"TLS",b,"Audit each callback",""});}
}
static void AnaStr(const PEI&pe,std::vector<Finding>&F){
    std::set<std::string> seen;
    for(auto&str:pe.strs){for(int i=0;g_str[i].p;i++){auto&p=g_str[i];bool m=false;
        if(p.cs)m=(str.v.find(p.p)!=std::string::npos);
        else{std::string l=Lo(str.v),pl=Lo(p.p);m=(l.find(pl)!=std::string::npos);}
        if(m){std::string k=std::string(p.p)+"|"+p.c;if(seen.count(k))continue;seen.insert(k);
            char d[512];sprintf(d,"@0x%X %s: \"%.60s%s\"",str.off,str.wide?"(wide)":"(ascii)",str.v.c_str(),str.v.size()>60?"...":"");
            F.push_back({p.s,"String",std::string(p.d)+" ["+p.c+"]",d,"XOR encrypt (CS) or hash-resolve"});}
    }}
}
static void AnaVer(const PEI&pe,std::vector<Finding>&F){
    if(!pe.verInfo) F.push_back({S_MED,"VerInfo","No version info","Missing","Add .rc file"});
    else{if(pe.comp.find("Microsoft")!=std::string::npos) F.push_back({S_HIGH,"VerInfo","Claims Microsoft","Must be signed","Change or sign"});
        if(!pe.origFn.empty()&&!pe.name.empty()&&Lo(pe.origFn)!=Lo(pe.name))
            F.push_back({S_MED,"VerInfo","OrigFn '"+pe.origFn+"' != '"+pe.name+"'","Mismatch","Match names"});}
    if(!pe.manifest) F.push_back({S_LOW,"Resources","No manifest","Modern bins should have one","Add manifest"});
}

// ═══════════════════════════════════════════════════════════════════
// External Tool Integration (YARA/Loki, Sigma, Sysinternals, PE-sieve)
// ═══════════════════════════════════════════════════════════════════
static void RunYARA(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.yaraDir.empty()||!fs::exists(cfg.yaraDir))return;
    std::string ye;
    // Search: tools/yara/, tools/, sysDir, PATH
    std::string base=fs::path(cfg.target).parent_path().string();
    for(auto&p:{std::string("yara64.exe"),std::string("tools\\yara\\yara64.exe"),
        cfg.sysDir+"\\yara64.exe",base+"\\tools\\yara\\yara64.exe",base+"\\bin\\yara64.exe"}){
        if(fs::exists(p)){ye=p;break;}}
    if(ye.empty()){std::string t=RunCmd("where yara64.exe",5000);
        if(!t.empty())ye="yara64.exe";
        else{F.push_back({S_INFO,"YARA","yara64.exe not found","Place in tools/yara/ or install globally",""});return;}}
    int rn=0,mn=0;
    for(auto&e:fs::recursive_directory_iterator(cfg.yaraDir)){
        if(!e.is_regular_file())continue;std::string ext=Lo(e.path().extension().string());
        if(ext!=".yar"&&ext!=".yara")continue;rn++;
        std::string out=RunCmd("\""+ye+"\" \""+e.path().string()+"\" \""+pe.path+"\"",15000);
        if(!out.empty()&&out.find("error")==std::string::npos){
            std::istringstream iss(out);std::string line;
            while(std::getline(iss,line)){if(line.empty()||line[0]=='0')continue;
                size_t sp=line.find(' ');if(sp!=std::string::npos){
                    F.push_back({S_HIGH,"YARA","Match: "+line.substr(0,sp)+" ("+e.path().filename().string()+")",e.path().string(),"Address pattern"});mn++;}}}}
    if(cfg.verb){cGr();printf("    YARA: %d rules, %d matches\n",rn,mn);cr();}
}
static void RunSigma(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.sigmaDir.empty()||!fs::exists(cfg.sigmaDir))return;
    int rn=0,mn=0;
    for(auto&e:fs::recursive_directory_iterator(cfg.sigmaDir)){
        if(!e.is_regular_file())continue;std::string ext=Lo(e.path().extension().string());
        if(ext!=".yml"&&ext!=".yaml"&&ext!=".sigma")continue;rn++;
        std::ifstream ifs(e.path());std::string ct((std::istreambuf_iterator<char>(ifs)),std::istreambuf_iterator<char>());
        std::string lc=Lo(ct);
        std::string title=e.path().stem().string();
        size_t tp=lc.find("title:");if(tp!=std::string::npos){size_t nl=ct.find('\n',tp);if(nl!=std::string::npos){title=ct.substr(tp+6,nl-tp-6);while(!title.empty()&&(title[0]==' '||title[0]=='\t'))title.erase(0,1);}}
        size_t dp=lc.find("detection:");if(dp==std::string::npos)continue;
        std::string det=lc.substr(dp);bool matched=false;
        for(auto&imp:pe.imps){if(!imp.fn.empty()&&det.find(Lo(imp.fn))!=std::string::npos){matched=true;break;}}
        if(!matched){for(auto&str:pe.strs){if(str.v.size()>6&&det.find(Lo(str.v.substr(0,50)))!=std::string::npos){matched=true;break;}}}
        if(matched){F.push_back({S_MED,"Sigma","Rule: "+title,e.path().string(),"Review detection"});mn++;}
    }
    if(cfg.verb){cGr();printf("    Sigma: %d rules, %d matches\n",rn,mn);cr();}
}
static void RunSysint(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.quick)return;
    std::string td=cfg.sysDir;
    if(td.empty()){
        std::string base=fs::path(cfg.target).parent_path().string();
        if(fs::exists(base+"\\tools\\sysinternals"))td=base+"\\tools\\sysinternals";
        else if(fs::exists(base+"\\bin"))td=base+"\\bin";
    }
    if(td.empty())return;
    std::string sc=td+"\\sigcheck.exe";if(!fs::exists(sc))sc=td+"\\sigcheck64.exe";
    if(fs::exists(sc)){std::string out=RunCmd("\""+sc+"\" -accepteula -nobanner \""+pe.path+"\"",15000);
        if(!out.empty()){if(out.find("Unsigned")!=std::string::npos||out.find("not signed")!=std::string::npos)
            F.push_back({S_HIGH,"Signing","Binary is UNSIGNED","Unsigned = heavily scrutinized","Sign with valid cert"});
            else if(out.find("Signed")!=std::string::npos)F.push_back({S_INFO,"Signing","Binary is signed",out.substr(0,200),""});}}
    std::string se=td+"\\strings.exe";if(!fs::exists(se))se=td+"\\strings64.exe";
    if(fs::exists(se)){std::string out=RunCmd("\""+se+"\" -accepteula -n 8 \""+pe.path+"\"",20000);
        int urls=0,ips=0,paths=0;std::istringstream iss(out);std::string line;
        while(std::getline(iss,line)){
            if(line.find("http://")!=std::string::npos||line.find("https://")!=std::string::npos)urls++;
            if(std::regex_search(line,std::regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")))ips++;
            if(line.find(":\\")!=std::string::npos)paths++;}
        if(urls>0){char b[64];sprintf(b,"%d URLs found",urls);F.push_back({S_MED,"ExtStrings",b,"URLs expose targets","Encrypt"});}
        if(ips>0){char b[64];sprintf(b,"%d IP addresses",ips);F.push_back({S_MED,"ExtStrings",b,"IPs expose infra","Encrypt"});}
        if(paths>3){char b[64];sprintf(b,"%d file paths",paths);F.push_back({S_LOW,"ExtStrings",b,"Paths expose env",""});}}
}
static void RunPESieve(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(cfg.pesieve.empty()){
        // Auto-detect in tools/pe-sieve/
        std::string base=fs::path(cfg.target).parent_path().string();
        std::string auto_p=base+"\\tools\\pe-sieve\\pe-sieve64.exe";
        if(!fs::exists(auto_p))auto_p=base+"\\tools\\pe-sieve\\pe-sieve32.exe";
        if(!fs::exists(auto_p))return;
        if(!cfg.dyn){F.push_back({S_INFO,"PE-sieve","Available - use --dynamic to scan live process","",""});return;}
    } else {
        if(!fs::exists(cfg.pesieve)){F.push_back({S_INFO,"PE-sieve","Not found: "+cfg.pesieve,"Place in tools/pe-sieve/",""});return;}
        if(!cfg.dyn){F.push_back({S_INFO,"PE-sieve","Available - use --dynamic to scan live process","",""});return;}
    }
}
static void RunDynamic(const PEI&pe,const Cfg&cfg,std::vector<Finding>&F){
    if(!cfg.dyn)return;
    F.push_back({S_INFO,"Dynamic","Creating suspended process","",""});
    STARTUPINFOA si={sizeof(si)};si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={};
    if(!CreateProcessA(pe.path.c_str(),NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        F.push_back({S_INFO,"Dynamic","CreateProcess failed","",""});return;}
    char buf[128];sprintf(buf,"PID %u suspended",pi.dwProcessId);
    F.push_back({S_INFO,"Dynamic",buf,"Inspecting memory",""});
    typedef struct{DWORD x[6];PVOID PebBaseAddress;}PBI;
    typedef LONG(WINAPI*NtQIP_t)(HANDLE,DWORD,PVOID,ULONG,PULONG);
    HMODULE hNt=GetModuleHandleA("ntdll.dll");
    if(hNt){NtQIP_t nq=(NtQIP_t)GetProcAddress(hNt,"NtQueryInformationProcess");
        if(nq){PBI pbi={};ULONG rl=0;if(nq(pi.hProcess,0,&pbi,sizeof(pbi),&rl)==0){
            sprintf(buf,"PEB @ %p",pbi.PebBaseAddress);F.push_back({S_INFO,"Dynamic",buf,"",""});
            BYTE pb[0x100]={};SIZE_T rd=0;
            if(ReadProcessMemory(pi.hProcess,pbi.PebBaseAddress,pb,sizeof(pb),&rd)){
                sprintf(buf,"BeingDebugged=%d NtGlobalFlag=0x%X",pb[2],pe.x64?*(DWORD*)(pb+0xBC):*(DWORD*)(pb+0x68));
                F.push_back({S_INFO,"Dynamic",buf,"Initial PEB",""});}}}}
    // PE-sieve on live process
    std::string psPath=cfg.pesieve;
    if(psPath.empty()){std::string base=fs::path(cfg.target).parent_path().string();
        if(fs::exists(base+"\\tools\\pe-sieve\\pe-sieve64.exe"))psPath=base+"\\tools\\pe-sieve\\pe-sieve64.exe";
        else if(fs::exists(base+"\\tools\\pe-sieve\\pe-sieve32.exe"))psPath=base+"\\tools\\pe-sieve\\pe-sieve32.exe";}
    if(!psPath.empty()&&fs::exists(psPath)){
        char cmd[512];sprintf(cmd,"\"%s\" /pid %u /json",psPath.c_str(),pi.dwProcessId);
        std::string out=RunCmd(cmd,15000);
        if(!out.empty()){if(out.find("\"replaced\"")!=std::string::npos||out.find("\"implanted\"")!=std::string::npos)
            F.push_back({S_CRIT,"PE-sieve","Hooks/hollowing detected",out.substr(0,300),""});
            else F.push_back({S_INFO,"PE-sieve","Clean scan",out.substr(0,200),""});}}
    TerminateProcess(pi.hProcess,0);WaitForSingleObject(pi.hProcess,5000);
    CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
    F.push_back({S_INFO,"Dynamic","Process terminated","Analysis complete",""});
}

// ═══════════════════════════════════════════════════════════════════
// Plugin System
// ═══════════════════════════════════════════════════════════════════
typedef void(*PlugFn)(const char*,const unsigned char*,unsigned int,void*);
struct Plug{std::string nm;HMODULE h;PlugFn fn;};
static std::vector<Plug> LoadPlugs(const std::string&dir){
    std::vector<Plug> pl;if(dir.empty()||!fs::exists(dir))return pl;
    for(auto&e:fs::directory_iterator(dir)){if(!e.is_regular_file())continue;
        if(Lo(e.path().extension().string())!=".dll")continue;
        HMODULE h=LoadLibraryA(e.path().string().c_str());if(!h)continue;
        PlugFn fn=(PlugFn)GetProcAddress(h,"PluginAnalyze");if(!fn){FreeLibrary(h);continue;}
        typedef const char*(*PNFn)();PNFn pn=(PNFn)GetProcAddress(h,"PluginName");
        pl.push_back({pn?pn():e.path().stem().string(),h,fn});}
    return pl;
}

// ═══════════════════════════════════════════════════════════════════
// TXT Report
// ═══════════════════════════════════════════════════════════════════
static void GenTxt(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    std::string p=cfg.outDir+"\\"+pe.name+"_defeat.txt";
    fs::create_directories(cfg.outDir);
    FILE*f=fopen(p.c_str(),"w");if(!f){printf("  [-] Cannot write %s\n",p.c_str());return;}
    fprintf(f,"=======================================================================\n");
    fprintf(f," PEDefeat v%s Report - %s\n",VER,pe.name.c_str());
    fprintf(f," Author: %s\n",AUTHOR);
    fprintf(f," Generated: %s\n",TSs((DWORD)time(NULL)).c_str());
    fprintf(f,"=======================================================================\n\n");
    fprintf(f,"FILE INFORMATION:\n");
    fprintf(f,"  Path:      %s\n",pe.path.c_str());
    fprintf(f,"  Size:      %u bytes (%.1f KB)\n",pe.fsize,pe.fsize/1024.0);
    fprintf(f,"  MD5:       %s\n",pe.md5.c_str());
    fprintf(f,"  SHA256:    %s\n",pe.sha256.c_str());
    fprintf(f,"  Arch:      %s\n",pe.x64?"x64":"x86");
    fprintf(f,"  Type:      %s\n",(pe.chars&IMAGE_FILE_DLL)?"DLL":"EXE");
    fprintf(f,"  Subsystem: %s\n",pe.subsys==3?"CONSOLE":pe.subsys==2?"GUI":"OTHER");
    fprintf(f,"  Timestamp: %s (0x%08X)\n",TSs(pe.ts).c_str(),pe.ts);
    fprintf(f,"  EP RVA:    0x%08X\n",pe.ep);
    fprintf(f,"  Sections:  %d\n",pe.nSec);
    fprintf(f,"  Imports:   %d funcs from %d DLLs\n",(int)pe.imps.size(),(int)pe.impDlls.size());
    fprintf(f,"  Exports:   %d funcs\n",(int)pe.exps.size());
    if(pe.verInfo){fprintf(f,"\nVERSION INFO:\n  Version: %s\n",pe.ver.c_str());
        if(!pe.prod.empty())fprintf(f,"  Product: %s\n",pe.prod.c_str());
        if(!pe.comp.empty())fprintf(f,"  Company: %s\n",pe.comp.c_str());
        if(!pe.origFn.empty())fprintf(f,"  OrigFile: %s\n",pe.origFn.c_str());}
    fprintf(f,"\nSECTIONS:\n  %-8s %-10s %-10s %-7s %-5s\n","Name","RawSize","VirtSize","Entropy","Flags");
    fprintf(f,"  %-8s %-10s %-10s %-7s %-5s\n","--------","----------","----------","-------","-----");
    for(auto&s:pe.secs){char fl[8]="";if(s.rd)strcat(fl,"R");if(s.wr)strcat(fl,"W");if(s.ex)strcat(fl,"X");
        fprintf(f,"  %-8s 0x%08X 0x%08X  %.2f   %s\n",s.nm.c_str(),s.raw,s.virt,s.ent,fl);}
    fprintf(f,"\nSECURITY:\n");
    fprintf(f,"  ASLR: %s  DEP: %s  CFG: %s  SEH: %s  Manifest: %s  Rich: %s  TLS: %s\n",
        (pe.dllCh&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)?"Yes":"NO",
        (pe.dllCh&IMAGE_DLLCHARACTERISTICS_NX_COMPAT)?"Yes":"NO",
        (pe.dllCh&IMAGE_DLLCHARACTERISTICS_GUARD_CF)?"Yes":"NO",
        pe.seh?"Yes":"NO",pe.manifest?"Yes":"No",pe.rich?"Yes":"No",pe.tls?"Yes":"No");
    int cnt[5]={};for(auto&fi:F)cnt[(int)fi.sev]++;
    fprintf(f,"\n=======================================================================\n");
    fprintf(f," DETECTION POINTS: CRIT=%d HIGH=%d MED=%d LOW=%d INFO=%d TOTAL=%d\n",cnt[4],cnt[3],cnt[2],cnt[1],cnt[0],(int)F.size());
    fprintf(f,"=======================================================================\n");
    fprintf(f,"%-3s  %-8s   %-14s  %s\n","#","SEVERITY","CATEGORY","FINDING");
    fprintf(f,"-----------------------------------------------------------------------\n");
    int n=1;for(auto&fi:F){
        fprintf(f,"%-3d  %-8s   %-14s  %s\n",n++,SevStr(fi.sev),fi.cat.c_str(),fi.title.c_str());
        if(!fi.detail.empty())fprintf(f,"                               %s\n",fi.detail.c_str());
        if(!fi.fix.empty())fprintf(f,"                               FIX: %s\n",fi.fix.c_str());}
    fclose(f);cG();printf("  [+] TXT: %s\n",p.c_str());cr();
}

// ═══════════════════════════════════════════════════════════════════
// HTML Report
// ═══════════════════════════════════════════════════════════════════
static void GenHtml(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    std::string p=cfg.outDir+"\\"+pe.name+"_defeat.html";
    fs::create_directories(cfg.outDir);
    FILE*f=fopen(p.c_str(),"w");if(!f)return;
    int cnt[5]={};for(auto&fi:F)cnt[(int)fi.sev]++;
    const char*sc[]={"#6c757d","#17a2b8","#ffc107","#fd7e14","#dc3545"};
    fprintf(f,"<!DOCTYPE html><html><head><meta charset='utf-8'><title>PEDefeat: %s</title>\n",pe.name.c_str());
    fprintf(f,"<style>body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e0e0e0;margin:0;padding:20px;}");
    fprintf(f,".ctr{max-width:1200px;margin:0 auto;}h1{color:#ff6b6b;border-bottom:2px solid #ff6b6b;padding-bottom:10px;}");
    fprintf(f,"h2{color:#7fdbca;margin-top:30px;}.card{background:#161b22;border-radius:8px;padding:20px;margin:10px 0;border:1px solid #30363d;}");
    fprintf(f,".stats{display:flex;gap:15px;flex-wrap:wrap;}.stat{background:#21262d;border-radius:8px;padding:15px 25px;text-align:center;min-width:100px;}");
    fprintf(f,".stat .num{font-size:2em;font-weight:bold;}.stat .lbl{font-size:0.85em;color:#8b949e;}");
    fprintf(f,"table{width:100%%;border-collapse:collapse;margin:10px 0;}th{background:#21262d;padding:10px;text-align:left;}");
    fprintf(f,"td{padding:8px 10px;border-bottom:1px solid #21262d;}tr:hover{background:#1c2128;}");
    fprintf(f,".sev{padding:3px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;color:#fff;}");
    fprintf(f,".fix{color:#7fdbca;font-style:italic;}.det{color:#8b949e;font-size:0.9em;}");
    fprintf(f,".author{color:#8b949e;font-size:0.9em;}</style></head>\n");
    fprintf(f,"<body><div class='ctr'><h1>PEDefeat v%s</h1>\n",VER);
    fprintf(f,"<p class='author'>%s | Generated: %s</p>\n",AUTHOR,TSs((DWORD)time(NULL)).c_str());
    fprintf(f,"<div class='card'><h2>Target</h2><table>\n");
    fprintf(f,"<tr><td><b>File</b></td><td>%s</td></tr>\n",pe.name.c_str());
    fprintf(f,"<tr><td><b>Size</b></td><td>%u bytes (%.1f KB)</td></tr>\n",pe.fsize,pe.fsize/1024.0);
    fprintf(f,"<tr><td><b>MD5</b></td><td><code>%s</code></td></tr>\n",pe.md5.c_str());
    fprintf(f,"<tr><td><b>SHA256</b></td><td><code>%s</code></td></tr>\n",pe.sha256.c_str());
    fprintf(f,"<tr><td><b>Arch</b></td><td>%s</td></tr>\n",pe.x64?"x64":"x86");
    fprintf(f,"<tr><td><b>Type</b></td><td>%s</td></tr>\n",(pe.chars&IMAGE_FILE_DLL)?"DLL":"EXE");
    fprintf(f,"<tr><td><b>Timestamp</b></td><td>%s</td></tr>\n",TSs(pe.ts).c_str());
    fprintf(f,"<tr><td><b>EP</b></td><td>0x%08X</td></tr>\n",pe.ep);
    if(pe.verInfo){fprintf(f,"<tr><td><b>Version</b></td><td>%s</td></tr>\n",pe.ver.c_str());
        if(!pe.prod.empty())fprintf(f,"<tr><td><b>Product</b></td><td>%s</td></tr>\n",pe.prod.c_str());
        if(!pe.comp.empty())fprintf(f,"<tr><td><b>Company</b></td><td>%s</td></tr>\n",pe.comp.c_str());}
    fprintf(f,"</table></div>\n");
    fprintf(f,"<h2>Detection Points</h2><div class='stats'>\n");
    const char*lb[]={"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    for(int i=4;i>=0;i--)fprintf(f,"<div class='stat'><div class='num' style='color:%s'>%d</div><div class='lbl'>%s</div></div>\n",sc[i],cnt[i],lb[i]);
    fprintf(f,"<div class='stat'><div class='num' style='color:#ff6b6b'>%d</div><div class='lbl'>TOTAL</div></div></div>\n",(int)F.size());
    fprintf(f,"<div class='card'><h2>Sections</h2><table><tr><th>Name</th><th>Raw</th><th>Virt</th><th>Entropy</th><th>Perm</th></tr>\n");
    for(auto&s:pe.secs){char fl[8]="";if(s.rd)strcat(fl,"R");if(s.wr)strcat(fl,"W");if(s.ex)strcat(fl,"X");
        const char*ec=s.ent>7.0?"#dc3545":s.ent>6.5?"#ffc107":"#7fdbca";
        fprintf(f,"<tr><td><b>%s</b></td><td>0x%08X</td><td>0x%08X</td><td style='color:%s'>%.2f</td><td>%s</td></tr>\n",s.nm.c_str(),s.raw,s.virt,ec,s.ent,fl);}
    fprintf(f,"</table></div>\n");
    fprintf(f,"<div class='card'><h2>All Findings</h2><table><tr><th>#</th><th>Sev</th><th>Category</th><th>Finding</th></tr>\n");
    int n=1;for(auto&fi:F){
        fprintf(f,"<tr><td>%d</td><td><span class='sev' style='background:%s'>%s</span></td><td>%s</td><td>%s",
            n++,sc[(int)fi.sev],SevStr(fi.sev),fi.cat.c_str(),fi.title.c_str());
        if(!fi.detail.empty())fprintf(f,"<br><span class='det'>%s</span>",fi.detail.c_str());
        if(!fi.fix.empty())fprintf(f,"<br><span class='fix'>FIX: %s</span>",fi.fix.c_str());
        fprintf(f,"</td></tr>\n");}
    fprintf(f,"</table></div></div></body></html>\n");
    fclose(f);cG();printf("  [+] HTML: %s\n",p.c_str());cr();
}

// ═══════════════════════════════════════════════════════════════════
// Console Output
// ═══════════════════════════════════════════════════════════════════
static void PrintConsole(const PEI&pe,const std::vector<Finding>&F,const Cfg&cfg){
    psec("TARGET");
    cGr();printf("  File:      ");cW();printf("%s\n",pe.name.c_str());
    cGr();printf("  Size:      %u bytes (%.1f KB)\n",pe.fsize,pe.fsize/1024.0);
    printf("  MD5:       %s\n",pe.md5.c_str());
    printf("  SHA256:    %s\n",pe.sha256.c_str());
    printf("  Arch:      %s | Type: %s | Subsys: %s\n",pe.x64?"x64":"x86",
        (pe.chars&IMAGE_FILE_DLL)?"DLL":"EXE",pe.subsys==3?"Console":pe.subsys==2?"GUI":"Other");
    printf("  Timestamp: %s\n",TSs(pe.ts).c_str());
    printf("  EP:        0x%08X\n",pe.ep);cr();
    if(pe.verInfo){cGr();printf("  Version:   %s",pe.ver.c_str());
        if(!pe.prod.empty())printf(" | %s",pe.prod.c_str());
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
    int cnt[5]={};for(auto&fi:F)cnt[(int)fi.sev]++;
    psec("DETECTION POINTS");
    printf("  ");cR();printf("CRIT:%d ",cnt[4]);cY();printf("HIGH:%d ",cnt[3]);
    printf("MED:%d ",cnt[2]);cC();printf("LOW:%d ",cnt[1]);cGr();printf("INFO:%d ",cnt[0]);
    cW();printf("TOTAL:%d\n",(int)F.size());cr();printf("\n");
    std::vector<const Finding*> sorted;
    for(auto&fi:F)sorted.push_back(&fi);
    std::sort(sorted.begin(),sorted.end(),[](const Finding*a,const Finding*b){return a->sev>b->sev;});
    for(auto*fp:sorted){if(fp->sev<cfg.minSev)continue;pf(*fp);}
}

// ═══════════════════════════════════════════════════════════════════
// Usage & Main
// ═══════════════════════════════════════════════════════════════════
static void ShowUsage(){
    printf("  Usage: PEDefeat.exe <target.exe|dll|sys> [options]\n\n");
    printf("  Options:\n");
    printf("    --output=<dir>       Report output dir (default: .\\reports)\n");
    printf("    --html               Generate HTML report\n");
    printf("    --txt                Generate TXT report (default)\n");
    printf("    --all                All report formats\n");
    printf("    --yara=<dir>         YARA/Loki rules directory\n");
    printf("    --sigma=<dir>        Sigma/YAML rules directory\n");
    printf("    --pesieve=<path>     Path to pe-sieve64.exe\n");
    printf("    --sysinternals=<dir> Sysinternals tools directory\n");
    printf("    --dynamic            Dynamic analysis (suspended process)\n");
    printf("    --plugins=<dir>      Plugin DLLs directory\n");
    printf("    --severity=<level>   Min: critical|high|medium|low|info\n");
    printf("    --verbose            Detailed output\n");
    printf("    --no-color           Disable colors\n");
    printf("    --quick              Skip dynamic + external tools\n\n");
}

int main(int argc,char*argv[]){
    HANDLE hOut=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode=0;GetConsoleMode(hOut,&mode);
    SetConsoleMode(hOut,mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    banner();
    if(argc<2){ShowUsage();return 1;}
    Cfg cfg; cfg.target=argv[1];
    for(int i=2;i<argc;i++){std::string a=argv[i];
        if(a.substr(0,9)=="--output=")cfg.outDir=a.substr(9);
        else if(a=="--html")cfg.html=true;
        else if(a=="--txt")cfg.txt=true;
        else if(a=="--all"){cfg.html=true;cfg.txt=true;}
        else if(a.substr(0,7)=="--yara=")cfg.yaraDir=a.substr(7);
        else if(a.substr(0,8)=="--sigma=")cfg.sigmaDir=a.substr(8);
        else if(a.substr(0,10)=="--pesieve=")cfg.pesieve=a.substr(10);
        else if(a.substr(0,16)=="--sysinternals=")cfg.sysDir=a.substr(16);
        else if(a=="--dynamic")cfg.dyn=true;
        else if(a.substr(0,10)=="--plugins=")cfg.plugDir=a.substr(10);
        else if(a.substr(0,11)=="--severity="){std::string s=Lo(a.substr(11));
            if(s=="critical")cfg.minSev=S_CRIT;else if(s=="high")cfg.minSev=S_HIGH;
            else if(s=="medium")cfg.minSev=S_MED;else if(s=="low")cfg.minSev=S_LOW;else cfg.minSev=S_INFO;}
        else if(a=="--verbose")cfg.verb=true;
        else if(a=="--no-color"){cfg.color=false;g_c=false;}
        else if(a=="--quick")cfg.quick=true;
    }
    // Auto-detect tools
    std::string base=fs::path(cfg.target).parent_path().string();
    if(cfg.sysDir.empty()){
        if(fs::exists(base+"\\tools\\sysinternals"))cfg.sysDir=base+"\\tools\\sysinternals";
        else if(fs::exists(base+"\\bin"))cfg.sysDir=base+"\\bin";
    }
    if(cfg.yaraDir.empty()&&fs::exists(base+"\\rules\\yara"))cfg.yaraDir=base+"\\rules\\yara";
    if(cfg.sigmaDir.empty()&&fs::exists(base+"\\rules\\sigma"))cfg.sigmaDir=base+"\\rules\\sigma";
    if(cfg.plugDir.empty()&&fs::exists(base+"\\plugins"))cfg.plugDir=base+"\\plugins";

    cGr();printf("  [*] Loading: %s\n",cfg.target.c_str());cr();
    PEI pe; pe.path=cfg.target; pe.name=fs::path(cfg.target).filename().string();
    pe.data=ReadAll(cfg.target);
    if(pe.data.empty()){cR();printf("  [-] Failed to read: %s\n",cfg.target.c_str());cr();return 1;}
    pe.fsize=(DWORD)pe.data.size();
    pe.md5=Hash(pe.data.data(),pe.fsize,CALG_MD5);
    pe.sha256=Hash(pe.data.data(),pe.fsize,CALG_SHA_256);

    cGr();printf("  [*] Parsing PE...\n");cr();
    if(!ParsePE(pe)){cR();printf("  [-] Not a valid PE file\n");cr();return 1;}
    ParseImps(pe);ParseExps(pe);ParseTLS(pe);ParseDbg(pe);ParseReloc(pe);ParseDD(pe);ParseVer(pe);
    cGr();printf("  [*] Extracting strings...\n");cr();
    ExtStrs(pe);
    cGr();printf("  [*] %d strings found\n",(int)pe.strs.size());cr();

    cGr();printf("  [*] Analyzing detection surface...\n");cr();
    std::vector<Finding> F;
    AnaHdr(pe,F);AnaSec(pe,F);AnaImp(pe,F);AnaExp(pe,F);AnaTLS(pe,F);AnaStr(pe,F);AnaVer(pe,F);

    if(!cfg.quick){
        cGr();printf("  [*] External tools...\n");cr();
        RunYARA(pe,cfg,F);RunSigma(pe,cfg,F);RunSysint(pe,cfg,F);RunPESieve(pe,cfg,F);
    }
    RunDynamic(pe,cfg,F);

    auto plugs=LoadPlugs(cfg.plugDir);
    if(!plugs.empty()){cGr();printf("  [*] %d plugins loaded\n",(int)plugs.size());cr();
        for(auto&pl:plugs){struct CB{std::vector<Finding>*f;};CB cb={&F};
            pl.fn(pe.path.c_str(),pe.data.data(),(unsigned int)pe.fsize,(void*)&cb);}}

    std::sort(F.begin(),F.end(),[](const Finding&a,const Finding&b){return a.sev>b.sev;});
    PrintConsole(pe,F,cfg);
    if(cfg.txt)GenTxt(pe,F,cfg);
    if(cfg.html)GenHtml(pe,F,cfg);

    cGr();printf("\n  Defeat analysis complete. %d detection points found.\n\n",(int)F.size());cr();
    return 0;
}
