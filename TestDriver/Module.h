#pragma once
#include <ntifs.h>

struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONG Locked : 1;                                                 //0x0
            ULONG Waiting : 1;                                                //0x0
            ULONG Waking : 1;                                                 //0x0
            ULONG MultipleShared : 1;                                         //0x0
            ULONG Shared : 28;                                                //0x0
        };
        ULONG Value;                                                        //0x0
        VOID* Ptr;                                                          //0x0
    };
};

typedef struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONG RefCnt : 3;                                                     //0x0
        ULONG Value;                                                        //0x0
    };
}EX_FAST_REF, * PEX_FAST_REF;
typedef struct _HARDWARE_PTE
{
    ULONG Valid : 1;                                                          //0x0
    ULONG Write : 1;                                                          //0x0
    ULONG Owner : 1;                                                          //0x0
    ULONG WriteThrough : 1;                                                   //0x0
    ULONG CacheDisable : 1;                                                   //0x0
    ULONG Accessed : 1;                                                       //0x0
    ULONG Dirty : 1;                                                          //0x0
    ULONG LargePage : 1;                                                      //0x0
    ULONG Global : 1;                                                         //0x0
    ULONG CopyOnWrite : 1;                                                    //0x0
    ULONG Prototype : 1;                                                      //0x0
    ULONG reserved : 1;                                                       //0x0
    ULONG PageFrameNumber : 20;                                               //0x0
}HARDWARE_PTE, * PHARDWARE_PTE;
typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
}SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;
typedef struct _MMSUPPORT_FLAGS
{
    UCHAR WorkingSetType : 3;                                                 //0x0
    UCHAR ModwriterAttached : 1;                                              //0x0
    UCHAR TrimHard : 1;                                                       //0x0
    UCHAR MaximumWorkingSetHard : 1;                                          //0x0
    UCHAR ForceTrim : 1;                                                      //0x0
    UCHAR MinimumWorkingSetHard : 1;                                          //0x0
    UCHAR SessionMaster : 1;                                                  //0x1
    UCHAR TrimmerState : 2;                                                   //0x1
    UCHAR Reserved : 1;                                                       //0x1
    UCHAR PageStealers : 4;                                                   //0x1
    UCHAR MemoryPriority : 8;                                                 //0x2
    UCHAR WsleDeleted : 1;                                                    //0x3
    UCHAR VmExiting : 1;                                                      //0x3
    UCHAR ExpansionFailed : 1;                                                //0x3
    UCHAR Available : 5;                                                      //0x3
}MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;
typedef struct _MMSUPPORT
{
    struct _EX_PUSH_LOCK WorkingSetMutex;                                   //0x0
    struct _KGATE* ExitGate;                                                //0x4
    VOID* AccessLog;                                                        //0x8
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0xc
    ULONG AgeDistribution[7];                                               //0x14
    ULONG MinimumWorkingSetSize;                                            //0x30
    ULONG WorkingSetSize;                                                   //0x34
    ULONG WorkingSetPrivateSize;                                            //0x38
    ULONG MaximumWorkingSetSize;                                            //0x3c
    ULONG ChargedWslePages;                                                 //0x40
    ULONG ActualWslePages;                                                  //0x44
    ULONG WorkingSetSizeOverhead;                                           //0x48
    ULONG PeakWorkingSetSize;                                               //0x4c
    ULONG HardFaultCount;                                                   //0x50
    struct _MMWSL* VmWorkingSetList;                                        //0x54
    USHORT NextPageColor;                                                   //0x58
    USHORT LastTrimStamp;                                                   //0x5a
    ULONG PageFaultCount;                                                   //0x5c
    ULONG RepurposeCount;                                                   //0x60
    ULONG Spare[1];                                                         //0x64
    struct _MMSUPPORT_FLAGS Flags;                                          //0x68
}MMSUPPORT, * PMMSUPPORT;
typedef struct _MMADDRESS_NODE
{
    union
    {
        LONG Balance : 2;                                                     //0x0
        struct _MMADDRESS_NODE* Parent;                                     //0x0
    } u1;                                                                   //0x0
    struct _MMADDRESS_NODE* LeftChild;                                      //0x4
    struct _MMADDRESS_NODE* RightChild;                                     //0x8
    ULONG StartingVpn;                                                      //0xc
    ULONG EndingVpn;                                                        //0x10
}MMADDRESS_NODE, * PMMADDRESS_NODE;
typedef struct _ALPC_PROCESS_CONTEXT
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x4
    volatile ULONG PagedPoolQuotaCache;                                     //0xc
}ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;
typedef struct _MM_AVL_TABLE
{
    struct _MMADDRESS_NODE BalancedRoot;                                    //0x0
    ULONG DepthOfTree : 5;                                                    //0x14
    ULONG Unused : 3;                                                         //0x14
    ULONG NumberGenericTableElements : 24;                                    //0x14
    VOID* NodeHint;                                                         //0x18
    VOID* NodeFreeHint;                                                     //0x1c
}MM_AVL_TABLE, * PMM_AVL_TABLE;
typedef struct _KGDTENTRY
{
    USHORT LimitLow;                                                        //0x0
    USHORT BaseLow;                                                         //0x2
    union
    {
        struct
        {
            UCHAR BaseMid;                                                  //0x4
            UCHAR Flags1;                                                   //0x5
            UCHAR Flags2;                                                   //0x6
            UCHAR BaseHi;                                                   //0x7
        } Bytes;                                                            //0x4
        struct
        {
            ULONG BaseMid : 8;                                                //0x4
            ULONG Type : 5;                                                   //0x4
            ULONG Dpl : 2;                                                    //0x4
            ULONG Pres : 1;                                                   //0x4
            ULONG LimitHi : 4;                                                //0x4
            ULONG Sys : 1;                                                    //0x4
            ULONG Reserved_0 : 1;                                             //0x4
            ULONG Default_Big : 1;                                            //0x4
            ULONG Granularity : 1;                                            //0x4
            ULONG BaseHi : 8;                                                 //0x4
        } Bits;                                                             //0x4
    } HighWord;                                                             //0x4
}KGDTENTRY, * PKGDTENTRY;
typedef struct _KIDTENTRY
{
    USHORT Offset;                                                          //0x0
    USHORT Selector;                                                        //0x2
    USHORT Access;                                                          //0x4
    USHORT ExtendedOffset;                                                  //0x6
}KIDTENTRY, * PKIDTENTRY;
typedef struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONG Bitmap[1];                                                        //0x8
}KAFFINITY_EX, * PKAFFINITY_EX;
typedef union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable : 1;                                                 //0x0
    UCHAR ExecuteEnable : 1;                                                  //0x0
    UCHAR DisableThunkEmulation : 1;                                          //0x0
    UCHAR Permanent : 1;                                                      //0x0
    UCHAR ExecuteDispatchEnable : 1;                                          //0x0
    UCHAR ImageDispatchEnable : 1;                                            //0x0
    UCHAR DisableExceptionChainValidation : 1;                                //0x0
    UCHAR Spare : 1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
};
typedef union _KSTACK_COUNT
{
    volatile LONG Value;                                                    //0x0
    volatile ULONG State : 3;                                                 //0x0
    ULONG StackCount : 29;                                                    //0x0
};
typedef struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x10
    ULONG DirectoryTableBase;                                               //0x18
    struct _KGDTENTRY LdtDescriptor;                                        //0x1c
    struct _KIDTENTRY Int21Descriptor;                                      //0x24
    struct _LIST_ENTRY ThreadListHead;                                      //0x2c
    ULONG ProcessLock;                                                      //0x34
    struct _KAFFINITY_EX Affinity;                                          //0x38
    struct _LIST_ENTRY ReadyListHead;                                       //0x44
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x4c
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x50
    union
    {
        struct
        {
            volatile LONG AutoAlignment : 1;                                  //0x5c
            volatile LONG DisableBoost : 1;                                   //0x5c
            volatile LONG DisableQuantum : 1;                                 //0x5c
            volatile ULONG ActiveGroupsMask : 1;                              //0x5c
            volatile LONG ReservedFlags : 28;                                 //0x5c
        };
        volatile LONG ProcessFlags;                                         //0x5c
    };
    CHAR BasePriority;                                                      //0x60
    CHAR QuantumReset;                                                      //0x61
    UCHAR Visited;                                                          //0x62
    UCHAR Unused3;                                                          //0x63
    ULONG ThreadSeed[1];                                                    //0x64
    USHORT IdealNode[1];                                                    //0x68
    USHORT IdealGlobalNode;                                                 //0x6a
    union _KEXECUTE_OPTIONS Flags;                                          //0x6c
    UCHAR Unused1;                                                          //0x6d
    USHORT IopmOffset;                                                      //0x6e
    ULONG Unused4;                                                          //0x70
    union _KSTACK_COUNT StackCount;                                         //0x74
    struct _LIST_ENTRY ProcessListEntry;                                    //0x78
    volatile ULONGLONG CycleTime;                                           //0x80
    ULONG KernelTime;                                                       //0x88
    ULONG UserTime;                                                         //0x8c
    VOID* VdmTrapcHandler;                                                  //0x90
}KPROCESS, * pKPROCESS;
typedef struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x98
    union _LARGE_INTEGER CreateTime;                                        //0xa0
    union _LARGE_INTEGER ExitTime;                                          //0xa8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0xb0
    VOID* UniqueProcessId;                                                  //0xb4
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0xb8
    ULONG ProcessQuotaUsage[2];                                             //0xc0
    ULONG ProcessQuotaPeak[2];                                              //0xc8
    volatile ULONG CommitCharge;                                            //0xd0
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0xd4
    struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;                              //0xd8
    ULONG PeakVirtualSize;                                                  //0xdc
    ULONG VirtualSize;                                                      //0xe0
    struct _LIST_ENTRY SessionProcessLinks;                                 //0xe4
    VOID* DebugPort;                                                        //0xec
    union
    {
        VOID* ExceptionPortData;                                            //0xf0
        ULONG ExceptionPortValue;                                           //0xf0
        ULONG ExceptionPortState : 3;                                         //0xf0
    };
    struct _HANDLE_TABLE* ObjectTable;                                      //0xf4
    struct _EX_FAST_REF Token;                                              //0xf8
    ULONG WorkingSetPage;                                                   //0xfc
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x100
    struct _ETHREAD* RotateInProgress;                                      //0x104
    struct _ETHREAD* ForkInProgress;                                        //0x108
    ULONG HardwareTrigger;                                                  //0x10c
    struct _MM_AVL_TABLE* PhysicalVadRoot;                                  //0x110
    VOID* CloneRoot;                                                        //0x114
    volatile ULONG NumberOfPrivatePages;                                    //0x118
    volatile ULONG NumberOfLockedPages;                                     //0x11c
    VOID* Win32Process;                                                     //0x120
    struct _EJOB* volatile Job;                                             //0x124
    VOID* SectionObject;                                                    //0x128
    VOID* SectionBaseAddress;                                               //0x12c
    ULONG Cookie;                                                           //0x130
    ULONG Spare8;                                                           //0x134
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x138
    VOID* Win32WindowStation;                                               //0x13c
    VOID* InheritedFromUniqueProcessId;                                     //0x140
    VOID* LdtInformation;                                                   //0x144
    VOID* VdmObjects;                                                       //0x148
    ULONG ConsoleHostProcess;                                               //0x14c
    VOID* DeviceMap;                                                        //0x150
    VOID* EtwDataSource;                                                    //0x154
    VOID* FreeTebHint;                                                      //0x158
    union
    {
        struct _HARDWARE_PTE PageDirectoryPte;                              //0x160
        ULONGLONG Filler;                                                   //0x160
    };
    VOID* Session;                                                          //0x168
    UCHAR ImageFileName[15];                                                //0x16c
    UCHAR PriorityClass;                                                    //0x17b
    struct _LIST_ENTRY JobLinks;                                            //0x17c
    VOID* LockedPagesList;                                                  //0x184
    struct _LIST_ENTRY ThreadListHead;                                      //0x188
    VOID* SecurityPort;                                                     //0x190
    VOID* PaeTop;                                                           //0x194
    volatile ULONG ActiveThreads;                                           //0x198
    ULONG ImagePathHash;                                                    //0x19c
    ULONG DefaultHardErrorProcessing;                                       //0x1a0
    LONG LastThreadExitStatus;                                              //0x1a4
    struct _PEB* Peb;                                                       //0x1a8
    struct _EX_FAST_REF PrefetchTrace;                                      //0x1ac
    union _LARGE_INTEGER ReadOperationCount;                                //0x1b0
    union _LARGE_INTEGER WriteOperationCount;                               //0x1b8
    union _LARGE_INTEGER OtherOperationCount;                               //0x1c0
    union _LARGE_INTEGER ReadTransferCount;                                 //0x1c8
    union _LARGE_INTEGER WriteTransferCount;                                //0x1d0
    union _LARGE_INTEGER OtherTransferCount;                                //0x1d8
    ULONG CommitChargeLimit;                                                //0x1e0
    volatile ULONG CommitChargePeak;                                        //0x1e4
    VOID* AweInfo;                                                          //0x1e8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x1ec
    struct _MMSUPPORT Vm;                                                   //0x1f0
    struct _LIST_ENTRY MmProcessLinks;                                      //0x25c
    VOID* HighestUserAddress;                                               //0x264
    ULONG ModifiedPageCount;                                                //0x268
    union
    {
        ULONG Flags2;                                                       //0x26c
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x26c
            ULONG AccountingFolded : 1;                                       //0x26c
            ULONG NewProcessReported : 1;                                     //0x26c
            ULONG ExitProcessReported : 1;                                    //0x26c
            ULONG ReportCommitChanges : 1;                                    //0x26c
            ULONG LastReportMemory : 1;                                       //0x26c
            ULONG ReportPhysicalPageChanges : 1;                              //0x26c
            ULONG HandleTableRundown : 1;                                     //0x26c
            ULONG NeedsHandleRundown : 1;                                     //0x26c
            ULONG RefTraceEnabled : 1;                                        //0x26c
            ULONG NumaAware : 1;                                              //0x26c
            ULONG ProtectedProcess : 1;                                       //0x26c
            ULONG DefaultPagePriority : 3;                                    //0x26c
            ULONG PrimaryTokenFrozen : 1;                                     //0x26c
            ULONG ProcessVerifierTarget : 1;                                  //0x26c
            ULONG StackRandomizationDisabled : 1;                             //0x26c
            ULONG AffinityPermanent : 1;                                      //0x26c
            ULONG AffinityUpdateEnable : 1;                                   //0x26c
            ULONG PropagateNode : 1;                                          //0x26c
            ULONG ExplicitAffinity : 1;                                       //0x26c
        };
    };
    union
    {
        ULONG Flags;                                                        //0x270
        struct
        {
            ULONG CreateReported : 1;                                         //0x270
            ULONG NoDebugInherit : 1;                                         //0x270
            ULONG ProcessExiting : 1;                                         //0x270
            ULONG ProcessDelete : 1;                                          //0x270
            ULONG Wow64SplitPages : 1;                                        //0x270
            ULONG VmDeleted : 1;                                              //0x270
            ULONG OutswapEnabled : 1;                                         //0x270
            ULONG Outswapped : 1;                                             //0x270
            ULONG ForkFailed : 1;                                             //0x270
            ULONG Wow64VaSpace4Gb : 1;                                        //0x270
            ULONG AddressSpaceInitialized : 2;                                //0x270
            ULONG SetTimerResolution : 1;                                     //0x270
            ULONG BreakOnTermination : 1;                                     //0x270
            ULONG DeprioritizeViews : 1;                                      //0x270
            ULONG WriteWatch : 1;                                             //0x270
            ULONG ProcessInSession : 1;                                       //0x270
            ULONG OverrideAddressSpace : 1;                                   //0x270
            ULONG HasAddressSpace : 1;                                        //0x270
            ULONG LaunchPrefetched : 1;                                       //0x270
            ULONG InjectInpageErrors : 1;                                     //0x270
            ULONG VmTopDown : 1;                                              //0x270
            ULONG ImageNotifyDone : 1;                                        //0x270
            ULONG PdeUpdateNeeded : 1;                                        //0x270
            ULONG VdmAllowed : 1;                                             //0x270
            ULONG CrossSessionCreate : 1;                                     //0x270
            ULONG ProcessInserted : 1;                                        //0x270
            ULONG DefaultIoPriority : 3;                                      //0x270
            ULONG ProcessSelfDelete : 1;                                      //0x270
            ULONG SetTimerResolutionLink : 1;                                 //0x270
        };
    };
    LONG ExitStatus;                                                        //0x274
    struct _MM_AVL_TABLE VadRoot;                                           //0x278
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x298
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x2a8
    ULONG RequestedTimerResolution;                                         //0x2b0
    ULONG ActiveThreadsHighWatermark;                                       //0x2b4
    ULONG SmallestTimerResolution;                                          //0x2b8
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x2bc
}EPROCESS, * pEPROCESS;

extern PVOID *NTAPI PsGetProcessWow64Process(
    __in PEPROCESS Process
);

 typedef struct _PEB_LDR_DATA32
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    ULONG SsHandle;                                                         //0x8
    LIST_ENTRY32 InLoadOrderModuleList;                               //0x10
    LIST_ENTRY32 InMemoryOrderModuleList;                             //0x20
    LIST_ENTRY32 InInitializationOrderModuleList;                     //0x30
    ULONG EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    ULONG ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA32,* PPEB_LDR_DATA32;

#pragma pack(push, 4)
typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
    LIST_ENTRY32 InMemoryOrderLinks;                                  //0x8
    LIST_ENTRY32 InInitializationOrderLinks;                          //0x10
    ULONG DllBase;                                                          //0x14
    ULONG EntryPoint;                                                       //0x18
    ULONG SizeOfImage;                                                      //0x1c
    UNICODE_STRING32 FullDllName;                                     //0x24
    UNICODE_STRING32 BaseDllName;                                     //0x2c
    ULONG Flags;                                                            //0x34
    USHORT LoadCount;                                                       //0x38
    USHORT TlsIndex;                                                        //0x3a
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x3c
        struct
        {
            ULONG SectionPointer;                                           //0x3c
            ULONG CheckSum;                                                 //0x40
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x44
        ULONG LoadedImports;                                                //0x44
    };
    ULONG EntryPointActivationContext;                //0x48
    ULONG PatchInformation;                                                 //0x4c
    LIST_ENTRY32 ForwarderLinks;                                      //0x50
    LIST_ENTRY32 ServiceTagLinks;                                     //0x58
    LIST_ENTRY32 StaticLinks;                                         //0x60
    ULONG ContextInformation;                                               //0x68
    ULONG OriginalBase;                                                     //0x6c
    union _LARGE_INTEGER LoadTime;                                          //0x70
}LDR_DATA_TABLE_ENTRY32,*PLDR_DATA_TABLE_ENTRY32;
#pragma pack(pop)

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsLegacyProcess : 1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR SpareBits : 3;                                              //0x3
        };
    };
    ULONG Mutant;                                                           //0x4
    ULONG ImageBaseAddress;                                                 //0x8
    ULONG Ldr;                                                              //0xc
    ULONG ProcessParameters;                                                //0x10
    ULONG SubSystemData;                                                    //0x14
    ULONG ProcessHeap;                                                      //0x18
    ULONG FastPebLock;                                                      //0x1c
    ULONG AtlThunkSListPtr;                                                 //0x20
    ULONG IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x28
            ULONG ProcessInitializing : 1;                                    //0x28
            ULONG ProcessUsingVEH : 1;                                        //0x28
            ULONG ProcessUsingVCH : 1;                                        //0x28
            ULONG ProcessUsingFTH : 1;                                        //0x28
            ULONG ReservedBits0 : 27;                                         //0x28
        };
    };
    union
    {
        ULONG KernelCallbackTable;                                          //0x2c
        ULONG UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved[1];                                                //0x30
    ULONG AtlThunkSListPtr32;                                               //0x34
    ULONG ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    ULONG TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    ULONG ReadOnlySharedMemoryBase;                                         //0x4c
    ULONG HotpatchInformation;                                              //0x50
    ULONG ReadOnlyStaticServerData;                                         //0x54
    ULONG AnsiCodePageData;                                                 //0x58
    ULONG OemCodePageData;                                                  //0x5c
    ULONG UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    ULONG ProcessHeaps;                                                     //0x90
    ULONG GdiSharedHandleTable;                                             //0x94
    ULONG ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    ULONG LoaderLock;                                                       //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    ULONG PostProcessInitRoutine;                                           //0x14c
    ULONG TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    ULONG pShimData;                                                        //0x1e8
    ULONG AppCompatInfo;                                                    //0x1ec
    struct _STRING32 CSDVersion;                                            //0x1f0
    ULONG ActivationContextData;                                            //0x1f8
    ULONG ProcessAssemblyStorageMap;                                        //0x1fc
    ULONG SystemDefaultActivationContextData;                               //0x200
    ULONG SystemAssemblyStorageMap;                                         //0x204
    ULONG MinimumStackCommit;                                               //0x208
    ULONG FlsCallback;                                                      //0x20c
    struct LIST_ENTRY32 FlsListHead;                                        //0x210
    ULONG FlsBitmap;                                                        //0x218
    ULONG FlsBitmapBits[4];                                                 //0x21c
    ULONG FlsHighIndex;                                                     //0x22c
    ULONG WerRegistrationData;                                              //0x230
    ULONG WerShipAssertPtr;                                                 //0x234
    ULONG pContextData;                                                     //0x238
    ULONG pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x240
            ULONG CritSecTracingEnabled : 1;                                  //0x240
            ULONG SpareTracingBits : 30;                                      //0x240
        };
    };
}PEB32,*PPEB32;

__declspec(align(8)) typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA,*PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    USHORT TlsIndex;                                                        //0x6e
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x70
        struct
        {
            VOID* SectionPointer;                                           //0x70
            ULONG CheckSum;                                                 //0x78
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x80
        VOID* LoadedImports;                                                //0x80
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* PatchInformation;                                                 //0x90
    struct _LIST_ENTRY ForwarderLinks;                                      //0x98
    struct _LIST_ENTRY ServiceTagLinks;                                     //0xa8
    struct _LIST_ENTRY StaticLinks;                                         //0xb8
    VOID* ContextInformation;                                               //0xc8
    ULONGLONG OriginalBase;                                                 //0xd0
    union _LARGE_INTEGER LoadTime;                                          //0xd8
} LDR_DATA_TABLE_ENTRY64,*PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsLegacyProcess : 1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR SpareBits : 3;                                              //0x3
        };
    };
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    PPEB_LDR_DATA Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    VOID* AtlThunkSListPtr;                                                 //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ReservedBits0 : 27;                                         //0x50
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved[1];                                                //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* HotpatchInformation;                                              //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID(*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
    struct _LIST_ENTRY FlsListHead;                                         //0x328
    VOID* FlsBitmap;                                                        //0x338
    ULONG FlsBitmapBits[4];                                                 //0x340
    ULONG FlsHighIndex;                                                     //0x350
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pContextData;                                                     //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG SpareTracingBits : 30;                                      //0x378
        };
    };
}PEB64,*PPEB64;

EXTERN_C PPEB64
PsGetProcessPeb(
    __in PEPROCESS Process
);

EXTERN_C NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);



ULONG_PTR GetModuleR3(HANDLE Pid, char* ModuleName, PULONG_PTR sizeImage);


typedef struct _MMEMORY_BASIC_INFORMATION
{
    ULONG64 BaseAddress;
    ULONG64 AllocationBase;
    ULONG64 AllocationProtect;
    ULONG64 RegionSize;
    ULONG64 State;
    ULONG64 Protect;
    ULONG64 Type;
} MMEMORY_BASIC_INFORMATION, * PMMEMORY_BASIC_INFORMATION;

// typedef struct _MEMORY_BASIC_INFORMATION32
// {
// 	ULONG BaseAddress;
// 	ULONG AllocationBase;
// 	ULONG AllocationProtect;
// 	ULONG RegionSize;
// 	ULONG State;
// 	ULONG Protect;
// 	ULONG Type;
// } MEMORY_BASIC_INFORMATION32, * PMEMORY_BASIC_INFORMATION32;

NTSTATUS QueryMemory(HANDLE pid, ULONG64 targetAddr, PMEMORY_BASIC_INFORMATION pInfo);

