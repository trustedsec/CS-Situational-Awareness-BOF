#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <sddl.h>
#include <stdint.h>

typedef enum _REG_ERROR_CODE {
    REG_SUCCESS = 0,
    SERVER_INACCESSIBLE = 1,
    OPEN_KEY_FAIL = 2,
    ADD_KEY_FAIL = 3,
    DEL_KEY_FAIL = 4
} REG_ERROR_CODE;

typedef enum _TASK_OPERATION {
    TaskAddOperation,
    TaskDeleteOperation
} TASK_OPERATION, * PTASK_OPERATION;

typedef struct Arguments {
    LPCSTR computerName;
    TASK_OPERATION taskOperation;
    LPCSTR taskName;
    LPCSTR program;
    LPCSTR argument;
    LPCSTR userName;
    unsigned short scheduleType;
    int hour;
    int minute;
    int second;
    unsigned short dayBitmap;
} Arguments;

// Below data structures took reference from https://cyber.wtf/2022/06/01/windows-registry-analysis-todays-episode-tasks/
typedef struct DynamicInfo {
    DWORD magic;
    FILETIME ftCreate;
    FILETIME ftLastRun;
    DWORD dwTaskState;
    DWORD dwLastErrorCode;
    FILETIME ftLastSuccessfulRun;
} DynamicInfo;

// Execution Action
typedef struct Actions {
    short version;
    DWORD sizeOfAuthor; // 0xc
    BYTE author[12];
    short magic;
    DWORD id;
    DWORD sizeOfCmd;
    wchar_t* cmd;
    DWORD sizeOfArgument;
    wchar_t* argument;
    DWORD sizeOfWorkingDirectory;
    wchar_t* workingDirectory;
    short flags;
} Actions;

typedef struct AlignedByte {
    BYTE value;
    BYTE padding[7];
} AlignedByte;

typedef struct TSTIME {
    AlignedByte isLocalized;
    FILETIME time;
} TSTIME;

// Total size is 0x68
typedef struct TimeTrigger {
    uint32_t magic;
    DWORD unknown0;
    TSTIME startBoundary;
    TSTIME endBoundary;
    TSTIME unknown1;
    DWORD repetitionIntervalSeconds;
    DWORD repetitionDurationSeconds;
    DWORD timeoutSeconds;
    DWORD mode;
    short data0;
    short data1;
    short data2;
    short pad0;
    byte stopTasksAtDurationEnd;
    byte enabled;
    short pad1;
    DWORD unknown2;
    DWORD maxDelaySeconds;
    DWORD pad2;
    uint64_t triggerId;
} TimeTrigger;

// Total size is 0x60
typedef struct LogonTrigger {
    uint32_t magic;
    DWORD unknown0;
    TSTIME startBoundary;
    TSTIME endBoundary;
    DWORD delaySeconds;
    DWORD timeoutSeconds;
    DWORD repetitionIntervalSeconds;
    DWORD repetitionDurationSeconds;
    DWORD repetitionDurationSeconds2;
    DWORD stopAtDurationEnd;
    AlignedByte enabled;
    AlignedByte unknown1;
    DWORD triggerId;
    DWORD blockPadding;
    AlignedByte skipUser; // 0x00 0x48484848484848
} LogonTrigger;

typedef struct Header {
    AlignedByte version;
    TSTIME startBoundary; // The earliest startBoundary of all triggers
    TSTIME endBoundary; // The latest endBoundary of all triggers
} Header;

// Local accounts
typedef struct UserInfo12 {
    AlignedByte skipUser; // 0x00 0x48484848484848
    AlignedByte skipSid; // 0x00 0x48484848484848
    DWORD sidType; // 0x1
    DWORD pad0; // 0x48484848
    DWORD sizeOfSid;
    DWORD pad1; // 0x48484848
    BYTE sid[12];
    DWORD pad2; // 0x48484848
    DWORD sizeOfUsername; // can be 0
    DWORD pad3; // 0x48484848
} UserInfo12;

// Domain accounts
typedef struct UserInfo28 {
    AlignedByte skipUser; // 0x00 0x48484848484848
    AlignedByte skipSid; // 0x00 0x48484848484848
    DWORD sidType; // 0x1
    DWORD pad0; // 0x48484848
    DWORD sizeOfSid;
    DWORD pad1; // 0x48484848
    BYTE sid[28];
    DWORD pad2; // 0x48484848
    DWORD sizeOfUsername; // can be 0
    DWORD pad3; // 0x48484848
} UserInfo28;

typedef struct OptionalSettings {
    DWORD idleDurationSeconds;
    DWORD idleWaitTimeoutSeconds;
    DWORD executionTimeLimitSeconds;
    DWORD deleteExpiredTaskAfter;
    DWORD priority;
    DWORD restartOnFailureDelay;
    DWORD restartOnFailureRetries;
    GUID networkId;
    // Padding for networkId
    DWORD pad0;
} OptionalSettings;

typedef struct JobBucket12 {
    DWORD flags;
    DWORD pad0; // 0x48484848
    DWORD crc32;
    DWORD pad1; // 0x48484848
    DWORD sizeOfAuthor; // 0xe
    DWORD pad2; // 0x48484848
    BYTE author[12]; // Author
    DWORD pad3;
    DWORD displayName;
    DWORD pad4; // 0x48484848
    UserInfo12 userInfo;
    DWORD sizeOfOptionalSettings;
    DWORD pad5;
    OptionalSettings optionalSettings;
} JobBucket12;

typedef struct JobBucket28 {
    DWORD flags;
    DWORD pad0; // 0x48484848
    DWORD crc32;
    DWORD pad1; // 0x48484848
    DWORD sizeOfAuthor; // 0xe
    DWORD pad2; // 0x48484848
    BYTE author[12]; // Author
    DWORD pad3;
    DWORD displayName;
    DWORD pad4; // 0x48484848
    UserInfo28 userInfo;
    DWORD sizeOfOptionalSettings;
    DWORD pad5;
    OptionalSettings optionalSettings;
} JobBucket28;

typedef struct Trigger12 {
    Header header;
    JobBucket12 jobBucket;
    BYTE trigger[];
} Trigger12;

typedef struct Trigger28 {
    Header header;
    JobBucket28 jobBucket;
    BYTE trigger[];
} Trigger28;