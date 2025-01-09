#pragma once
#ifndef STRUCTS_H
#define STRUCTS_H

#include <Windows.h>

// Define constants and structs used to allocate and free pipe attributes on the paged kernel pool
typedef struct _PIPE_ATTRIBUTE {
	LIST_ENTRY list;
	char* AttributeName;
	uint64_t ValueSize;
	char* AttributeValue;
	char data[0];
} PIPE_ATTRIBUTE, * PPIPE_ATTRIBUTE;

typedef struct _PIPE_RW_HND {
	HANDLE write;
	HANDLE read;
} PIPE_RW_HND, * PPIPE_RW_HND;


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved
	);

// NtFsControlFile used to create(set) and read PIPE_ATTRIBUTE objects
typedef NTSTATUS(WINAPI* _NtFsControlFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            FsControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
	);


// NtWriteVirtualMemory API definition for write primitive after previousMode decrement
typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten
	);


#endif
