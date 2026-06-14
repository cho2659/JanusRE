NTSYSAPI
NTSTATUS
NTAPI
LdrUnlockLoaderLock(
    _In_ ULONG Flags, // RCX
    _In_ PVOID Cookie // RDX
    );

// Return: NTSTATUS via RAX