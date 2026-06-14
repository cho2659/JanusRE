NTSYSAPI
NTSTATUS
NTAPI
LdrLockLoaderLock(
    _In_ ULONG Flags, // RCX
    _Out_opt_ PULONG Disposition, // RDX
    _Out_ PVOID *Cookie // R8
    );

// Return: NTSTATUS via RAX