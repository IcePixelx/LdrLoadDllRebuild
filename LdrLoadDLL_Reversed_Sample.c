// from ntdl.dll, copyright goes to their respective owners.

NTSTATUS __stdcall LdrLoadDll(PWCHAR path_to_file, ULONG arg_flags, PUNICODE_STRING arg_module_file_name, PHANDLE arg_ptr_handle)
{
  int characteristics_flags; // ebx
  NTSTATUS return_value; // esi
  _LDR_DATA_TABLE_ENTRY *ldr_entry; // [esp+10h] [ebp-60h] MAPDST BYREF
  struct_6 v10; // [esp+18h] [ebp-58h] BYREF
  char v11; // [esp+64h] [ebp-Ch]

  if ( arg_flags )
    characteristics_flags = LdrpDllCharacteristicsToLoadFlags(*(_DWORD *)arg_flags);
  else
    characteristics_flags = 0;
  if ( (ShowSnaps & 9) != 0 )
    LdrpLogDbgPrint((int)"minkernel\\ntdll\\ldrapi.c", 151, "LdrLoadDll", 3, "DLL name: %wZ\n", arg_module_file_name);
  if ( (LdrpPolicyBits & 4) == 0 && ((unsigned __int16)path_to_file & 0x401) == 1025 )
    return STATUS_INVALID_PARAMETER;
  if ( (characteristics_flags & 8) == 0 || (LdrpPolicyBits & 8) != 0 )
  {
    if ( (NtCurrentTeb()->SameTebFlags & 0x2000) != 0 )
    {
      return_value = STATUS_INVALID_THREAD;
    }
    else
    {
      LdrpInitializeDllPath(arg_module_file_name->Buffer, path_to_file, &v10);
      return_value = LdrpLoadDll(arg_module_file_name, &v10, characteristics_flags, (_LDR_DATA_TABLE_ENTRY *)&ldr_entry);
      if ( v11 )
        RtlReleasePath(v10.dword1);
      if ( return_value >= 0 )
      {
        *arg_ptr_handle = ldr_entry->DllBase;
        LdrpDereferenceModule(ldr_entry);
      }
    }
  }
  else
  {
    if ( (ShowSnaps & 3) != 0 )
      LdrpLogDbgPrint(
        (int)"minkernel\\ntdll\\ldrapi.c",
        172,
        "LdrLoadDll",
        0,
        "Nonpackaged process attempted to load a packaged DLL.\n");
    if ( (ShowSnaps & 0x10) != 0 )
      __debugbreak();
    return_value = STATUS_NO_APPLICATION_PACKAGE;
  }
  if ( (ShowSnaps & 9) != 0 )
    LdrpLogDbgPrint((int)"minkernel\\ntdll\\ldrapi.c", 204, "LdrLoadDll", 4, "Status: 0x%08lx\n", return_value);
  return return_value;
}