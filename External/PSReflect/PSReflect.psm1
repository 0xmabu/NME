#Requires -Version 2

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
# 
# NME framwwork additions/changes:
# Added parameters "EntryPoint" and "ExactSpelling"
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError,

        [string]
        $EntryPoint,

        [Switch]
        $ExactSpelling
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    if ($ExactSpelling) { $Properties['ExactSpelling'] = $ExactSpelling }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.

NME framwwork additions/changes:
Added support for "EntryPoint" and "ExactSpelling"
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [string]
        $EntryPoint,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $ExactSpelling,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]

            $EntryPointField = $DllImport.GetField('EntryPoint') #NME addition
            $ExactSpellingField = $DllImport.GetField('ExactSpelling') #NME addition
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            if ($EntryPoint) { $EPValue = $EntryPoint } #NME addition
            if ($ExactSpelling) { $ESValue = $True } else { $ESValue = $False } #NME addition

            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])

            if($EntryPoint) #Quick and dirty if/else for "EntryPoint" support
            {
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                    $Constructor,
                    $DllName,
                    [Reflection.PropertyInfo[]] @(),
                    [Object[]] @(),
                    [Reflection.FieldInfo[]] @(
                        $ExactSpellingField
                        $EntryPointField
                        $SetLastErrorField,
                        $CallingConventionField,
                        $CharsetField
                    ),
                    [Object[]] @(
                        $ESValue,
                        $EPValue,
                        $SLEValue,
                        ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                        ([Runtime.InteropServices.CharSet] $Charset)
                    )
                )
            }
            else
            {
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                    $Constructor,
                    $DllName,
                    [Reflection.PropertyInfo[]] @(),
                    [Object[]] @(),
                    [Reflection.FieldInfo[]] @(
                        $ExactSpellingField
                        $SetLastErrorField,
                        $CallingConventionField,
                        $CharsetField
                    ),
                    [Object[]] @(
                        $ESValue,
                        $SLEValue,
                        ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                        ([Runtime.InteropServices.CharSet] $Charset)
                    )
                )
            }

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


$Mod = New-InMemoryModule -ModuleName Win32

### ENUMS

$enum_SHARE_TYPE = psenum $Mod SHARE_TYPE UInt64 @{
    STYPE_DISKTREE  = 0
    STYPE_PRINTQ    = 1
    STYPE_DEVICE    = 2
    STYPE_IPC       = 3
    STYPE_TEMPORARY = 1073741824
    STYPE_SPECIAL   = 2147483648
}

$enum_USER_PRIV = psenum $Mod USER_PRIV UInt32 @{
    USER_PRIV_GUEST = 0
    USER_PRIV_USER  = 1
    USER_PRIV_ADMIN = 2
}

$enum_USER_FLAGS = psenum $Mod USER_FLAGS UInt64 @{
    UF_SCRIPT                          = 0x1
    UF_ACCOUNTDISABLE                  = 0x2
    UF_HOMEDIR_REQUIRED                = 0x8
    UF_LOCKOUT                         = 0x10
    UF_PASSWD_NOTREQD                  = 0x20
    UF_PASSWD_CANT_CHANGE              = 0x40
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80
    UF_TEMP_DUPLICATE_ACCOUNT          = 0x100
    UF_NORMAL_ACCOUNT                  = 0x200
    UF_INTERDOMAIN_TRUST_ACCOUNT       = 0x800
    UF_WORKSTATION_TRUST_ACCOUNT       = 0x1000
    UF_SERVER_TRUST_ACCOUNT            = 0x2000
    UF_DONT_EXPIRE_PASSWD              = 0x10000
    UF_MNS_LOGON_ACCOUNT               = 0x20000
    UF_SMARTCARD_REQUIRED              = 0x40000
    UF_TRUSTED_FOR_DELEGATION          = 0x80000
    UF_NOT_DELEGATED                   = 0x100000
    UF_USE_DES_KEY_ONLY                = 0x200000
    UF_DONT_REQUIRE_PREAUTH            = 0x400000
    UF_PASSWORD_EXPIRED                = 0x800000
}

$enum_AUTH_FLAGS = psenum $Mod AUTH_FLAGS UInt32 @{
    AF_OP_PRINT    = 0x1
    AF_OP_COMM     = 0x2
    AF_OP_SERVER   = 0x3
    AF_OP_ACCOUNTS = 0x4
}

<#
$enum_SID_NAME_USE = psenum $Mod SID_NAME_USE UInt32 @{
    SidTypeUser           = 1
    SidTypeGroup          = 2
    SidTypeDomain         = 3
    SidTypeAlias          = 4
    SidTypeWellKnownGroup = 5
    SidTypeDeletedAccount = 6
    SidTypeInvalid        = 7
    SidTypeUnknown        = 8
    SidTypeComputer       = 9
    SidTypeLabel          = 10
}
#>

$enum_DNSRecordTypes = psenum $Mod DNSRecordTypes Int32 @{
    DNS_TYPE_A       = 0x1
    DNS_TYPE_NS      = 0x2
    DNS_TYPE_MD      = 0x3
    DNS_TYPE_MF      = 0x4
    DNS_TYPE_CNAME   = 0x5
    DNS_TYPE_SOA     = 0x6
    DNS_TYPE_MB      = 0x7
    DNS_TYPE_MG      = 0x8
    DNS_TYPE_MR      = 0x9
    DNS_TYPE_NULL    = 0xA
    DNS_TYPE_WKS     = 0xB
    DNS_TYPE_PTR     = 0xC
    DNS_TYPE_HINFO   = 0xD
    DNS_TYPE_MINFO   = 0xE
    DNS_TYPE_MX      = 0xF
    DNS_TYPE_TEXT    = 0x10 # This is how it's specified on MSDN
    DNS_TYPE_TXT     = 0x10 # DNS_TYPE_TEXT
    DNS_TYPE_RP      = 0x11
    DNS_TYPE_AFSDB   = 0x12
    DNS_TYPE_X25     = 0x13
    DNS_TYPE_ISDN    = 0x14
    DNS_TYPE_RT      = 0x15
    DNS_TYPE_NSAP    = 0x16
    DNS_TYPE_NSAPPTR = 0x17
    DNS_TYPE_SIG     = 0x18
    DNS_TYPE_KEY     = 0x19
    DNS_TYPE_PX      = 0x1A
    DNS_TYPE_GPOS    = 0x1B
    DNS_TYPE_AAAA    = 0x1C
    DNS_TYPE_LOC     = 0x1D
    DNS_TYPE_NXT     = 0x1E
    DNS_TYPE_EID     = 0x1F
    DNS_TYPE_NIMLOC  = 0x20
    DNS_TYPE_SRV     = 0x21
    DNS_TYPE_ATMA    = 0x22
    DNS_TYPE_NAPTR   = 0x23
    DNS_TYPE_KX      = 0x24
    DNS_TYPE_CERT    = 0x25
    DNS_TYPE_A6      = 0x26
    DNS_TYPE_DNAME   = 0x27
    DNS_TYPE_SINK    = 0x28
    DNS_TYPE_OPT     = 0x29
    DNS_TYPE_DS      = 0x2B
    DNS_TYPE_RRSIG   = 0x2E
    DNS_TYPE_NSEC    = 0x2F
    DNS_TYPE_DNSKEY  = 0x30
    DNS_TYPE_DHCID   = 0x31
    DNS_TYPE_UINFO   = 0x64
    DNS_TYPE_UID     = 0x65
    DNS_TYPE_GID     = 0x66
    DNS_TYPE_UNSPEC  = 0x67
    DNS_TYPE_ADDRS   = 0xF8
    DNS_TYPE_TKEY    = 0xF9
    DNS_TYPE_TSIG    = 0xFA
    DNS_TYPE_IXFR    = 0xFB
    DNS_TYPE_AFXR    = 0xFC
    DNS_TYPE_MAILB   = 0xFD
    DNS_TYPE_MAILA   = 0xFE
    DNS_TYPE_ALL     = 0xFF
    DNS_TYPE_ANY     = 0xFF
    DNS_TYPE_WINS    = 0xFF01
    DNS_TYPE_WINSR   = 0xFF02
    DNS_TYPE_NBSTAT  = 0xFF02 #DNS_TYPE_WINSR
}

$enum_DNSClassTypes = psenum $Mod DNSClassTypes Int32 @{
    DNS_CLASS_INTERNET = 0x0001
    DNS_CLASS_CSNET	   = 0x0002
    DNS_CLASS_CHAOS	   = 0x0003
    DNS_CLASS_HESIOD   = 0x0004
    DNS_CLASS_NONE     = 0x00fe
    DNS_CLASS_ALL      = 0x00ff
    DNS_CLASS_ANY      = 0x00ff
}

$enum_DNSQueryTypes = psenum $Mod DNSQueryTypes Int32 @{
    DNS_OPCODE_QUERY         = 0x0000
    DNS_OPCODE_IQUERY        = 0x0001
    DNS_OPCODE_SERVER_STATUS = 0x0002
    DNS_OPCODE_UNKNOWN       = 0x0003
    DNS_OPCODE_NOTIFY        = 0x0004
    DNS_OPCODE_UPDATE        = 0x0005
}

$enum_DNSQueryOptions = psenum $Mod DNSQueryOptions Int32 @{
    DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 1
    DNS_QUERY_BYPASS_CACHE              = 8
    DNS_QUERY_DONT_RESET_TTL_VALUES     = 0x100000
    DNS_QUERY_NO_HOSTS_FILE             = 0x40
    DNS_QUERY_NO_LOCAL_NAME             = 0x20
    DNS_QUERY_NO_NETBT                  = 0x80
    DNS_QUERY_NO_RECURSION              = 4
    DNS_QUERY_NO_WIRE_QUERY             = 0x10
    DNS_QUERY_RESERVED                  = -16777216
    DNS_QUERY_RETURN_MESSAGE            = 0x200
    DNS_QUERY_STANDARD                  = 0
    DNS_QUERY_TREAT_AS_FQDN             = 0x1000
    DNS_QUERY_USE_TCP_ONLY              = 2
    DNS_QUERY_WIRE_ONLY                 = 0x100
    DNS_QUERY_MULTICAST_ONLY            = 0x00000400
    DNS_QUERY_NO_MULTICAST              = 0x00000800
}

$enum_DNSFreeTypes = psenum $Mod DNSFreeTypes Int32 @{
    DnsFreeFlat                = 0
    DnsFreeRecordList          = 1
    DnsFreeParsedMessageFields = 2
}

$enum_DNSRecordFlags = psenum $Mod DNSRecordFlags Int32 @{
    DNSREC_QUESTION   = 0x00000000
    DNSREC_ANSWER     = 0x00000001
    DNSREC_AUTHORITY  = 0x00000002
    DNSREC_ADDITIONAL = 0x00000003
}


### STRUCTS

$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type    = field 1 UInt32
    shi1_remark  = field 2 String -MarshalAs @('LPWStr')
}

$USER_INFO_3 = struct $Mod USER_INFO_3 @{
    usri3_name             = field 0 String -MarshalAs @('LPWStr')
    usri3_password         = field 1 String -MarshalAs @('LPWStr')
    usri3_password_age     = field 2 UInt32
    usri3_priv             = field 3 $enum_USER_PRIV
    usri3_home_dir         = field 4 String -MarshalAs @('LPWStr')
    usri3_comment          = field 5 String -MarshalAs @('LPWStr') 
    usri3_flags            = field 6 $enum_USER_FLAGS
    usri3_script_path      = field 7 String -MarshalAs @('LPWStr')
    usri3_auth_flags       = field 8 $enum_AUTH_FLAGS
    usri3_full_name        = field 9 String -MarshalAs @('LPWStr')
    usri3_usr_comment      = field 10 String -MarshalAs @('LPWStr')
    usri3_params           = field 11 String -MarshalAs @('LPWStr')
    usri3_workstations     = field 12 String -MarshalAs @('LPWStr')
    usri3_last_logoff      = field 13 UInt32
    usri3_last_logon       = field 14 UInt32
    usri3_acct_expires     = field 15 UInt32 
    usri3_max_storage      = field 16 UInt32 
    usri3_units_per_week   = field 17 UInt32
    usri3_logon_hours      = field 18 IntPtr # -MarshalAs @('PBYTE')  
    usri3_bad_pw_count     = field 19 UInt32 
    usri3_num_logons       = field 20 UInt32 
    usri3_logon_server     = field 21 String -MarshalAs @('LPWStr')
    usri3_country_code     = field 22 UInt32 
    usri3_code_page        = field 23 UInt32
    usri3_user_id          = field 24 UInt32
    usri3_primary_group_id = field 25 UInt32
    usri3_profile          = field 26 String -MarshalAs @('LPWStr')
    usri3_home_dir_drive   = field 27 String -MarshalAs @('LPWStr')
    usri3_password_expired = field 28 UInt32
}

$USER_MODALS_INFO_0 = struct $Mod USER_MODALS_INFO_0 @{
    usrmod0_min_passwd_len    = field 0 UInt32
    usrmod0_max_passwd_age    = field 1 UInt32
    usrmod0_min_passwd_age    = field 2 UInt32
    usrmod0_force_logoff      = field 3 UInt32
    usrmod0_password_hist_len = field 4 UInt32
}

$USER_MODALS_INFO_1 = struct $Mod USER_MODALS_INFO_1 @{
    usrmod1_role    = field 0 UInt32
    usrmod1_primary = field 1 String -MarshalAs @('LPWStr')
}

$USER_MODALS_INFO_2 = struct $Mod USER_MODALS_INFO_2 @{
    usrmod2_domain_name = field 0 String -MarshalAs @('LPWStr')
    usrmod2_domain_id   = field 1 IntPtr
}

$USER_MODALS_INFO_3 = struct $Mod USER_MODALS_INFO_3 @{
    usrmod3_lockout_duration           = field 0 UInt32 
    usrmod3_lockout_observation_window = field 1 UInt32
    usrmod3_lockout_threshold          = field 2 Uint32
}

$SID_IDENTIFIER_AUTHORITY = struct $Mod SID_IDENTIFIER_AUTHORITY @{
    Value = field 0 Byte[] -MarshalAs @('ByValArray', 6)
}

$SID = struct $Mod SID @{
    Revision            = field 0 Byte
    SubAuthorityCount   = field 1 Byte
    IdentifierAuthority = field 2 $SID_IDENTIFIER_AUTHORITY
    SubAuthority        = field 3 Uint32[] -MarshalAs @('ByValArray', 15)
}

$GROUP_INFO_2 = struct $Mod GROUP_INFO_2 @{
    grpi2_name       = field 0 String -MarshalAs @('LPWStr')
    grpi2_comment    = field 1 String -MarshalAs @('LPWStr')
    grpi2_group_id   = field 2 UInt32
    grpi2_attributes = field 3 UInt32
}

$GROUP_USERS_INFO_0 = struct $Mod GROUP_USERS_INFO_0 @{
    grui0_name = field 0 String -MarshalAs @('LPWStr')
}
        
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name    = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}
        
$LOCALGROUP_MEMBERS_INFO_3 = struct $Mod LOCALGROUP_MEMBERS_INFO_3 @{
    lgrmi3_domainandname = field 0 String -MarshalAs @('LPWStr')
}

$DOMAIN_PASSWORD_INFORMATION = struct $Mod DOMAIN_PASSWORD_INFORMATION @{
     MinPasswordLength     = field 0 UInt16
     PasswordHistoryLength = field 1 UInt16
     PasswordPropertie     = field 2 UInt64
     MaxPasswordAge        = field 3 UInt64
     MinPasswordAge        = field 4 Uint64
} 

$WKSTA_USER_INFO_1 = struct $Mod WKSTA_USER_INFO_1 @{
    wkui1_username     = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains  = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}

$USE_INFO_2 = struct $Mod USE_INFO_2 @{
    ui2_local      = field 0 String # -MarshalAs @('LPWStr')
    ui2_remote     = field 1 String # -MarshalAs @('LPWStr')
    ui2_password   = field 2 String # -MarshalAs @('LPWStr')
    ui2_status     = field 3 UInt32
    ui2_asg_type   = field 4 UInt32
    ui2_refcount   = field 5 UInt32
    ui2_usecount   = field 6 UInt32
    ui2_username   = field 7 String #-MarshalAs @('LPWStr')
    ui2_domainname = field 8 String #-MarshalAs @('LPWStr')
}

$USE_INFO_1 = struct $Mod USE_INFO_1 @{
    ui1_local      = field 0 String # -MarshalAs @('LPWStr')
    ui1_remote     = field 1 String # -MarshalAs @('LPWStr')
    ui1_password   = field 2 String # -MarshalAs @('LPWStr')
    ui1_status     = field 3 UInt32
    ui1_asg_type   = field 4 UInt32
    ui1_refcount   = field 5 UInt32
    ui1_usecount   = field 6 UInt32
}

# the NetSessionEnum result structure
<#$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}#>

# the NetFileEnum result structure
<#$FILE_INFO_3 = struct $Mod FILE_INFO_3 @{
    fi3_id = field 0 UInt32
    fi3_permissions = field 1 UInt32
    fi3_num_locks = field 2 UInt32
    fi3_pathname = field 3 String -MarshalAs @('LPWStr')
    fi3_username = field 4 String -MarshalAs @('LPWStr')
}#>

# the NetConnectionEnum result structure
<#$CONNECTION_INFO_1 = struct $Mod CONNECTION_INFO_1 @{
    coni1_id = field 0 UInt32
    coni1_type = field 1 UInt32
    coni1_num_opens = field 2 UInt32
    coni1_num_users = field 3 UInt32
    coni1_time = field 4 UInt32
    coni1_username = field 5 String -MarshalAs @('LPWStr')
    coni1_netname = field 6 String -MarshalAs @('LPWStr')
}#>

$DNS_A_DATA = struct $Mod DNS_A_DATA @{
    IpAddress = field 0 uint32
}

$DNS_SOA_DATA = struct $Mod DNS_SOA_DATA @{
    pNamePrimaryServer = field 0 intptr
    pNameAdministrator = field 1 intptr
    dwSerialNo         = field 2 uint32
    dwRefresh          = field 3 uint32
    dwRetry            = field 4 uint32
    dwExpire           = field 5 uint32
    dwDefaultTtl       = field 6 uint32
}

$DNS_PTR_DATA = struct $Mod DNS_PTR_DATA @{
    pNameHost = field 0 intptr
}

$DNS_MINFO_DATA = struct $Mod DNS_MINFO_DATA @{
    pNameMailbox       = field 0 intptr
    pNameErrorsMailbox = field 1 intptr
}

$DNS_MX_DATA = struct $Mod DNS_MX_DATA @{
    pNameExchange = field 0 intptr
    wPreference   = field 1 uint16
    Pad           = field 2 uint16
}

$DNS_TXT_DATA = struct $Mod DNS_TXT_DATA @{
    dwStringCount = field 0 uint32
    pStringArray  = field 1 intptr
}

$DNS_NULL_DATA = struct $Mod DNS_NULL_DATA @{
    dwByteCount = field 0 uint32
    Data        = field 1 intptr
}

$DNS_WKS_DATA = struct $Mod DNS_WKS_DATA @{
    IpAddress  = field 0 uint32
    chProtocol = field 1 byte
    BitMask    = field 2 intptr
}

$DNS_AAAA_DATA = struct $Mod DNS_AAAA_DATA @{
    Ip6Address0 = field 0 uint32
    Ip6Address1 = field 1 uint32
    Ip6Address2 = field 2 uint32
    Ip6Address3 = field 3 uint32
}

$DNS_KEY_DATA = struct $Mod DNS_KEY_DATA @{
    wFlags      = field 0 uint16
    chProtocol  = field 1 byte
    chAlgorithm = field 2 byte
    Key         = field 3 intptr
}

$DNS_SIG_DATA = struct $Mod DNS_SIG_DATA @{
    pNameSigner   = field 0 intptr
    wTypeCovered  = field 1 uint16
    chAlgorithm   = field 2 byte
    chLabelCount  = field 3 byte
    dwOriginalTtl = field 4 uint32
    dwExpiration  = field 5 uint32
    dwTimeSigned  = field 6 uint32
    wKeyTag       = field 7 uint16
    Pad           = field 8 uint16
    Signature     = field 9 intptr
}

$DNS_ATMA_DATA = struct $Mod DNS_ATMA_DATA @{
    AddressType = field 0 byte
    Address0    = field 1 byte
    Address1    = field 2 byte
    Address2    = field 3 byte
    Address3    = field 4 byte
    Address4    = field 5 byte
    Address5    = field 6 byte
    Address6    = field 7 byte
    Address7    = field 8 byte
    Address8    = field 9 byte
    Address9    = field 10 byte
    Address10   = field 11 byte
    Address11   = field 12 byte
    Address12   = field 13 byte
    Address13   = field 14 byte
    Address14   = field 15 byte
    Address15   = field 16 byte
    Address16   = field 17 byte
    Address17   = field 18 byte
    Address18   = field 19 byte
    Address19   = field 20 byte
}

$DNS_NXT_DATA = struct $Mod DNS_NXT_DATA @{
    pNameNext = field 0 intptr
    wNumTypes = field 1 uint16
    wTypes    = field 2 intptr
}

$DNS_SRV_DATA = struct $Mod DNS_SRV_DATA @{
    pNameTarget = field 0 intptr
    uPriority   = field 1 uint16
    wWeight     = field 2 uint16
    wPort       = field 3 uint16
    Pad         = field 4 uint16
}

$DNS_NAPTR_DATA = struct $Mod DNS_NAPTR_DATA @{
    wOrder             = field 0 uint16
    wPreference        = field 1 uint16
    pFlags             = field 2 intptr
    pService           = field 3 intptr
    pRegularExpression = field 4 IntPtr
    pReplacement       = field 5 IntPtr
}

$DNS_OPT_DATA = struct $Mod DNS_OPT_DATA @{
    wDataLength = field 0 uint16
    wPad        = field 1 uint16
    Data        = field 2 IntPtr
}

$DNS_DS_DATA = struct $Mod DNS_DS_DATA @{
    wKeyTag       = field 0 uint16
    chAlgorithm   = field 1 byte
    chDigestType  = field 2 byte
    wDigestLength = field 3 uint16
    wPad          = field 4 uint16
    Digest        = field 5 intptr
}

$DNS_RRSIG_DATA = struct $Mod DNS_RRSIG_DATA @{
    pNameSigner   = field 0 intptr
    wTypeCovered  = field 1 uint16
    chAlgorithm   = field 2 byte
    chLabelCount  = field 3 byte
    dwOriginalTtl = field 4 uint32
    dwExpiration  = field 5 uint32
    dwTimeSigned  = field 6 uint32
    wKeyTag       = field 7 uint16
    Pad           = field 8 uint16
    Signature     = field 9 intptr
}

$DNS_NSEC_DATA = struct $Mod DNS_NSEC_DATA @{
    pNextDomainName    = field 0 intptr
    wTypeBitMapsLength = field 1 uint16
    wPad               = field 2 uint16
    TypeBitMaps        = field 3 intptr
}

$DNS_DNSKEY_DATA = struct $Mod DNS_DNSKEY_DATA @{
    wFlags       = field 0 uint16
    chProtocol   = field 1 byte
    chAlgorithm  = field 2 byte
    wKeyLength   = field 3 uint16
    wPad         = field 4 uint16
    Key          = field 5 intptr
}

$DNS_TKEY_DATA = struct $Mod DNS_TKEY_DATA @{
    pNameAlgorithm    = field 0 intptr
    pAlgorithmPacket  = field 1 intptr
    pKey              = field 2 IntPtr
    pOtherData        = field 3 intptr
    dwCreateTime      = field 4 uint32
    dwExpireTime      = field 5 uint32
    wMode             = field 6 uint16
    wError            = field 7 uint16
    wKeyLength        = field 8 uint16
    wOtherLength      = field 9 uint16
    cAlgNameLength    = field 10 byte
    bPacketPointers   = field 11 int32
}

$DNS_TSIG_DATA = struct $Mod DNS_TSIG_DATA @{
    pNameAlgorithm   = field 0 intptr
    pAlgorithmPacket = field 1 intptr
    pSignature       = field 2 intptr
    pOtherData       = field 3 intptr
    i64CreateTime    = field 4 long
    wFudgeTime       = field 5 uint16
    wOriginalXid     = field 6 uint16
    wError           = field 7 uint16
    wSigLength       = field 8 uint16
    wOtherLength     = field 9 uint16
    cAlgNameLength   = field 10 byte
    bPacketPointers  = field 11 int32
}

$DNS_WINS_DATA = struct $Mod DNS_WINS_DATA @{
    dwMappingFlag    = field 0 uint32
    dwLookupTimeout  = field 1 uint32
    dwCacheTimeout   = field 2 uint32
    cWinsServerCount = field 3 uint32
    WinsServers      = field 4 uint32
}

$DNS_WINSR_DATA = struct $Mod DNS_WINSR_DATA @{
    dwMappingFlag     = field 0 uint32
    dwLookupTimeout   = field 1 uint32
    dwCacheTimeout    = field 2 uint32
    pNameResultDomain = field 3 intptr
}

$DNS_DHCID_DATA = struct $Mod DNS_DHCID_DATA @{
    dwByteCount = field 0 uint32
    DHCID       = field 1 intptr
}

$DNS_DATA_UNION = struct $Mod DNS_DATA_UNION @{
    A        = field 0 DNS_A_DATA 0
    SOA      = field 1 DNS_SOA_DATA 0
    PTR      = field 2 DNS_PTR_DATA 0
    MINFO    = field 3 DNS_MINFO_DATA 0
    MX       = field 4 DNS_MX_DATA 0
    HINTO    = field 5 DNS_TXT_DATA 0
    Null     = field 6 DNS_NULL_DATA 0
    WKS      = field 7 DNS_WKS_DATA 0
    AAAA     = field 8 DNS_AAAA_DATA 0
    KEY      = field 9 DNS_KEY_DATA 0
    SIG      = field 10 DNS_SIG_DATA 0
    ATMA     = field 11 DNS_ATMA_DATA 0
    NXT      = field 12 DNS_NXT_DATA 0
    SRV      = field 13 DNS_SRV_DATA 0
    NAPTR    = field 14 DNS_NAPTR_DATA 0
    OPT      = field 15 DNS_OPT_DATA 0
    DS       = field 16 DNS_DS_DATA 0
    RRSIG    = field 17 DNS_RRSIG_DATA 0
    NSEC     = field 18 DNS_NSEC_DATA 0
    DNSKEY   = field 19 DNS_DNSKEY_DATA 0
    TKEY     = field 20 DNS_TKEY_DATA 0
    TSIG     = field 21 DNS_TSIG_DATA 0
    WINS     = field 22 DNS_WINS_DATA 0
    WINSR    = field 23 DNS_WINSR_DATA 0
    DHCID    = field 24 DNS_DHCID_DATA 0
} -ExplicitLayout

$DNS_RECORD_FLAGS = struct $Mod DNS_RECORD_FLAGS @{
    data     = field 0 uint32
    Section  = field 1 uint32
    Delete   = field 2 uint32
    CharSet  = field 3 uint32
    Unused   = field 4 uint32
    Reserved = field 5 uint32
}

<#$DNS_RECORD_FLAGS = struct $Mod DNS_RECORD_FLAGS @{
    Section  = field 0 uint32
    Delete   = field 1 uint32
    CharSet  = field 2 uint32
    Unused   = field 3 uint32
    Reserved = field 4 uint32
}#>

$DNS_FLAGS_UNION = struct $Mod DNS_FLAGS_UNION @{
    DW = field 0 uint32 0
    S  = field 1 DNS_RECORD_FLAGS 0
} -ExplicitLayout

$DNS_RECORD = struct $Mod DNS_RECORD @{
    pNext       = field 0 IntPtr 0
    pName       = field 1 IntPtr 8 #4
    wType       = field 2 uint16 16 #8
    wDataLength = field 3 uint16 18 #10
    Flags       = field 4 DNS_FLAGS_UNION 20 #12
    dwTtl       = field 5 uint32 24 #16
    dwReserved  = field 6 uint32 28 #20
    Data        = field 7 DNS_DATA_UNION 32 #24
} -ExplicitLayout

$IP4_ARRAY = struct $Mod IP4_ARRAY @{
    AddrCount = field 0 UInt32
    AddrArray = field 1 Uint32[]
}


### Win32 API functions

$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetUserEnum ([Int]) @([string], [Int], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetUserModalsGet ([Int]) @([string], [Int], [IntPtr].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetGroupEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetGroupGetUsers ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetUseAdd ([Int]) @([string], [uint32], [USE_INFO_1].MakeByRefType(), [uint32].MakeByRefType()))
    (func netapi32 NetUseDel ([Int]) @([string], [string], [int]))
    #(func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),    
    #(func netapi32 NetFileEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    #(func netapi32 NetConnectionEnum ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
    #(func advapi32 LookupAccountSid ([int]) @([string], [byte[]], [string], [int].MakeByRefType(), [string], [int].MakeByRefType(), [int].MakeByRefType()))
    (func advapi32 LogonUser ([bool]) @([string], [string], [string], [Int], [Int], [Int].MakeByRefType()) -SetLastError)
    (func advapi32 RevertToSelf ([bool]) @() -SetLastError)
    (func advapi32 ImpersonateAnonymousToken ([bool]) @([IntPtr]))
    #(func advapi32 OpenSCManagerW ([IntPtr]) @([string], [string], [Int])),
    #(func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func kernel32 GetCurrentThread ([IntPtr]) @())
    #(func dnsapi DnsQuery ([int]) @([string], [QueryTypes], [QueryOptions], [int], [IntPtr].MakeByRefType(), [int]))
    (func dnsapi DnsQuery ([int]) @([string], [int], [uint32], [IP4_ARRAY].MakeByRefType(), [IntPtr].MakeByRefType(), [int]) -SetLastError -Charset Unicode -EntryPoint DnsQuery_W -ExactSpelling)
    (func dnsapi DnsRecordListFree ([int]) @([IntPtr], [int]) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Global:Netapi32 = $Types['netapi32']
$Global:Advapi32 = $Types['advapi32']
$Global:Kernel32 = $Types['kernel32']
$Global:Dnsapi   = $Types['dnsapi']