import struct
import math

# ----------------------------------------------------------------------------------
# HELPER METHODS

def getUint(contents: bytes, offset: int = 0):
    return (struct.unpack_from("<I", contents, offset))[0]

def getInt(contents: bytes, offset: int = 0):
    return (struct.unpack_from("<i", contents, offset))[0]

def getUshort(contents: bytes, offset: int = 0):
    return (struct.unpack_from("<H", contents, offset))[0]

def getShort(contents: bytes, offset: int = 0):
    return (struct.unpack_from("<h", contents, offset))[0]

def getStringUtf8(contents: bytes, offset: int = 0, maxCount = -1):
    length = 0
    while True:
        if contents[offset + length] == 0:
            break
        length += 1

        if maxCount == length:
            break

    return contents[offset:offset + length].decode("utf-8")

def getStringUtf16Le(contents: bytes, offset: int = 0, maxCount = -1):
    length = 0
    while True:
        if contents[offset + length] == 0:
            break
        length += 2

        if maxCount == int(length / 2):
            break

    return contents[offset:offset + length].decode("utf-16le")

def getBit(contents: bytes, bitIndex = 0):
    byteIndex = math.floor(bitIndex / 8)
    byteExtracted = contents[byteIndex]

    bitValue = byteExtracted << (bitIndex % 8)
    bitValue = bitValue >> 7
    bitValue = bitValue << 7
    
    return bitValue != 0

def systemTimeToUtcSeconds(systemTime: bytes):
    """
    The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

     typedef struct _FILETIME {
       DWORD dwLowDateTime;
       DWORD dwHighDateTime;
     } FILETIME,
      *PFILETIME,
      *LPFILETIME;
    """
    intervals = (struct.unpack_from("<Q", systemTime, 0))[0]
    intervalsSeconds = (intervals * 100) / (math.pow(10, 9))
    intervalsSecondsCorrected = intervalsSeconds - ((1970 - 1601) * 31556926)
    return intervalsSecondsCorrected

def packUint(number: int = 0):
    return struct.pack("<I", number)

def packInt(number: int = 0):
    return struct.pack("<i", number)

def packUshort(number: int = 0):
    return struct.pack("<H", number)

def packShort(number: int = 0):
    return struct.pack("<h", number)

def packStringUtf8(string: str):
    return string.encode("utf-8")

def packStringUtf16Le(string: str):
    return string.encode("utf-16le")

def packBit(contents: bytes, bitIndex = 0, value: bool = False):
    byteIndex = math.floor(bitIndex / 8)
    byteExtracted = contents[byteIndex]

    byteNew = 0
    bitIndexInByte = bitIndex % 8
    if value:
        mask = (0x01 << 7) >> bitIndexInByte
        byteNew = byteExtracted | mask
    else:
        mask1 = 0xFF >> (bitIndexInByte + 1)
        mask2 = 0xFF << (8 - bitIndexInByte)
        mask = mask1 | mask2
        byteNew = byteExtracted & mask

    contentsPre = contents[0:byteIndex]
    contentsPost = contents[byteIndex + 1:]

    return contentsPre + int.to_bytes(byteNew) + contentsPost

def utcSecondsToSystemTime(utcSeconds: int):
    """
    The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

     typedef struct _FILETIME {
       DWORD dwLowDateTime;
       DWORD dwHighDateTime;
     } FILETIME,
      *PFILETIME,
      *LPFILETIME;
    """
    intervalsSeconds = utcSeconds +  ((1970 - 1601) * 31556926)
    intervals = int((intervalsSeconds * (math.pow(10, 9))) / 100)
    intervalsPacked = struct.pack("<Q", intervals)
    return intervalsPacked
    

# HELPER METHODS END
# ----------------------------------------------------------------------------------



# ----------------------------------------------------------------------------------
# SUB-STRUCTURES CLASSES

class _ShellLinkHeader:
    # Data
    HeaderSize = 0x4C # 4 bytes; 0x4C
    LinkCLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x0F" # 16 bytes; 00021401-0000-0000-C000-000000000046 OR 00021401-0000-0000-C000-00000000000F
    HasLinkTargetIDList = False # 1 bit; The shell link is saved with an item ID list (IDList). If this bit is set, a LinkTargetIDList structure (section 2.2) MUST follow the ShellLinkHeader. If this bit is not set, this structure MUST NOT be present.
    HasLinkInfo = False # The shell link is saved with link information. If this bit is set, a LinkInfo structure (section 2.3) MUST be present. If this bit is not set, this structure MUST NOT be present.
    HasName = False # 1 bit; The shell link is saved with a name string. If this bit is set, a NAME_STRING StringData structure (section 2.4) MUST be present. If this bit is not set, this structure MUST NOT be present.
    HasRelativePath = False # 1 bit; The shell link is saved with a relative path string. If this bit is set, a RELATIVE_PATH StringData structure (section 2.4) MUST be present. If this bit is not set, this structure MUST NOT be present.
    HasWorkingDir = False # 1 bit; The shell link is saved with a working directory string. If this bit is set, a WORKING_DIR StringData structure (section 2.4) MUST be present. If this bit is not set, this structure MUST NOT be present.
    HasArguments = False # 1 bit; The shell link is saved with command line arguments. If this bit is set, a COMMAND_LINE_ARGUMENTS StringData structure (section 2.4) MUST be present. If this bit is not set, this structure MUST NOT be present.
    HasIconLocation = False # 1 bit; The shell link is saved with an icon location string. If this bit is set, an ICON_LOCATION StringData structure (section 2.4) MUST be present. If this bit is not set, this structure MUST NOT be present.
    IsUnicode = False # 1 bit; The shell link contains Unicode encoded strings. This bit SHOULD be set. If this bit is set, the StringData section contains Unicode-encoded strings; otherwise, it contains strings that are encoded using the system default code page.
    ForceNoLinkInfo = False # 1 bit; The LinkInfo structure (section 2.3) is ignored.
    HasExpString = False # 1 bit; The shell link is saved with an EnvironmentVariableDataBlock (section 2.5.4).
    RunInSeparateProcess = False # 1 bit; The target is run in a separate virtual machine when launching a link target that is a 16-bit application.
    HasDarwinID = False # 1 bit; The shell link is saved with a DarwinDataBlock (section 2.5.3).
    RunAsUser = False # 1 bit; The application is run as a different user when the target of the shell link is activated.
    HasExpIcon = False # 1 bit; The shell link is saved with an IconEnvironmentDataBlock (section 2.5.5).
    NoPidlAlias = False # 1 bit; The file system location is represented in the shell namespace when the path to an item is parsed into an IDList.
    RunWithShimLayer = False # 1 bit; The shell link is saved with a ShimDataBlock (section 2.5.8).
    ForceNoLinkTrack = False # 1 bit; The TrackerDataBlock (section 2.5.10) is ignored.
    EnableTargetMetadata = False # 1 bit; The shell link attempts to collect target properties and store them in the PropertyStoreDataBlock (section 2.5.7) when the link target is set.
    DisableLinkPathTracking = False # 1 bit; The EnvironmentVariableDataBlock is ignored.
    DisableKnownFolderTracking = False # 1 bit; The SpecialFolderDataBlock (section 2.5.9) and the KnownFolderDataBlock (section 2.5.6) are ignored when loading the shell link. If this bit is set, these extra data blocks SHOULD NOT be saved when saving the shell link.
    DisableKnownFolderAlias = False # 1 bit; If the link has a KnownFolderDataBlock (section 2.5.6), the unaliased form of the known folder IDList SHOULD be used when translating the target IDList at the time that the link is loaded.
    AllowLinkToLink = False # 1 bit; Creating a link that references another link is enabled. Otherwise, specifying a link as the target IDList SHOULD NOT be allowed.
    UnaliasOnSave = False # 1 bit; When saving a link for which the target IDList is under a known folder, either the unaliased form of that known folder or the target IDList SHOULD be used.
    PreferEnvironmentPath = False # 1 bit; The target IDList SHOULD NOT be stored; instead, the path specified in the EnvironmentVariableDataBlock (section 2.5.4) SHOULD be used to refer to the target.
    KeepLocalIDListForUNCTarget = False # 1 bit; When the target is a UNC name that refers to a location on a local machine, the local path IDList in the PropertyStoreDataBlock (section 2.5.7) SHOULD be stored, so it can be used when the link is loaded on the local machine.
    FILE_ATTRIBUTE_READONLY = False # 1 bit; The file or directory is read-only. For a file, if this bit is set, applications can read the file but cannot write to it or delete it. For a directory, if this bit is set, applications cannot delete the directory.
    FILE_ATTRIBUTE_HIDDEN = False # 1 bit; The file or directory is hidden. If this bit is set, the file or folder is not included in an ordinary directory listing.
    FILE_ATTRIBUTE_SYSTEM = False # 1 bit; The file or directory is part of the operating system or is used exclusively by the operating system.
    FILE_ATTRIBUTE_DIRECTORY = False # 1 bit; The link target is a directory instead of a file.
    FILE_ATTRIBUTE_ARCHIVE = False # 1 bit; The file or directory is an archive file. Applications use this flag to mark files for backup or removal.
    FILE_ATTRIBUTE_NORMAL = False # 1 bit; The file or directory has no other flags set. If this bit is 1, all other bits in this structure MUST be clear.
    FILE_ATTRIBUTE_TEMPORARY = False # 1 bit; The file is being used for temporary storage.
    FILE_ATTRIBUTE_SPARSE_FILE = False # 1 bit; The file is a sparse file.
    FILE_ATTRIBUTE_REPARSE_POINT = False # 1 bit; The file or directory has an associated reparse point.
    FILE_ATTRIBUTE_COMPRESSED = False # 1 bit; The file or directory is compressed. For a file, this means that all data in the file is compressed. For a directory, this means that compression is the default for newly created files and subdirectories.
    FILE_ATTRIBUTE_OFFLINE = False # 1 bit; The data of the file is not immediately available.
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = False # 1 bit; The contents of the file need to be indexed.
    FILE_ATTRIBUTE_ENCRYPTED = False # 1 bit; The file or directory is encrypted. For a file, this means that all data in the file is encrypted. For a directory, this means that encryption is the default for newly created files and subdirectories.
    CreationTime = 0 # UTC seconds
    AccessTime = 0 # UTC seconds
    WriteTime = 0 # UTC seconds
    FileSize = 0 # Size, in bytes, of the link target. If the link target file is larger than 0xFFFFFFFF, this value specifies the least significant 32 bits of the link target file size.
    IconIndex = 0 # Index of an icon within a given icon location
    ShowCommand = 1 # 1=Normal, 3=Maximized, 7=Minimized
    HotkeyFlags = [0, 0] # low byte, high byte; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/8cd21240-1b5d-43e6-adc4-38cf14e30cea

    def __init__(self, contents: bytes):
        # HeaderSize; 4 bytes
        self.HeaderSize = getUint(contents, 0)

        # LinkCLSID; 16 bytes
        self.LinkCLSID = contents[4:20]

        # LinkFlags; 4 bytes
        linkFlags = contents[20:24]
        self.HasLinkTargetIDList = getBit(linkFlags, 0)
        self.HasLinkInfo = getBit(linkFlags, 1)
        self.HasName = getBit(linkFlags, 2)
        self.HasRelativePath = getBit(linkFlags, 3)
        self.HasWorkingDir = getBit(linkFlags, 4)
        self.HasArguments = getBit(linkFlags, 5)
        self.HasIconLocation = getBit(linkFlags, 6)
        self.IsUnicode = getBit(linkFlags, 7)
        self.ForceNoLinkInfo = getBit(linkFlags, 8)
        self.HasExpString = getBit(linkFlags, 9)
        self.RunInSeparateProcess = getBit(linkFlags, 10)
        self.HasDarwinID = getBit(linkFlags, 12)
        self.RunAsUser = getBit(linkFlags, 13)
        self.HasExpIcon = getBit(linkFlags, 14)
        self.NoPidlAlias = getBit(linkFlags, 15)
        self.RunWithShimLayer = getBit(linkFlags, 17)
        self.ForceNoLinkTrack = getBit(linkFlags, 18)
        self.EnableTargetMetadata = getBit(linkFlags, 19)
        self.DisableLinkPathTracking = getBit(linkFlags, 20)
        self.DisableKnownFolderTracking = getBit(linkFlags, 21)
        self.DisableKnownFolderAlias = getBit(linkFlags,22)
        self.AllowLinkToLink = getBit(linkFlags, 23)
        self.UnaliasOnSave = getBit(linkFlags, 24)
        self.PreferEnvironmentPath = getBit(linkFlags, 25)
        self.KeepLocalIDListForUNCTarget = getBit(linkFlags, 26)

        # File attributes; 4 bytes
        fileAttributes = contents[24:28]
        self.FILE_ATTRIBUTE_READONLY = getBit(fileAttributes, 0)
        self.FILE_ATTRIBUTE_HIDDEN = getBit(fileAttributes, 1)
        self.FILE_ATTRIBUTE_SYSTEM = getBit(fileAttributes, 2)
        self.FILE_ATTRIBUTE_DIRECTORY = getBit(fileAttributes, 4)
        self.FILE_ATTRIBUTE_ARCHIVE = getBit(fileAttributes, 5)
        self.FILE_ATTRIBUTE_NORMAL = getBit(fileAttributes, 7)
        self.FILE_ATTRIBUTE_TEMPORARY = getBit(fileAttributes, 8)
        self.FILE_ATTRIBUTE_SPARSE_FILE = getBit(fileAttributes, 9)
        self.FILE_ATTRIBUTE_REPARSE_POINT = getBit(fileAttributes, 10)
        self.FILE_ATTRIBUTE_COMPRESSED = getBit(fileAttributes, 11)
        self.FILE_ATTRIBUTE_OFFLINE = getBit(fileAttributes, 12)
        self.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = getBit(fileAttributes, 13)
        self.FILE_ATTRIBUTE_ENCRYPTED = getBit(fileAttributes, 14)
        
        # CreationTime; 8 bytes
        creationTime = contents[28:36]
        self.CreationTime = systemTimeToUtcSeconds(creationTime)

        # AccessTime; 8 bytes
        accessTime = contents[36:44]
        self.AccessTime = systemTimeToUtcSeconds(accessTime)

        # WriteTime; 8 bytes
        writeTime = contents[44:52]
        self.WriteTime = systemTimeToUtcSeconds(writeTime)

        # FileSize; 4 bytes
        fileSize = contents[52:56]
        self.FileSize = getUint(fileSize, 0)

        # IconIndex; 4 bytes
        iconIndex = contents[56:60]
        self.IconIndex = getInt(iconIndex, 0)

        # ShowCommand; 4 bytes
        showCommand = contents[60:64]
        self.ShowCommand = getUint(showCommand, 0)

        # HotKeyFlags; 2 bytes
        self.HotkeyFlags[0] = contents[64]
        self.HotkeyFlags[1] = contents[65]

    def pack(self):
        contents = b""

        # HeaderSize; 4 bytes
        contents += packUint(self.HeaderSize)

        # LinkCLSID; 16 bytes
        contents += self.LinkCLSID

        # LinkFlags; 4 bytes
        linkFlags = bytes(4)
        linkFlags = packBit(linkFlags, 0, self.HasLinkTargetIDList)
        linkFlags = packBit(linkFlags, 1, self.HasLinkInfo)
        linkFlags = packBit(linkFlags, 2, self.HasName)
        linkFlags = packBit(linkFlags, 3, self.HasRelativePath)
        linkFlags = packBit(linkFlags, 4, self.HasWorkingDir)
        linkFlags = packBit(linkFlags, 5, self.HasArguments)
        linkFlags = packBit(linkFlags, 6, self.HasIconLocation)
        linkFlags = packBit(linkFlags, 7, self.IsUnicode)
        linkFlags = packBit(linkFlags, 8, self.ForceNoLinkInfo)
        linkFlags = packBit(linkFlags, 9, self.HasExpString)
        linkFlags = packBit(linkFlags, 10, self.RunInSeparateProcess)
        linkFlags = packBit(linkFlags, 12, self.HasDarwinID)
        linkFlags = packBit(linkFlags, 13, self.RunAsUser)
        linkFlags = packBit(linkFlags, 14, self.HasExpIcon)
        linkFlags = packBit(linkFlags, 15, self.NoPidlAlias)
        linkFlags = packBit(linkFlags, 17, self.RunWithShimLayer)
        linkFlags = packBit(linkFlags, 18, self.ForceNoLinkTrack)
        linkFlags = packBit(linkFlags, 19, self.EnableTargetMetadata)
        linkFlags = packBit(linkFlags, 20, self.DisableLinkPathTracking)
        linkFlags = packBit(linkFlags, 21, self.DisableKnownFolderTracking)
        linkFlags = packBit(linkFlags, 22, self.DisableKnownFolderAlias)
        linkFlags = packBit(linkFlags, 23, self.AllowLinkToLink)
        linkFlags = packBit(linkFlags, 24, self.UnaliasOnSave)
        linkFlags = packBit(linkFlags, 25, self.PreferEnvironmentPath)
        linkFlags = packBit(linkFlags, 26, self.KeepLocalIDListForUNCTarget)
        contents += linkFlags

        # File attributes; 4 bytes
        fileAttributes = bytes(4)
        fileAttributes = packBit(fileAttributes, 0, self.FILE_ATTRIBUTE_READONLY)
        fileAttributes = packBit(fileAttributes, 1, self.FILE_ATTRIBUTE_HIDDEN)
        fileAttributes = packBit(fileAttributes, 2, self.FILE_ATTRIBUTE_SYSTEM)
        fileAttributes = packBit(fileAttributes, 4, self.FILE_ATTRIBUTE_DIRECTORY)
        fileAttributes = packBit(fileAttributes, 5, self.FILE_ATTRIBUTE_ARCHIVE)
        fileAttributes = packBit(fileAttributes, 7, self.FILE_ATTRIBUTE_NORMAL)
        fileAttributes = packBit(fileAttributes, 8, self.FILE_ATTRIBUTE_TEMPORARY)
        fileAttributes = packBit(fileAttributes, 9, self.FILE_ATTRIBUTE_SPARSE_FILE)
        fileAttributes = packBit(fileAttributes, 10, self.FILE_ATTRIBUTE_REPARSE_POINT)
        fileAttributes = packBit(fileAttributes, 11, self.FILE_ATTRIBUTE_COMPRESSED)
        fileAttributes = packBit(fileAttributes, 12, self.FILE_ATTRIBUTE_OFFLINE)
        fileAttributes = packBit(fileAttributes, 13, self.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        fileAttributes = packBit(fileAttributes, 14, self.FILE_ATTRIBUTE_ENCRYPTED)
        contents += fileAttributes
        
        # CreationTime; 8 bytes
        contents += utcSecondsToSystemTime(self.CreationTime)

        # AccessTime; 8 bytes
        contents += utcSecondsToSystemTime(self.AccessTime)

        # WriteTime; 8 bytes
        contents += utcSecondsToSystemTime(self.WriteTime)

        # FileSize; 4 
        contents += packUint(self.FileSize)

        # IconIndex; 4 bytes
        contents += packInt(self.IconIndex)

        # ShowCommand; 4 bytes
        contents += packUint(self.ShowCommand)

        # HotKeyFlags; 2 bytes
        contents += int.to_bytes(self.HotkeyFlags[0]) + int.to_bytes(self.HotkeyFlags[1])

        # Reserved1 + Reserved2 + Reserved3
        reserved = bytes(2 + 4 + 4)
        contents += reserved

        # Return result
        return contents



class _LinkTargetIDList:
    itemIdDatas: list[bytes] = []

    @property
    def totalSize(self):
        size = 2 # IDListSize
        for itemIdData in self.itemIdDatas:
            size += 2 + len(itemIdData)
        size += 2 # TerminalID
        return size

    @property
    def sizeOfIdList(self):
        for itemIdData in self.itemIdDatas:
            size += 2 + len(itemIdData)
        size += 2 # TerminalID
        return size

    def __init__(self, offset: int, contents: bytes):
        if offset != 0 and contents != None:
            sizeOfIdList = getUshort(contents, offset)

            if sizeOfIdList != 0:
                sizeOfItemIdIndex = offset + 2
                while True:
                    sizeOfItemId = getUshort(contents, sizeOfItemIdIndex)
                    if sizeOfItemId == 0:
                        break

                    itemIdDataIndex = sizeOfItemIdIndex + 2
                    data = contents[itemIdDataIndex:(itemIdDataIndex + sizeOfItemId - 2)]
                    self.itemIdDatas.append(data)

                    sizeOfItemIdIndex += sizeOfItemId

    def pack(self):
        contents = b""

        # IDListSize
        contents += packUshort(self.sizeOfIdList)

        # IDList -> ItemIDList
        for itemIdData in self.itemIdDatas:
            contents += packUshort(len(itemIdData))
            contents += itemIdData 

        # IDList -> TerminalID
        contents += b"\x00\x00"

        return contents


class _LinkInfo:
    LinkInfoSize: int = 0
    LinkInfoHeaderSize: int = 0
    OffsetsToOptionalFieldsPresent: bool = False
    LinkInfoFlags = 0
    VolumeIDAndLocalBasePathPresent: bool = False
    CommonNetworkRelativeLinkAndPathSuffixPresent: bool = False
    VolumeIdSize = 0
    VolumeIdDriveType = 0 # 0=Unknown,1=NoRootDir,2=Removable,3=Fixed,4=Remote,5=CD,6=RAM
    VolumeIdDriveSerialNumber = 0
    VolumeIdLabelOffset = 0
    VolumeIdLabelOffsetUnicode = 0
    VolumeIdData = b""
    LocalBasePath: str = None
    CommonNetworkRelativeLinkSize: int
    CommonNetworkRelativeLinkFlags: int
    CommonNetworkRelativeLinkValidDevice = False
    CommonNetworkRelativeLinkValidNetType = False
    NetNameOffset: int = 0
    NetNameOffsetUnicode: int = 0
    NetNameUnicode: str = ""
    NetName: str = ""
    DeviceNameOffset: int = 0
    DeviceNameOffsetUnicode: int = 0
    DeviceNameUnicode: str = ""
    DeviceName:str = ""
    NetworkProviderType: int = 0
    CommonPathSuffix: str = ""
    LocalBasePathUnicode: str = ""
    CommonPathSuffixUnicode: str = ""

    def __init__(self, offset: int, contents: bytes):
        if offset != 0 and contents != None:
            linkInfoOffset = offset + 2
            self.LinkInfoSize = getUint(contents, linkInfoOffset)

            if self.LinkInfoSize != 0:
                # LinkInfoHeaderSize
                self.LinkInfoHeaderSize = getUint(contents, linkInfoOffset + 4)
                if self.LinkInfoHeaderSize >= 0x24:
                    self.OffsetsToOptionalFieldsPresent = True

                # LinkInfoFlags
                self.LinkInfoFlags = getUint(contents, linkInfoOffset + 8)
                if self.LinkInfoFlags != 0:
                    if self.LinkInfoFlags == 1:
                        self.VolumeIDAndLocalBasePathPresent = True
                    elif self.LinkInfoFlags == 2:
                        self.CommonNetworkRelativeLinkAndPathSuffixPresent = True
                    else:
                        self.VolumeIDAndLocalBasePathPresent = True
                        self.CommonNetworkRelativeLinkAndPathSuffixPresent = True

                # VolumeIDOffset
                self.VolumeIDOffset = getUint(contents, linkInfoOffset + 12)

                # LocalBasePathOffset
                self.LocalBasePathOffset = getUint(contents, linkInfoOffset + 16)

                # CommonNetworkRelativeLinkOffset
                self.CommonNetworkRelativeLinkOffset = getUint(contents, linkInfoOffset + 20)

                # CommonPathSuffixOffset
                self.CommonPathSuffixOffset = getUint(contents, linkInfoOffset + 24)

                # LocalBasePathOffsetUnicode
                if self.LinkInfoHeaderSize >= 0x24:
                    self.LocalBasePathOffsetUnicode = getUint(contents, linkInfoOffset + 28)

                # CommonPathSuffixOffsetUnicode
                if self.LinkInfoHeaderSize >= 0x24:
                    self.CommonPathSuffixOffsetUnicode = getUint(contents, linkInfoOffset + 32)

                # VolumeID
                if self.VolumeIDAndLocalBasePathPresent and self.VolumeIDOffset != 0:
                    self.VolumeIdSize = getUint(contents, linkInfoOffset + self.VolumeIDOffset)
                    self.VolumeIdDriveType = getUint(contents, linkInfoOffset + self.VolumeIDOffset + 4)
                    self.VolumeIdDriveSerialNumber = getUint(contents, linkInfoOffset + self.VolumeIDOffset + 8)
                    self.VolumeIdLabelOffset = getUint(contents, linkInfoOffset + self.VolumeIDOffset + 12)

                    if self.VolumeIdLabelOffset == 0x14:
                        self.VolumeIdLabelOffsetUnicode = getUint(contents, linkInfoOffset + self.VolumeIDOffset + 16)
                    self.VolumeIdData = contents[linkInfoOffset + self.VolumeIDOffset + 20:linkInfoOffset + self.VolumeIDOffset + 20 + self.VolumeIdSize]

                # LocalBasePath
                if self.VolumeIDAndLocalBasePathPresent and self.LocalBasePathOffset != 0:
                    self.LocalBasePath = getStringUtf8(contents, linkInfoOffset + self.LocalBasePathOffset)

                # CommonNetworkRelativeLink
                if self.CommonNetworkRelativeLinkAndPathSuffixPresent and self.CommonNetworkRelativeLinkOffset != 0:
                    self.CommonNetworkRelativeLinkSize = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset)
                    self.CommonNetworkRelativeLinkFlags = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 4)

                    if self.CommonNetworkRelativeLinkFlags != 0:
                        if self.CommonNetworkRelativeLinkFlags == 1:
                            self.CommonNetworkRelativeLinkValidDevice = True
                        elif self.CommonNetworkRelativeLinkFlags == 2:
                            self.CommonNetworkRelativeLinkValidNetType = True
                        else:
                            self.CommonNetworkRelativeLinkValidDevice = True
                            self.CommonNetworkRelativeLinkValidNetType = True

                    self.NetNameOffset = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 8)
                    if self.NetNameOffset != 0:
                        if self.NetNameOffset > 0x14:
                            self.NetNameOffsetUnicode = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 20)
                            self.NetNameUnicode = getStringUtf16Le(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + self.NetNameOffsetUnicode)
                        else:
                            self.NetName = getStringUtf8(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + self.NetNameOffset)

                    self.DeviceNameOffset = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 12)
                    if self.CommonNetworkRelativeLinkValidDevice and self.DeviceNameOffset != 0:
                        if self.NetNameOffset > 0x14:
                            self.DeviceNameOffsetUnicode = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 24)
                            self.DeviceNameUnicode = getStringUtf16Le(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + self.DeviceNameOffsetUnicode)
                        else:
                            self.DeviceName = getStringUtf8(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + self.DeviceNameOffset)

                    if self.CommonNetworkRelativeLinkValidNetType:
                        self.NetworkProviderType = getUint(contents, linkInfoOffset + self.CommonNetworkRelativeLinkOffset + 16)

                # CommonPathSuffix
                self.CommonPathSuffix = getStringUtf8(contents, linkInfoOffset + self.CommonPathSuffixOffset)

                # LocalBasePathUnicode
                if self.VolumeIDAndLocalBasePathPresent and self.LinkInfoHeaderSize >= 0x24 and self.LocalBasePathOffsetUnicode != 0:
                    self.LocalBasePathUnicode = getStringUtf16Le(contents, linkInfoOffset + self.LocalBasePathOffsetUnicode)

                # CommonPathSuffixUnicode
                if self.LinkInfoHeaderSize >= 0x24 and self.CommonPathSuffixOffsetUnicode != 0:
                    self.CommonPathSuffixUnicode = getStringUtf16Le(contents, linkInfoOffset + self.CommonPathSuffixOffsetUnicode)

    def pack(self):
        # Pack all the required variable data individually

        ## VolumeID
        contentsVolumeId = b""
        if self.VolumeIDAndLocalBasePathPresent:
            ### VolumeIDSize
            contentsVolumeId += packUint(
                (5 * 4)
                + len(self.VolumeIdData) + 1
                + ((len(self.VolumeIdData) + 1) * 2)
            )

            ### DriveType
            contentsVolumeId += packUint(self.VolumeIdDriveType)

            ### DriveSerialNumber
            contentsVolumeId += packUint(self.VolumeIdDriveSerialNumber)
            
            ### VolumeLabelOffset
            contentsVolumeId += packUint(20)

            ### VolumeLabelOffsetUnicode
            contentsVolumeId += packUint(20 + len(self.VolumeIdData) + 1)

            ### Data
            contentsVolumeId += packStringUtf8(self.VolumeIdData) + b"\x00"
            contentsVolumeId += packStringUtf16Le(self.VolumeIdData) + b"\x00\x00"

        ## LinkInfoFlags
        contentsLinkInfoFlags = b""
        if self.VolumeIDAndLocalBasePathPresent:
            contentsLinkInfoFlags = packUint(1)
        elif self.CommonNetworkRelativeLinkAndPathSuffixPresent:
            contentsLinkInfoFlags = packUint(2)
        elif self.VolumeIDAndLocalBasePathPresent and self.CommonNetworkRelativeLinkAndPathSuffixPresent:
            contentsLinkInfoFlags = packUint(3)
        else:
            contentsLinkInfoFlags = packUint(0)

        ## LocalBasePath
        contentsLocalBasePath = packStringUtf8(self.LocalBasePath)

        ## CommonPathSuffix
        contentsCommonPathSuffix = packStringUtf8(self.CommonPathSuffix)

        ## LocalBasePathUnicode
        contentsLocalBasePathUnicode = packStringUtf16Le(self.LocalBasePathUnicode)

        ## CommonPathSuffixUnicode
        contentsCommonPathSuffixUnicode = packStringUtf16Le(self.CommonPathSuffixUnicode)

        ## CommonNetworkRelativeLink
        contentsCommonNetworkRelativeLinkFlags = packUint(0)
        if self.CommonNetworkRelativeLinkValidDevice and not self.CommonNetworkRelativeLinkValidNetType:
            contentsCommonNetworkRelativeLinkFlags = packUint(1)
        elif not self.CommonNetworkRelativeLinkValidDevice and self.CommonNetworkRelativeLinkValidNetType:
            contentsCommonNetworkRelativeLinkFlags = packUint(2)
        elif self.CommonNetworkRelativeLinkValidDevice and self.CommonNetworkRelativeLinkValidNetType:
            contentsCommonNetworkRelativeLinkFlags = packUint(3)
        contentsNetName = packStringUtf8(self.NetName)
        contentsNetNameUnicode = packStringUtf16Le(self.NetNameUnicode)
        contentsDeviceName = packStringUtf8(self.DeviceName)
        contentsDeviceNameUnicode = packStringUtf16Le(self.DeviceNameUnicode)
        contentsNetworkProviderType = packUint(self.NetworkProviderType)
        
        contentsCommonNetworkRelativeLink = b""

        ### CommonNetworkRelativeLinkSize
        contentsCommonNetworkRelativeLink += packUint(
            (7 * 4)
            + len(contentsNetName) + 1
            + 2 * (len(contentsNetNameUnicode) + 1)
            + len(contentsDeviceName)
            + 2 * (len(contentsDeviceNameUnicode) + 1)
            )
        ### CommonNetworkRelativeLinkFlags
        contentsCommonNetworkRelativeLink += contentsCommonNetworkRelativeLinkFlags
        ### NetNameOffset
        contentsCommonNetworkRelativeLink += packUint(28)
        ### DeviceNameOffset
        contentsCommonNetworkRelativeLink += packUint(28 + len(contentsNetName) + 1)
        ### NetworkProviderType
        contentsCommonNetworkRelativeLink += contentsNetworkProviderType
        ### NetNameOffsetUnicode
        contentsCommonNetworkRelativeLink += packUint(28 + len(contentsNetName) + 1 + len(contentsDeviceName) + 1)
        ### DeviceNameOffsetUnicode
        contentsCommonNetworkRelativeLink += packUint(28 + len(contentsNetName) + 1 + len(contentsDeviceName) + 1 + ((2 * len(contentsNetNameUnicode)) + 2))
        ### NetName
        contentsCommonNetworkRelativeLink += contentsNetName + b"\x00"
        ### DeviceName
        contentsCommonNetworkRelativeLink += contentsDeviceName + b"\x00"
        ### NetNameUnicode
        contentsCommonNetworkRelativeLink += contentsNetNameUnicode + b"\x00\x00"
        ### DeviceNameUnicode
        contentsCommonNetworkRelativeLink += contentsDeviceNameUnicode + b"\x00\x00"

        # Pack all data, combining individual packings
        contents = b""

        ## LinkInfoSize
        contents += packUint(
            (9 * 4)
            + len(contentsVolumeId)
            + len(contentsLocalBasePath)
            + len(contentsCommonNetworkRelativeLink)
            + len(contentsCommonPathSuffix)
            + len(contentsLocalBasePathUnicode)
            + len(contentsCommonPathSuffixUnicode)
        )

        ## LinkInfoHeaderSize
        contents += packUint(
            (9 * 4)
        )

        ## LinkInfoFlags
        contents += contentsLinkInfoFlags

        ## VolumeIDOffset
        contents += packUint(36)

        ## LocalBasePathOffset
        contents += packUint(36 + len(contentsVolumeId))

        ## CommonNetworkRelativeLinkOffset
        contents += packUint(36 + len(contentsVolumeId) + len(contentsLocalBasePath))

        ## CommonPathSuffixOffset
        contents += packUint(36 + len(contentsVolumeId) + len(contentsLocalBasePath) + len(contentsCommonNetworkRelativeLink))

        ## LocalBasePathOffsetUnicode
        contents += packUint(36 + len(contentsVolumeId) + len(contentsLocalBasePath) + len(contentsCommonNetworkRelativeLink) + len(contentsCommonPathSuffix))

        ## CommonPathSuffixOffsetUnicode
        contents += packUint(36 + len(contentsVolumeId) + len(contentsLocalBasePath) + len(contentsCommonNetworkRelativeLink) + len(contentsCommonPathSuffix) + len(contentsLocalBasePathUnicode))

        ## VolumeID
        contents += contentsVolumeId

        ## LocalBasePath
        contents += contentsLocalBasePath

        ## CommonNetworkRelativeLink
        contents += contentsCommonNetworkRelativeLink

        ## CommonPathSuffix
        contents += contentsCommonPathSuffix

        ## LocalBasePathUnicode
        contents += contentsLocalBasePathUnicode

        ## CommonPathSuffixUnicode
        contents += contentsCommonPathSuffixUnicode

        # Return final packed data
        return contents 
    

class _StringData:
    NAME_STRING: str = ""
    RELATIVE_PATH: str = ""
    WORKING_DIR: str = ""
    COMMAND_LINE_ARGUMENTS: str = ""
    ICON_LOCATION: str = ""
    NAME_STRING_IS_UNICODE: bool = False
    RELATIVE_PATH_IS_UNICODE: bool = False
    WORKING_DIR_IS_UNICODE: bool = False
    COMMAND_LINE_ARGUMENTS_IS_UNICODE: bool = False
    ICON_LOCATION_IS_UNICODE: bool = False
    sizeOfStringData = 0

    def parseString(self, contents: bytes, offset: int):        
        countCharacters = getUshort(contents, offset)
        if countCharacters == 0:
            self.sizeOfStringData += 2
            return (2, "", False)

        stringData = getStringUtf8(contents, offset + 2, countCharacters)
        stringDataUnicode = getStringUtf16Le(contents, offset + 2, countCharacters)

        if len(stringData) > len(stringDataUnicode):
            self.sizeOfStringData += 2 + countCharacters
            return (2 + countCharacters, stringData, False)
        elif len(stringData) < len(stringDataUnicode):
            self.sizeOfStringData += (2 + (countCharacters * 2))
            return (2 + (countCharacters * 2), stringDataUnicode, True)
        elif len(stringData) == len(stringDataUnicode) == 0:
            self.sizeOfStringData += 2
            return (2, "", False)
        else:
            self.sizeOfStringData += 2
            return (2, "", False)

    def __init__(self, shellLinkHeader: _ShellLinkHeader, offset: int, contents: bytes):
        if offset != 0 and contents != None:
            offsetLocal = 0

            # NAME_STRING
            if shellLinkHeader.HasName:
                offsetLocalIncrement, self.NAME_STRING, isUnicode = self.parseString(contents, offset + offsetLocal)
                self.NAME_STRING_IS_UNICODE = isUnicode
                offsetLocal += offsetLocalIncrement

            # RELATIVE_PATH
            if shellLinkHeader.HasRelativePath:
                offsetLocalIncrement, self.RELATIVE_PATH, isUnicode = self.parseString(contents, offset + offsetLocal)
                self.RELATIVE_PATH_IS_UNICODE = isUnicode
                offsetLocal += offsetLocalIncrement

            # WORKING_DIR
            if shellLinkHeader.HasWorkingDir:
                offsetLocalIncrement, self.WORKING_DIR, isUnicode = self.parseString(contents, offset + offsetLocal)
                self.WORKING_DIR_IS_UNICODE = isUnicode
                offsetLocal += offsetLocalIncrement

            # COMMAND_LINE_ARGUMENTS
            if shellLinkHeader.HasArguments:
                offsetLocalIncrement, self.COMMAND_LINE_ARGUMENTS, isUnicode = self.parseString(contents, offset + offsetLocal)
                self.COMMAND_LINE_ARGUMENTS_IS_UNICODE = isUnicode
                offsetLocal += offsetLocalIncrement

            # ICON_LOCATION
            if shellLinkHeader.HasIconLocation:
                offsetLocalIncrement, self.ICON_LOCATION, isUnicode = self.parseString(contents, offset + offsetLocal)
                self.ICON_LOCATION_IS_UNICODE = isUnicode
                offsetLocal += offsetLocalIncrement

    def pack(self):
        pass # TODO


# SUB-STRUCTURES CLASSES END
# ----------------------------------------------------------------------------------

"""
SHELL_LINK = SHELL_LINK_HEADER [LINKTARGET_IDLIST] [LINKINFO]
              [STRING_DATA] *EXTRA_DATA
"""
class LNK:
    # Data
    shellLinkHeader: _ShellLinkHeader = None
    linkTargetIdList: _LinkTargetIDList = None
    linkInfo: _LinkInfo = None
    stringData: _StringData = None

    # ----------------------------------------------------------------------------------
    # FUNCTIONS

    # Constructor
    def __init__(self, lnkFilePath: str = None):
        if lnkFilePath != None:
            nextOffset = 0
            with open(lnkFilePath, "rb") as lnkFile:
                contents = lnkFile.read()
                self.shellLinkHeader = _ShellLinkHeader(
                    contents=contents
                    )
                nextOffset += self.shellLinkHeader.HeaderSize
                
                if self.shellLinkHeader.HasLinkTargetIDList:
                    self.linkTargetIdList = _LinkTargetIDList(
                        offset = nextOffset,
                        contents = contents
                        )
                    nextOffset += self.linkTargetIdList.totalSize
                else:
                    self.linkTargetIdList = _LinkTargetIDList(offset = 0, contents = None)

                if self.shellLinkHeader.HasLinkInfo:
                    self.linkInfo = _LinkInfo(
                        offset = nextOffset,
                        contents = contents
                        )
                    nextOffset += self.linkInfo.LinkInfoSize
                else:
                    self.linkInfo = _LinkInfo(offset = 0, contents = None)

                self.stringData = _StringData(
                    shellLinkHeader = self.shellLinkHeader,
                    offset = nextOffset,
                    contents = contents
                    )
                nextOffset += self.stringData.sizeOfStringData
                
                # self.extraData TODO (not required; shortcut works without it)

        else:
            self.shellLinkHeader = _ShellLinkHeader()
            self.linkTargetIdList = _LinkTargetIDList(offset = 0, contents = None)
            self.linkInfo = _LinkInfo(offset = 0, contents = None)
            self.stringData = _StringData(shellLinkHeader=self.shellLinkHeader, offset = 0, contents = None)

    # Pack into LNK
    def pack(self):
        shellLinkHeaderContents = self.shellLinkHeader.pack()

        linkTargetIdListContents = b""
        if self.shellLinkHeader.HasLinkTargetIDList:
            linkTargetIdListContents = self.linkTargetIdList.pack()

        linkInfoContents = b""
        if self.shellLinkHeader.HasLinkInfo:
            linkInfoContents = self.linkInfo.pack()

        contents = shellLinkHeaderContents + linkTargetIdListContents + linkInfoContents # +

        return contents
    
    # Pack into LNK and write out the file
    def packAndSave(self, filePath: str):
        contents = self.pack()
        with open(filePath, "wb") as fileToWrite:
            fileToWrite.write(contents)

    # FUNCTIONS END
    # ----------------------------------------------------------------------------------

    


########### MAIN
if __name__ == "__main__":
    lnk = LNK("calc.lnk")

    packed = lnk.packAndSave("test.lnk")

    print("junk")