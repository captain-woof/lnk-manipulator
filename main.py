import struct
import math

# ----------------------------------------------------------------------------------
# HELPER METHODS

def getInt(contents: bytes, offset: int = 0):
    return (struct.unpack_from("<I", contents, offset))[0]

def getBit(contents: bytes, bitIndex = 0):
    byteIndex = math.floor(bitIndex / 8)
    byteExtracted = contents[byteIndex]

    bitValue = byteExtracted << (bitIndex % 8)
    bitValue = bitValue >> 7
    bitValue = bitValue << 7
    
    return bitValue != 0
    

# HELPER METHODS END
# ----------------------------------------------------------------------------------

"""
SHELL_LINK = SHELL_LINK_HEADER [LINKTARGET_IDLIST] [LINKINFO]
              [STRING_DATA] *EXTRA_DATA
"""

class LNK:
    # Data
    lnkFilePath: str = None
    contents: bytes = b""

    # ----------------------------------------------------------------------------------
    # SHELL_LINK_HEADER
    HeaderSize = 0 # 4 bytes; 0x4C
    LinkCLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46" # 16 bytes; 00021401-0000-0000-C000-000000000046 OR 00021401-0000-0000-C000-00000000000F
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
    Unused1 = False # 1 bit; A bit that is undefined and MUST be ignored.
    HasDarwinID = False # 1 bit; The shell link is saved with a DarwinDataBlock (section 2.5.3).
    RunAsUser = False # 1 bit; The application is run as a different user when the target of the shell link is activated.
    HasExpIcon = False # 1 bit; The shell link is saved with an IconEnvironmentDataBlock (section 2.5.5).
    NoPidlAlias = False # 1 bit; The file system location is represented in the shell namespace when the path to an item is parsed into an IDList.
    Unused2 = False # 1 bit; A bit that is undefined and MUST be ignored.
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

    # SHELL_LINK_HEADER END
    # ----------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------
    # LINKTARGET_IDLIST

    # LINKTARGET_IDLIST END
    # ----------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------
    # LINKINFO

    # LINKINFO END
    # ----------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------
    # STRING_DATA

    # STRING_DATA END
    # ----------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------
    # EXTRA_DATA

    # EXTRA_DATA END
    # ----------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------
    # FUNCTIONS

    # Constructor
    def __init__(self, lnkFilePath: str = None):
        self.lnkFilePath = lnkFilePath
        if lnkFilePath != None:
            with open(lnkFilePath, "rb") as lnkFile:
                self.contents = lnkFile.read()
                self.parse()

    # Parse LNK
    def parse(self):
        if len(self.contents) != 0:
            self._parseShellLinkHeader()

    # Parse LNK SHELL_LINK_HEADER
    def _parseShellLinkHeader(self):
        if len(self.contents) != 0:
            # HeaderSize
            self.HeaderSize = getInt(self.contents, 0)

            # LinkCLSID
            self.LinkCLSID = self.contents[4:20]

            # LinkFlags
            linkFlags = self.contents[20:36]
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
            self.Unused1 = getBit(linkFlags, 11)
            self.HasDarwinID = getBit(linkFlags, 12)
            self.RunAsUser = getBit(linkFlags, 13)
            self.HasExpIcon = getBit(linkFlags, 14)
            self.NoPidlAlias = getBit(linkFlags, 15)
            self.Unused2 = getBit(linkFlags, 16)
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

            print("junk")


    # FUNCTIONS END
    # ----------------------------------------------------------------------------------

    





########### MAIN
if __name__ == "__main__":
    lnk = LNK("calc.lnk")