BEGIN TRANSACTION;

/****** 
Copyright (C) 2014-2015 Jerome Athias
Windows objects related tables for XORCISM database (mainly from MITRE CybOX)
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "WINDOWSCOMPUTERACCOUNT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSCOMPUTERACCOUNT"(
	"WindowsComputerAccountID" INTEGER NOT NULL,
	"AccountID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSCRITICALSECTION"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSCRITICALSECTION"(
	"WindowsCriticalSectionID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSDRIVER"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSDRIVER"(
	"WindowsDriverID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSDRIVETYPE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSDRIVETYPE"(
	"WindowsDriveTypeID" INTEGER NOT NULL,
	"WindowsDriveTypeName" TEXT NOT NULL,
	"WindowsDriveTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "WINDOWSEVENT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSEVENT"(
	"WindowsEventID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSEVENTLOG"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSEVENTLOG"(
	"WindowsEventLogID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSEXECUTABLEFILE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSEXECUTABLEFILE"(
	"WindowsExecutableFileID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSFILE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSFILE"(
	"WindowsFileID" INTEGER NOT NULL,
	"WindowsFileGUID" TEXT NULL,
	"FileID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSGROUP"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSGROUP"(
	"WindowsGroupID" INTEGER NOT NULL,
	"WindowsGroupName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSGROUPFORWINDOWSUSERACCOUNT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSGROUPFORWINDOWSUSERACCOUNT"(
	"WindowsGroupWindowsUserAccountID" INTEGER NOT NULL,
	"WindowsGroupID" INTEGER NOT NULL,
	"WindowsUserAccountID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSHANDLE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSHANDLE"(
	"WindowsHandleID" INTEGER NOT NULL,
	"WindowsHandleObjectID" INTEGER NULL,
	"WindowsHandleName" TEXT NULL,
	"HandleTypeID" INTEGER NULL,
	"Object_Address" INTEGER NULL,
	"Access_Mask" INTEGER NULL,
	"Pointer_Count" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSHANDLELIST"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSHANDLELIST"(
	"WindowsHandleListID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSHANDLELISTHANDLES"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSHANDLELISTHANDLES"(
	"WindowsHandleListHandlesID" INTEGER NOT NULL,
	"WindowsHandleListID" INTEGER NOT NULL,
	"WindowsHandleID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSHANDLETYPE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSHANDLETYPE"(
	"WindowsHandleTypeID" INTEGER NOT NULL,
	"HandleTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSKERNELHOOK"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSKERNELHOOK"(
	"WindowsKernelHookID" INTEGER NOT NULL,
	"Digital_Signature_Hooking" TEXT NULL,
	"DigitalSignatureInfoHookingID" INTEGER NULL,
	"Digital_Signature_Hooked" TEXT NULL,
	"DigitalSignatureInfoHookedID" INTEGER NULL,
	"Hooking_Address" INTEGER NULL,
	"Hook_Description" TEXT NULL,
	"Hooked_Function" TEXT NULL,
	"FunctionHookedID" INTEGER NULL,
	"Hooked_Module" TEXT NULL,
	"ModuleHookedID" INTEGER NULL,
	"Hooking_Module" TEXT NULL,
	"KernelHookID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"DetectionMethodID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSKERNELOBJECT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSKERNELOBJECT"(
	"WindowsKernelObjectID" INTEGER NOT NULL,
	"IDTEntryListID" INTEGER NULL,
	"SSDTEntryListID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"CollectionToolID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSMAILSLOT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSMAILSLOT"(
	"WindowsMailslotID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSMEMORYPAGEREGION"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSMEMORYPAGEREGION"(
	"WindowsMemoryPageRegionID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSMUTEX"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSMUTEX"(
	"WindowsMutexID" INTEGER NOT NULL,
	"WindowsHandleID" INTEGER NULL,
	"MutexID" INTEGER NULL,
	"Security_Attributes" TEXT NULL,
	"WindowsMutexDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSMUTEXHANDLE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSMUTEXHANDLE"(
	"WindowsMutexHandleID" INTEGER NOT NULL,
	"WindowsMutexID" INTEGER NOT NULL,
	"WindowsHandleID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSMUTEXSECURITYATTRIBUTE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSMUTEXSECURITYATTRIBUTE"(
	"WindowsMutexSecurityAttributeID" INTEGER NOT NULL,
	"WindowsMutexID" INTEGER NOT NULL,
	"SecurityAttributeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSNETWORKROUTEENTRY"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSNETWORKROUTEENTRY"(
	"WindowsNetworkRouteEntryID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSNETWORKSHARE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSNETWORKSHARE"(
	"WindowsNetworkShareID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSPIPEOBJECT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPIPEOBJECT"(
	"WindowsPipeObjectID" INTEGER NOT NULL,
	"PipeObjectID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSPREFETCHACCESSEDFILELIST"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPREFETCHACCESSEDFILELIST"(
	"WindowsPrefetchObjectAccessedFileListID" INTEGER NOT NULL,
	"WindowsPrefetchObjectID" INTEGER NOT NULL,
	"AccessedFileListID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "WINDOWSPREFETCHCHANGERECORD"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPREFETCHCHANGERECORD"(
	"WindowsPrefetchChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSPREFETCHOBJECT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPREFETCHOBJECT"(
	"WindowsPrefetchObjectID" INTEGER NOT NULL,
	"Application_File_Name" TEXT NULL,
	"FileID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"Prefetch_Hash" TEXT NULL,
	"Times_Executed" INTEGER NULL,
	"First_Run" TEXT NULL,
	"Last_Run" TEXT NULL,
	"VolumeObjectID" INTEGER NULL,
	"WindowsVolumeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSPRIVILEGE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPRIVILEGE"(
	"WindowsPrivilegeID" INTEGER NOT NULL,
	"PrivilegeID" INTEGER NULL,
	"User_Right" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSPROCESS"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPROCESS"(
	"WindowsProcessID" INTEGER NOT NULL,
	"ProcessID" INTEGER NULL,
	"WindowsProcessGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"aslr_enabled" INTEGER NULL,
	"dep_enabled" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSPROCESSTOKEN"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSPROCESSTOKEN"(
	"WindowsProcessTokenID" INTEGER NOT NULL,
	"WindowsProcessID" INTEGER NOT NULL,
	"TokenID" INTEGER NOT NULL,
	"IntegrityLevelID" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSREGISTRYKEYOBJECT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSREGISTRYKEYOBJECT"(
	"WindowsRegistryKeyObjectID" INTEGER NOT NULL,
	"Hive" TEXT NULL,
	"operation" TEXT NULL,
	"Full_Key" TEXT NULL,
	"RegistryHiveID" INTEGER NULL,
	"Number_Values" INTEGER NULL,
	"Name" TEXT NULL,
	"comment" TEXT NULL,
	"RegistryValuesID" INTEGER NULL,
	"Modified_Time" TEXT NULL,
	"Creator_Username" TEXT NULL,
	"AccountID" INTEGER NULL,
	"UserAccountID" INTEGER NULL,
	"WindowsUserAccountID" INTEGER NULL,
	"WindowsHandleListID" INTEGER NULL,
	"Number_Subkeys" INTEGER NULL,
	"RegistrySubkeysID" INTEGER NULL,
	"ByteRunsID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CollectionMethodID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSSEMAPHORE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSSEMAPHORE"(
	"WindowsSemaphoreID" INTEGER NOT NULL,
	"SemaphoreID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSSERVICE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSSERVICE"(
	"WindowsServiceID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSSYSTEM"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSSYSTEM"(
	"WindowsSystemID" INTEGER NOT NULL,
	"SystemID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSSYSTEMRESTORE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSSYSTEMRESTORE"(
	"WindowsSystemRestoreID" INTEGER NOT NULL,
	"Restore_Point_Description" TEXT NULL,
	"Restore_Point_Full_Path" TEXT NULL,
	"Restore_Point_Name" TEXT NULL,
	"Restore_Point_Type" TEXT NULL,
	"ACL_Change_SID" TEXT NULL,
	"ACL_Change_Username" TEXT NULL,
	"Backup_File_Name" TEXT NULL,
	"Change_Event" TEXT NULL,
	"ChangeLog_Entry_Flags" TEXT NULL,
	"ChangeLog_Entry_Sequence_Number" INTEGER NULL,
	"ChangeLog_Entry_Type" TEXT NULL,
	"Change_Log_File_Name" TEXT NULL,
	"Created" TEXT NULL,
	"File_Attributes" TEXT NULL,
	"New_File_Name" TEXT NULL,
	"Original_File_Name" TEXT NULL,
	"Original_Short_File_Name" TEXT NULL,
	"Process_Name" TEXT NULL,
	"Registry_Hive_List" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSTASK"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSTASK"(
	"WindowsTaskID" INTEGER NOT NULL,
	"TaskID" INTEGER NULL,
	"SessionCronID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"Status" TEXT NULL,
	"TaskStatusID" INTEGER NULL,
	"Priority" TEXT NULL,
	"TaskPriorityID" INTEGER NULL,
	"Name" TEXT NULL,
	"Application_Name" TEXT NULL,
	"ApplicationID" INTEGER NULL,
	"CPEName" TEXT NULL,
	"Parameters" TEXT NULL,
	"Flags" TEXT NULL,
	"Account_Name" TEXT NULL,
	"AccountID" INTEGER NULL,
	"Account_Run_Level" TEXT NULL,
	"Account_Logon_Type" TEXT NULL,
	"Creator" TEXT NULL,
	"Creation_Date" TEXT NULL,
	"Most_Recent_Run_Time" TEXT NULL,
	"Exit_Code" INTEGER NULL,
	"Max_Run_Time" INTEGER NULL,
	"Next_Run_Time" TEXT NULL,
	"Comment" TEXT NULL,
	"Working_Directory" TEXT NULL,
	"DirectoryID" INTEGER NULL,
	"Work_Item_Data" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSTHREAD"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSTHREAD"(
	"WindowsThreadID" INTEGER NOT NULL,
	"Thread_ID" INTEGER NULL,
	"WindowsHandleID" INTEGER NULL,
	"ThreadRunningStatusID" INTEGER NULL,
	"Running_Status" TEXT NULL,
	"Context" TEXT NULL,
	"Priority" INTEGER NULL,
	"Creation_Flags" TEXT NULL,
	"Creation_Time" TEXT NULL,
	"Start_Address" TEXT NULL,
	"StartMemoryAddressID" INTEGER NULL,
	"Parameter_Address" TEXT NULL,
	"ParameterMemoryAddressID" INTEGER NULL,
	"Security_Attributes" TEXT NULL,
	"Stack_Size" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSUSERACCOUNT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSUSERACCOUNT"(
	"WindowsUserAccountID" INTEGER NOT NULL,
	"WindowsUserAccountGUID" TEXT NULL,
	"AccountID" INTEGER NULL,
	"UserAccountID" INTEGER NULL,
	"WindowsComputerAccountID" INTEGER NULL,
	"Security_ID" TEXT NULL,
	"Security_Type" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"TrustLevelID" INTEGER NULL,
	"TrustReasonID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"suspected_malicious" INTEGER NULL,
	"SuspectedMaliciousReasonID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSUSERACCOUNTCHANGERECORD"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSUSERACCOUNTCHANGERECORD"(
	"WindowsUserAccountChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSUSERACCOUNTPRIVILEGE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSUSERACCOUNTPRIVILEGE"(
	"WindowsUserAccountPrivilegeID" INTEGER NOT NULL,
	"WindowsUserAccountID" INTEGER NOT NULL,
	"WindowsPrivilegeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSVOLUME"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSVOLUME"(
	"WindowsVolumeID" INTEGER NOT NULL,
	"WindowsVolumeGUID" TEXT NULL,
	"VolumeObjectID" INTEGER NULL,
	"Drive_Letter" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSVOLUMEATTRIBUTE"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSVOLUMEATTRIBUTE"(
	"WindowsVolumeAttributeID" INTEGER NOT NULL,
	"AttributeID" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSVOLUMEATTRIBUTEENUM"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSVOLUMEATTRIBUTEENUM"(
	"WindowsVolumeAttributeEnumID" INTEGER NOT NULL,
	"WindowsVolumeAttributeEnumValue" TEXT NOT NULL,
	"WindowsVolumeAttributeEnumDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "WINDOWSVOLUMEATTRIBUTESLIST"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSVOLUMEATTRIBUTESLIST"(
	"WindowsVolumeAttributesListID" INTEGER NOT NULL,
	"WindowsVolumeID" INTEGER NOT NULL,
	"WindowsVolumeAttributeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSVOLUMEENCRYPTION"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSVOLUMEENCRYPTION"(
	"WindowsVolumeEncryptionID" INTEGER NOT NULL,
	"WindowsVolumeID" INTEGER NOT NULL,
	"EncryptionID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINDOWSWAITABLETIMER"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSWAITABLETIMER"(
	"WindowsWaitableTimerID" INTEGER NOT NULL
)

;
/****** Object:  Table "WINDOWSWAITABLETIMEROBJECT"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINDOWSWAITABLETIMEROBJECT"(
	"WindowsWaitableTimerObjectID" INTEGER NOT NULL,
	"WindowsHandleID" INTEGER NULL,
	"WindowsWaitableTimerObjectName" TEXT NULL,
	"Security_Attributes" TEXT NULL,
	"WaitableTimerTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "WINWAITABLETIMER"    Script Date: 04/03/2015 19:52:20 ******/

;

;
CREATE TABLE "WINWAITABLETIMER"(
	"WinWaitableTimerID" INTEGER NOT NULL
)

;

COMMIT;
