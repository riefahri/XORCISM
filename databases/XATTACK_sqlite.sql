BEGIN TRANSACTION;

/****** 
Copyright (C) 2014-2015 Jerome Athias
Attacks related tables for XORCISM database
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "ATTACKCATEGORY"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKCATEGORY"(
	"AttackCategoryID" INTEGER NOT NULL,
	"AttackCategoryGUID" TEXT NULL,
	"CategoryID" INTEGER NULL,
	"CategoryGUID" TEXT NULL,
	"AttackCategoryName" TEXT NULL,
	"AttackCategoryDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKCATEGORYREFERENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKCATEGORYREFERENCE"(
	"AttackCategoryReferenceID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKCONSEQUENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKCONSEQUENCE"(
	"AttackConsequenceID" INTEGER NOT NULL,
	"Consequence" TEXT NULL,
	"ConsequenceNote" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKCONSEQUENCETAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKCONSEQUENCETAG"(
	"AttackConsequenceTagID" INTEGER NOT NULL,
	"AttackConsequenceID" INTEGER NULL,
	"TagID" INTEGER NULL
)

;
/****** Object:  Table "ATTACKEXAMPLE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKEXAMPLE"(
	"AttackExampleID" INTEGER NOT NULL,
	"AttackExampleGUID" TEXT NULL,
	"AttackExampleName" TEXT NULL,
	"AttackExampleDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"AttackExampleVocabularyID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKEXAMPLEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKEXAMPLEFORATTACKPATTERN"(
	"AttackExampleForAttackPatternID" INTEGER NOT NULL,
	"AttackExampleID" INTEGER NOT NULL,
	"AttackExampleGUID" TEXT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"capec_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKEXECUTIONFLOW"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKEXECUTIONFLOW"(
	"AttackExecutionFlowID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"capec_id" TEXT NULL,
	"AttackExecutionFlowGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ATTACKEXECUTIONFLOWPHASE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKEXECUTIONFLOWPHASE"(
	"AttackExecutionFlowPhaseID" INTEGER NOT NULL,
	"AttackExecutionFlowID" INTEGER NULL,
	"AttackExecutionFlowGUID" TEXT NULL,
	"AttackPhaseID" INTEGER NULL,
	"AttackPhaseGUID" TEXT NULL,
	"AttackPhaseOrder" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKMETHOD"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKMETHOD"(
	"AttackMethodID" INTEGER NOT NULL,
	"AttackMethodGUID" TEXT NULL,
	"AttackMethodTitle" TEXT NOT NULL,
	"AttackMethodDescription" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKMETHODDESCRIPTION"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKMETHODDESCRIPTION"(
	"AttackMethodDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKMETHODFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKMETHODFORATTACKPATTERN"(
	"AttackPatternMethodID" INTEGER NOT NULL,
	"AttackMethodID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKMETHODREFERENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKMETHODREFERENCE"(
	"AttackMethodReferenceID" INTEGER NOT NULL,
	"AttackMethodID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKMETHODTAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKMETHODTAG"(
	"AttackMethodTagID" INTEGER NOT NULL,
	"AttackMethodID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERN"(
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"capec_id" TEXT NULL,
	"category" INTEGER NULL,
	"AttackPatternName" TEXT NULL,
	"AttackPatternDescription" TEXT NULL,
	"PatternAbstraction" TEXT NULL,
	"PatternCompleteness" TEXT NULL,
	"PatternStatus" TEXT NULL,
	"TypicalSeverity" TEXT NULL,
	"Payload_Activation_Impact" TEXT NULL,
	"SourceID" INTEGER NULL,
	"SourceGUID" TEXT NULL,
	"RepositoryID" INTEGER NULL,
	"RepositoryGUID" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"VocabularyGUID" TEXT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"CreationObjectGUID" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNATTACKCONSEQUENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNATTACKCONSEQUENCE"(
	"AttackPatternAttackConsequenceID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"CAPECAttackConsequenceOrder" INTEGER NULL,
	"AttackConsequenceID" INTEGER NULL,
	"Consequence_Note" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNATTACKCONSEQUENCESCOPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNATTACKCONSEQUENCESCOPE"(
	"AttackPatternAttackConsequenceScopeID" INTEGER NOT NULL,
	"AttackPatternAttackConsequenceID" INTEGER NULL,
	"AttackScopeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNATTACKTECHNICALIMPACT"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNATTACKTECHNICALIMPACT"(
	"AttackPatternAttackTechnicalImpactID" INTEGER NOT NULL,
	"AttackPatternAttackConsequenceID" INTEGER NULL,
	"AttackTechnicalImpactID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNCWE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNCWE"(
	"AttackPatternCWEID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"WeaknessRelationship" TEXT NULL,
	"CWEID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNFORTHREATACTORTTP"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNFORTHREATACTORTTP"(
	"AttackPatternForThreatActorTTPID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNINDICATORWARNING"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNINDICATORWARNING"(
	"AttackPatternIndicatorWarningID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternIndicatorWarningOrder" INTEGER NULL,
	"IndicatorWarningAttack" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNMITIGATION"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNMITIGATION"(
	"AttackPatternMitigationID" INTEGER NOT NULL,
	"AttackPatternMitigationGUID" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"MitigationID" INTEGER NULL,
	"MitigationGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNNOTE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNNOTE"(
	"AttackPatternNoteID" INTEGER NOT NULL,
	"NoteText" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNNOTES"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNNOTES"(
	"AttackPatternNotesID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"NoteOrder" INTEGER NULL,
	"AttackPatternNoteID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNOBFUSCATIONTECHNIQUE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNOBFUSCATIONTECHNIQUE"(
	"AttackPatternObfuscationTechniqueID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"ObfuscationTechniqueID" INTEGER NOT NULL,
	"ObfuscationTechniqueGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNPROBINGTECHNIQUE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNPROBINGTECHNIQUE"(
	"AttackPatternProbingTechniqueID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"AttackTechniqueID" INTEGER NULL,
	"AttackTechniqueGUID" TEXT NULL,
	"TechniqueID" INTEGER NULL,
	"TechniqueGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNREFERENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNREFERENCE"(
	"AttackPatternReferenceID" INTEGER NOT NULL,
	"AttackPatternReferenceGUID" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"ReferenceID" INTEGER NULL,
	"ReferenceGUID" TEXT NULL,
	"Reference_ID" TEXT NULL,
	"Local_Reference_ID" TEXT NULL,
	"Reference_Section" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNRELATIONSHIP"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNRELATIONSHIP"(
	"AttackPatternRelationshipID" INTEGER NOT NULL,
	"AttackPatternRefID" INTEGER NULL,
	"AttackPatternRefGUID" TEXT NULL,
	"RelationshipName" TEXT NULL,
	"Relationship_Description" TEXT NULL,
	"AttackPatternSubjectID" INTEGER NULL,
	"AttackPatternSubjectGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNSECURITYCONTROL"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNSECURITYCONTROL"(
	"AttackPatternSecurityControlID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"SecurityControlID" INTEGER NULL,
	"AttackPatternSecurityControlVocabularyID" INTEGER NULL,
	"AttackPatternSecurityControlOrder" INTEGER NULL,
	"SecurityControlTypeID" INTEGER NULL,
	"SecurityControlType" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ATTACKPATTERNTAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNTAG"(
	"AttackPatternTagID" INTEGER NOT NULL,
	"AttackPatternTagGUID" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"TagGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNVIEW"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNVIEW"(
	"AttackPatternViewID" INTEGER NOT NULL,
	"AttackPatternViewGUID" TEXT NULL,
	"ViewVocabularyID" INTEGER NULL,
	"AttackPatternViewName" TEXT NULL,
	"View_Structure" TEXT NULL,
	"AttackPatternViewDescription" TEXT NULL,
	"View_Filter" TEXT NULL,
	"ViewStatus" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPATTERNVIEWRELATIONSHIP"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPATTERNVIEWRELATIONSHIP"(
	"AttackPatternViewRelationshipID" INTEGER NOT NULL,
	"AttackPatternViewID" INTEGER NULL,
	"Ordinal" TEXT NULL,
	"Relationship_Target_Form" TEXT NULL,
	"Relationship_Nature" TEXT NULL,
	"Relationship_Description" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPAYLOAD"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPAYLOAD"(
	"AttackPayloadID" INTEGER NOT NULL,
	"AttackPayloadGUID" TEXT NULL,
	"PayloadText" TEXT NOT NULL,
	"Payload_Activation_Impact" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromdate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPAYLOADENCODER"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPAYLOADENCODER"(
	"AttackPayloadEncoderID" INTEGER NOT NULL,
	"AttackPayloadEncoderName" TEXT NULL,
	"AttackPayloadEncoderDescription" TEXT NULL,
	"AttackPayloadEncoderVersion" TEXT NULL,
	BLOB TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPAYLOADFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPAYLOADFORATTACKPATTERN"(
	"AttackPatternPayloadID" INTEGER NOT NULL,
	"AttackPatternPayloadGUID" TEXT NULL,
	"AttackPayloadID" INTEGER NOT NULL,
	"AttackPayloadGUID" TEXT NULL,
	"AttackPayloadImpactID" INTEGER NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"AttackPatternGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPAYLOADIMPACT"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPAYLOADIMPACT"(
	"AttackPayloadImpactID" INTEGER NOT NULL,
	"PayloadActivationImpactDescription" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPAYLOADIMPACTFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPAYLOADIMPACTFORATTACKPATTERN"(
	"AttackPatternPayloadImpactID" INTEGER NOT NULL,
	"AttackPayloadImpactID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"capec_id" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPHASE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPHASE"(
	"AttackPhaseID" INTEGER NOT NULL,
	"AttackPhaseGUID" TEXT NULL,
	"PhaseID" INTEGER NULL,
	"AttackPhaseName" TEXT NULL,
	"AttackPhaseDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPHASEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPHASEFORATTACKPATTERN"(
	"AttackPatternAttackPhaseID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"AttackPhaseGUID" TEXT NULL,
	"AttackPhaseID" INTEGER NULL,
	"AttackPhaseVocabularyID" INTEGER NULL,
	"AttackPhaseOrder" INTEGER NULL,
	"AttackPhaseDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPREREQUISITE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPREREQUISITE"(
	"AttackPrerequisiteID" INTEGER NOT NULL,
	"AttackPrerequisiteGUID" TEXT NULL,
	"PrerequisiteText" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKPREREQUISITEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPREREQUISITEFORATTACKPATTERN"(
	"AttackPatternAttackPrerequisiteID" INTEGER NOT NULL,
	"AttackPrerequisiteID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPURPOSE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPURPOSE"(
	"AttackPurposeID" INTEGER NOT NULL,
	"AttackPurposeGUID" TEXT NULL,
	"AttackPurposeName" TEXT NOT NULL,
	"AttackPurposeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKPURPOSEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKPURPOSEFORATTACKPATTERN"(
	"AttackPatternPurposeID" INTEGER NOT NULL,
	"AttackPurposeID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKRESOURCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKRESOURCE"(
	"AttackResourceID" INTEGER NOT NULL,
	"AttackResourceText" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKRESOURCEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKRESOURCEFORATTACKPATTERN"(
	"AttackPatternAttackResourceRequiredID" INTEGER NOT NULL,
	"AttackResourceID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKRESOURCETAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKRESOURCETAG"(
	"AttackResourceTagID" INTEGER NOT NULL,
	"AttackResourceID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSCENARIO"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSCENARIO"(
	"AttackScenarioID" INTEGER NOT NULL,
	"ScenarioID" INTEGER NOT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ATTACKSCOPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSCOPE"(
	"AttackScopeID" INTEGER NOT NULL,
	"AttackScopeGUID" TEXT NULL,
	"ConsequenceScope" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSTEP"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEP"(
	"AttackStepID" INTEGER NOT NULL,
	"AttackStepGUID" TEXT NULL,
	"AttackPatternAttackPhaseID" INTEGER NULL,
	"AttackStepVocabularyID" INTEGER NULL,
	"AttackStepOrder" INTEGER NULL,
	"Attack_Step_Title" TEXT NULL,
	"Attack_Step_Description" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPINDICATOR"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPINDICATOR"(
	"AttackStepIndicatorID" INTEGER NOT NULL,
	"AttackStepIndicatorGUID" TEXT NULL,
	"AttackStepID" INTEGER NULL,
	"AttackStepGUID" TEXT NULL,
	"IndicatorID" INTEGER NULL,
	"IndicatorGUID" TEXT NULL,
	"AttackStepIndicatorVocabularyID" TEXT NULL,
	"AttackStepIndicatorType" TEXT NULL,
	"AttackStepIndicatorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSTEPINDICATORENVIRONMENT"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPINDICATORENVIRONMENT"(
	"AttackStepIndicatorEnvironmentID" INTEGER NOT NULL,
	"AttackStepIndicatorID" INTEGER NOT NULL,
	"EnvironmentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSTEPINDICATORTAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPINDICATORTAG"(
	"AttackStepIndicatorTagID" INTEGER NOT NULL,
	"AttackStepIndicatorID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPOUTCOME"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPOUTCOME"(
	"AttackStepOutcomeID" INTEGER NOT NULL,
	"AttackStepID" INTEGER NULL,
	"OutcomeVocabularyID" TEXT NULL,
	"OutcomeType" TEXT NULL,
	"OutcomeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSTEPOUTCOMETAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPOUTCOMETAG"(
	"AttackStepOutcomeTagID" INTEGER NOT NULL,
	"AttackStepOutcomeID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPSECURITYCONTROL"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPSECURITYCONTROL"(
	"AttackStepSecurityControlID" INTEGER NOT NULL,
	"AttackStepID" INTEGER NULL,
	"AttackStepGUID" TEXT NULL,
	"SecurityControlID" INTEGER NULL,
	"SecurityControlGUID" TEXT NULL,
	"AttackStepSecurityControlVocabularyID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPTAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPTAG"(
	"AttackStepTagID" INTEGER NOT NULL,
	"AttackStepID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPTECHNIQUE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPTECHNIQUE"(
	"AttackStepTechniqueID" INTEGER NOT NULL,
	"AttackStepTechniqueGUID" TEXT NULL,
	"AttackStepTechniqueVocabularyID" TEXT NULL,
	"AttackStepID" INTEGER NULL,
	"AttackTechniqueID" INTEGER NULL,
	"AttackStepTechniqueOrder" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPTECHNIQUEENVIRONMENT"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPTECHNIQUEENVIRONMENT"(
	"AttackStepTechniqueEnvironmentID" INTEGER NOT NULL,
	"AttackStepTechniqueID" INTEGER NULL,
	"EnvironmentID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSTEPTECHNIQUELEVERAGEDPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSTEPTECHNIQUELEVERAGEDPATTERN"(
	"AttackStepTechniqueLeveragedPatternID" INTEGER NOT NULL,
	"AttackStepTechniqueID" INTEGER NULL,
	"AttackStepTechniqueGUID" TEXT NULL,
	"AttackPatternID" INTEGER NULL,
	"AttackPatternGUID" TEXT NULL,
	"LeveragedAttackPatternOrder" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSURFACE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACE"(
	"AttackSurfaceID" INTEGER NOT NULL,
	"AttackSurfaceGUID" TEXT NULL,
	"AttackSurfaceName" TEXT NULL,
	"AttackSurfaceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"ConfidenceReasonID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSURFACECHANGERECORD"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACECHANGERECORD"(
	"AttackSurfaceChangeRecordID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKSURFACEFORATTACKPATTERN"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACEFORATTACKPATTERN"(
	"AttackPatternSurfaceID" INTEGER NOT NULL,
	"AttackSurfaceID" INTEGER NOT NULL,
	"AttackPatternID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSURFACEINTERACTIONPOINTS"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACEINTERACTIONPOINTS"(
	"AttackSurfaceInteractionPointsID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKSURFACELOCALITY"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACELOCALITY"(
	"AttackSurfaceLocalityID" INTEGER NOT NULL,
	"AttackSurfaceLocalityName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSURFACELOCALITYFORATTACKSURFACE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACELOCALITYFORATTACKSURFACE"(
	"AttackSurfaceLocalitiesID" INTEGER NOT NULL,
	"AttackSurfaceLocalityID" INTEGER NOT NULL,
	"AttackSurfaceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKSURFACESERVICE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACESERVICE"(
	"AttackSurfaceServiceID" INTEGER NOT NULL,
	"AttackSurfaceID" INTEGER NOT NULL,
	"EndPointID" INTEGER NULL,
	"TargetFunctionalServiceID" INTEGER NULL,
	"TargetFunctionalServiceName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSURFACESERVICEPROTOCOL"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACESERVICEPROTOCOL"(
	"AttackSurfaceServiceProtocolID" INTEGER NOT NULL,
	"AttackSurfaceServiceID" INTEGER NOT NULL,
	"TargetFunctionalServiceProtocolID" INTEGER NULL,
	"ProtocolID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSURFACETYPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACETYPE"(
	"AttackSurfaceTypeID" INTEGER NOT NULL,
	"AttackSurfaceTypeName" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKSURFACETYPEFORATTACKSURFACE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKSURFACETYPEFORATTACKSURFACE"(
	"AttackSurfaceTypesID" INTEGER NOT NULL,
	"AttackSurfaceTypeID" INTEGER NOT NULL,
	"AttackSurfaceID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTECHNICALIMPACT"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNICALIMPACT"(
	"AttackTechnicalImpactID" INTEGER NOT NULL,
	"AttackTechnicalImpactGUID" TEXT NULL,
	"ImpactID" INTEGER NULL,
	"ConsequenceTechnicalImpact" TEXT NOT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKTECHNIQUE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNIQUE"(
	"AttackTechniqueID" INTEGER NOT NULL,
	"AttackTechniqueGUID" TEXT NULL,
	"TechniqueID" INTEGER NULL,
	"AttackTechniqueName" TEXT NULL,
	"AttackTechniqueDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTECHNIQUEINDICATOR"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNIQUEINDICATOR"(
	"AttackTechniqueIndicatorID" INTEGER NOT NULL,
	"AttackTechniqueID" INTEGER NULL,
	"IndicatorID" INTEGER NULL,
	"CreatedDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKTECHNIQUEREFERENCE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNIQUEREFERENCE"(
	"AttackTechniqueReferenceID" INTEGER NOT NULL,
	"AttackTechniqueID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTECHNIQUETAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNIQUETAG"(
	"AttackTechniqueTagID" INTEGER NOT NULL,
	"AttackTechniqueID" INTEGER NULL,
	"AttackTechniqueGUID" TEXT NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTECHNIQUETOOL"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTECHNIQUETOOL"(
	"AttackTechniqueToolID" INTEGER NOT NULL,
	"AttackTechniqueID" INTEGER NULL,
	"AttackTechniqueGUID" TEXT NULL,
	"AttackToolID" INTEGER NULL,
	"AttackToolGUID" TEXT NULL,
	"ToolID" INTEGER NULL,
	"ToolGUID" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKTOOL"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOL"(
	"AttackToolID" INTEGER NOT NULL,
	"AttackTooldGUID" TEXT NULL,
	"TooldID" INTEGER NULL,
	"AttackToolTypeID" INTEGER NULL,
	"AttackToolName" TEXT NOT NULL,
	"AttackToolVersion" TEXT NULL,
	"VersionID" INTEGER NULL,
	"AttackToolDescription" TEXT NULL,
	"AttackToolAuthor" TEXT NULL,
	"AttackToolLink" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTOOLAUTHENTICATIONTYPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLAUTHENTICATIONTYPE"(
	"AttackToolAuthenticationTypeID" INTEGER NOT NULL,
	"AttackToolID" INTEGER NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"AttackToolAuthenticationTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTOOLDESCRIPTION"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLDESCRIPTION"(
	"AttackToolDescriptionID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKTOOLFORTHREATACTORTTP"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLFORTHREATACTORTTP"(
	"ThreatActorTTPAttackToolID" INTEGER NOT NULL,
	"AttackToolID" INTEGER NOT NULL,
	"ThreatActorTTPID" INTEGER NOT NULL,
	"notes" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "ATTACKTOOLMODULE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLMODULE"(
	"AttackToolModuleID" INTEGER NOT NULL,
	"AttackToolModuleName" TEXT NULL,
	"AttackToolModuleDescription" TEXT NULL,
	"AttackToolModuleVersion" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "ATTACKTOOLMODULEAUTHENTICATIONTYPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLMODULEAUTHENTICATIONTYPE"(
	"AttackToolModuleAuthenticationTypeID" INTEGER NOT NULL,
	"AttackToolModuleID" INTEGER NULL,
	"AuthenticationTypeID" INTEGER NULL,
	"AttackToolModuleAuthenticationTypeDescription" TEXT NULL,
	"ConfidenceLevelID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "ATTACKTOOLTAG"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLTAG"(
	"AttackToolTagID" INTEGER NOT NULL
)

;
/****** Object:  Table "ATTACKTOOLTYPE"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKTOOLTYPE"(
	"AttackToolTypeID" INTEGER NOT NULL,
	"AttackToolTypeGUID" TEXT NULL,
	"AttackToolTypeName" TEXT NOT NULL,
	"AttackToolTypeDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"EnumerationVersionID" INTEGER NULL
)

;
/****** Object:  Table "ATTACKVECTOR"    Script Date: 04/03/2015 19:42:32 ******/

;

;
CREATE TABLE "ATTACKVECTOR"(
	"AttackVectorID" INTEGER NOT NULL,
	"AttackVectorName" TEXT NULL,
	"AttackvectorDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;

COMMIT;
