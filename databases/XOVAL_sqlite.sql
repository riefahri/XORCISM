BEGIN TRANSACTION;

/****** 
Copyright (C) 2014-2015 Jerome Athias
MITRE OVAL related tables for XORCISM database
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
******/

;
/****** Object:  Table "OPERATORENUMERATION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OPERATORENUMERATION"(
	"OperatorEnumerationID" INTEGER NOT NULL,
	"OperatorValue" TEXT NOT NULL,
	"OperatorDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALBEHAVIOR"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALBEHAVIOR"(
	"OVALBehaviorID" INTEGER NOT NULL,
	"BehaviorKey" TEXT NULL,
	"BehaviorValue" TEXT NULL,
	"BehaviorID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALBEHAVIORFOROVALOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALBEHAVIORFOROVALOBJECT"(
	"OVALObjectBehaviorID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"OVALBehaviorID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OVALCLASSDIRECTIVES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCLASSDIRECTIVES"(
	"OVALClassDirectivesID" INTEGER NOT NULL,
	"OVALClassEnumerationID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALCLASSDIRECTIVESFOROVALDIRECTIVES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCLASSDIRECTIVESFOROVALDIRECTIVES"(
	"OVALDirectivesID" INTEGER NOT NULL,
	"OVALClassDirectivesID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALCLASSDIRECTIVESFOROVALRESULTS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCLASSDIRECTIVESFOROVALRESULTS"(
	"OVALResultsID" INTEGER NOT NULL,
	"OVALClassDirectivesID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALCLASSENUMERATION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCLASSENUMERATION"(
	"OVALClassEnumerationID" INTEGER NOT NULL,
	"OVALClassEnumerationGUID" TEXT NULL,
	"ClassValue" TEXT NOT NULL,
	"ClassDescription" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALCOMPONENTGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCOMPONENTGROUP"(
	"OVALComponentGroupID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NULL,
	"OVALFunctionID" INTEGER NULL,
	"FunctionName" TEXT NULL,
	"FunctionOperation" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALCRITERIA"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIA"(
	"OVALCriteriaID" INTEGER NOT NULL,
	"OperatorEnumerationID" INTEGER NULL,
	"negate" INTEGER NULL,
	"comment" TEXT NULL,
	"applicabilitycheck" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALCRITERIACRITERION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIACRITERION"(
	"OVALCriteriaCriterionID" INTEGER NOT NULL,
	"OVALCriteriaID" INTEGER NOT NULL,
	"negate" INTEGER NULL,
	"OVALTestID" INTEGER NULL,
	"comment" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALCRITERIAEXTENDDEFINITION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIAEXTENDDEFINITION"(
	"OVALCriteriaExtendDefinitionID" INTEGER NOT NULL,
	"OVALCriteriaID" INTEGER NOT NULL,
	"negate" INTEGER NULL,
	"OVALDefinitionID" INTEGER NULL,
	"comment" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALCRITERIAFOROVALCRITERIA"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIAFOROVALCRITERIA"(
	"OVALCriteriaRelationshipID" INTEGER NOT NULL,
	"OVALCriteriaRefID" INTEGER NOT NULL,
	"RelationshipName" TEXT NULL,
	"OVALCriteriaSubjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CriteriaRank" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALCRITERIATYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIATYPE"(
	"OVALCriteriaTypeID" INTEGER NOT NULL,
	"OperatorEnumerationID" INTEGER NOT NULL,
	"OperatorValue" TEXT NOT NULL,
	"negate" INTEGER NULL,
	"ResultEnumerationID" INTEGER NOT NULL,
	"applicability_check" INTEGER NULL
)

;
/****** Object:  Table "OVALCRITERIATYPEFOROVALDEFINITIONTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIATYPEFOROVALDEFINITIONTYPE"(
	"OVALDefinitionTypeID" INTEGER NOT NULL,
	"OVALCriteriaTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALCRITERION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERION"(
	"OVALCriterionID" INTEGER NOT NULL,
	"OVALTestIDPattern" TEXT NOT NULL,
	"negate" INTEGER NULL,
	"comment" TEXT NULL,
	"applicabilitycheck" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALCRITERIONTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIONTYPE"(
	"OVALCriterionTypeID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NULL,
	"OVALTestIDPattern" TEXT NOT NULL,
	"OVALTestVersion" INTEGER NOT NULL,
	"variable_instance" INTEGER NULL,
	"negate" INTEGER NULL,
	"ResultEnumerationID" INTEGER NOT NULL,
	"applicability_check" INTEGER NULL
)

;
/****** Object:  Table "OVALCRITERIONTYPEFOROVALCRITERIATYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALCRITERIONTYPEFOROVALCRITERIATYPE"(
	"OVALCriteriaTypeID" INTEGER NOT NULL,
	"OVALCriterionTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALDEFAULTDIRECTIVES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFAULTDIRECTIVES"(
	"OVALDefaultDirectivesID" INTEGER NOT NULL,
	"include_source_definitions" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITION"(
	"OVALDefinitionID" INTEGER NOT NULL,
	"OVALDefinitionIDPattern" TEXT NOT NULL,
	"OVALDefinitionVersion" INTEGER NOT NULL,
	"OVALClassEnumerationID" INTEGER NULL,
	"deprecated" INTEGER NULL,
	"OVALDefinitionTitle" TEXT NULL,
	"OVALDefinitionDescription" TEXT NULL,
	"notes" TEXT NULL,
	"OVALCriteriaID" INTEGER NULL,
	"signature" TEXT NULL,
	"StatusName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONCCE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONCCE"(
	"OVALDefinitionCCEID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NOT NULL,
	"CCEID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONCHANGE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONCHANGE"(
	"OVALDefinitionChangeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ChangeDate" TEXT NULL,
	"ChangeTypeName" TEXT NULL,
	"ChangeValue" TEXT NULL,
	"ChangeComment" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONCHANGES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONCHANGES"(
	"OVALDefinitionChangesID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"OVALDefinitionChangeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"OrganisationID" INTEGER NULL,
	"PersonID" INTEGER NULL,
	"AuthorID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONCPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONCPE"(
	"OVALDefinitionCPEID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"OVALDefinitionCPERelationship" TEXT NULL,
	"CPEID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONFAMILY"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONFAMILY"(
	"OVALDefinitionFamilyID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"OSFamilyID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONORGANISATION"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONORGANISATION"(
	"OrganisationOVALDefinitionID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NOT NULL,
	"OrganisationID" INTEGER NOT NULL,
	"OrganisationRole" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONPLATFORM"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONPLATFORM"(
	"OVALDefinitionPlatformID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"PlatformID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONPRODUCT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONPRODUCT"(
	"OVALDefinitionProductID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"ProductID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONREFERENCE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONREFERENCE"(
	"OVALDefinitionReferenceID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"ReferenceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONS"(
	"OVALDefinitionsID" INTEGER NOT NULL,
	"GeneratorTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALDEFINITIONSTATUS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONSTATUS"(
	"OVALDefinitionID" INTEGER NOT NULL,
	"StatusID" INTEGER NOT NULL,
	"StatusDate" TEXT NULL,
	BLOB TEXT NULL
)

;
/****** Object:  Table "OVALDEFINITIONTAG"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONTAG"(
	"OVALDefinitionTagID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDEFINITIONTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONTYPE"(
	"OVALDefinitionTypeID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"OVALDefinitionIDPattern" TEXT NOT NULL,
	"OVALDefinitionVersion" INTEGER NOT NULL,
	"variable_instance" INTEGER NULL,
	"OVALClassEnumerationID" INTEGER NULL,
	"ClassValue" TEXT NULL,
	"ResultEnumerationID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALDEFINITIONTYPEFOROVALSYSTEMTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONTYPEFOROVALSYSTEMTYPE"(
	"OVALSystemTypeID" INTEGER NOT NULL,
	"OVALDefinitionTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALDEFINITIONVULNERABILITY"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDEFINITIONVULNERABILITY"(
	"OVALDefinitionVulnerabilityID" INTEGER NOT NULL,
	"OVALDefinitionID" INTEGER NULL,
	"OVALDefinitionVulnerabilityRelationship" TEXT NULL,
	"VulnerabilityID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALDIRECTIVE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDIRECTIVE"(
	"OVALDirectiveID" INTEGER NOT NULL,
	"reported" INTEGER NOT NULL,
	"ContentEnumerationValue" TEXT NULL
)

;
/****** Object:  Table "OVALDIRECTIVES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDIRECTIVES"(
	"OVALDirectivesID" INTEGER NOT NULL,
	"GeneratorTypeID" INTEGER NOT NULL,
	"OVALDefaultDirectivesID" INTEGER NOT NULL,
	"signature" TEXT NULL
)

;
/****** Object:  Table "OVALDIRECTIVESTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALDIRECTIVESTYPE"(
	"OVALDirectivesTypeID" INTEGER NOT NULL,
	"definition_trueOVALDirectiveID" INTEGER NOT NULL,
	"definition_falseOVALDirectiveID" INTEGER NOT NULL,
	"definition_unknownOVALDirectiveID" INTEGER NOT NULL,
	"definition_errorDirectiveID" INTEGER NOT NULL,
	"definition_not_evaluatedDirectiveID" INTEGER NOT NULL,
	"definition_not_applicableDirectiveID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALENTITYATTRIBUTEGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALENTITYATTRIBUTEGROUP"(
	"OVALEntityAttributeGroupID" INTEGER NOT NULL,
	"SimpleDataTypeID" INTEGER NULL,
	"DataTypeName" TEXT NULL,
	"OperationEnumerationID" INTEGER NULL,
	"OperationValue" TEXT NULL,
	"mask" INTEGER NULL,
	"OVALVariableID" INTEGER NULL,
	"OVALVariableIDPattern" TEXT NULL,
	"CheckEnumerationID" INTEGER NULL,
	"EnumerationValue" TEXT NULL
)

;
/****** Object:  Table "OVALENTITYCOMPLEXBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALENTITYCOMPLEXBASE"(
	"OVALEntityComplexBaseID" INTEGER NOT NULL,
	"OVALEntityAttributeGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALENTITYSIMPLEBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALENTITYSIMPLEBASE"(
	"OVALEntitySimpleBaseID" INTEGER NOT NULL,
	"OVALEntityAttributeGroupID" INTEGER NOT NULL,
	"SimpleBaseValue" TEXT NULL
)

;
/****** Object:  Table "OVALEXTENSIONPOINT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALEXTENSIONPOINT"(
	"ExtensionPointID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALEXTENSIONPOINTFOROVALGENERATORTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALEXTENSIONPOINTFOROVALGENERATORTYPE"(
	"GeneratorTypeID" INTEGER NOT NULL,
	"ExtensionPointID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALEXTENSIONPOINTFORSYSTEMINFO"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALEXTENSIONPOINTFORSYSTEMINFO"(
	"SystemInfoID" INTEGER NOT NULL,
	"OVALExtensionPointID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALFILTER"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALFILTER"(
	"OVALFilterID" INTEGER NOT NULL,
	"OVALStateID" INTEGER NOT NULL,
	"FilterActionValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALFILTERFOROVALSET"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALFILTERFOROVALSET"(
	"OVALSetID" INTEGER NOT NULL,
	"OVALFilterID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALGENERATORTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALGENERATORTYPE"(
	"GeneratorTypeID" INTEGER NOT NULL,
	"productname" TEXT NULL,
	"productversion" TEXT NULL,
	"schemaversion" REAL NOT NULL,
	BLOB TEXT NOT NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OVALITEM"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALITEM"(
	"OVALItemID" INTEGER NOT NULL,
	"OVALItemIDPattern" TEXT NOT NULL,
	"StatusID" INTEGER NULL,
	"StatusName" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OVALITEMATTRIBUTEGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALITEMATTRIBUTEGROUP"(
	"OVALItemAttributeGroupID" INTEGER NOT NULL,
	"DataTypeName" TEXT NULL,
	"mask" INTEGER NULL,
	"StatusName" TEXT NULL,
	"OVALItemIDPattern" TEXT NULL
)

;
/****** Object:  Table "OVALITEMCOMPLEXBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALITEMCOMPLEXBASE"(
	"OVALItemComplexBaseID" INTEGER NOT NULL,
	"OVALItemAttributeGroupID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALITEMFOROVALSYSTEMOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALITEMFOROVALSYSTEMOBJECT"(
	"OVALSystemObjectID" INTEGER NOT NULL,
	"OVALItemID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALITEMSIMPLEBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALITEMSIMPLEBASE"(
	"OVALItemSimpleBaseID" INTEGER NOT NULL,
	"OVALItemAttributeGroupID" INTEGER NOT NULL,
	"EntityValue" TEXT NULL
)

;
/****** Object:  Table "OVALLITERALCOMPONENT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALLITERALCOMPONENT"(
	"OVALLiteralComponentID" INTEGER NOT NULL,
	"SimpleDataTypeID" INTEGER NULL,
	"LiteralComponentValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALLITERALCOMPONENTFOROVALCOMPONENTGROUP"(
	"OVALComponentGroupLiteralComponentID" INTEGER NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL,
	"OVALLiteralComponentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALMESSAGETYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPE"(
	"MessageTypeID" INTEGER NOT NULL,
	"MessageLevelValue" TEXT NULL,
	"MessageLevelID" INTEGER NULL,
	"MessageText" TEXT NOT NULL
)

;
/****** Object:  Table "OVALMESSAGETYPEFOROVALDEFINITIONTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPEFOROVALDEFINITIONTYPE"(
	"OVALDefinitionTypeID" INTEGER NOT NULL,
	"OVALMessageTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALMESSAGETYPEFOROVALITEM"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPEFOROVALITEM"(
	"OVALItemID" INTEGER NOT NULL,
	"MessageTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALMESSAGETYPEFOROVALSYSTEMOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPEFOROVALSYSTEMOBJECT"(
	"OVALSystemObjectID" INTEGER NOT NULL,
	"MessageTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALMESSAGETYPEFOROVALTESTEDITEM"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPEFOROVALTESTEDITEM"(
	"OVALTestedItemID" INTEGER NOT NULL,
	"MessageTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALMESSAGETYPEFOROVALTESTTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALMESSAGETYPEFOROVALTESTTYPE"(
	"OVALTestTypeID" INTEGER NOT NULL,
	"OVALMessageTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALNAMESPACE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALNAMESPACE"(
	"OVALNamespaceID" INTEGER NOT NULL,
	"OVALNamespaceName" TEXT NULL,
	"OVALNamespaceDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECT"(
	"OVALObjectID" INTEGER NOT NULL,
	"OVALObjectIDPattern" TEXT NOT NULL,
	"OVALObjectVersion" INTEGER NOT NULL,
	"OVALObjectGUID" TEXT NULL,
	"comment" TEXT NOT NULL,
	"deprecated" INTEGER NULL,
	"notes" TEXT NULL,
	"signature" TEXT NULL,
	"OVALObjectDataTypeID" INTEGER NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTCOMPONENT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTCOMPONENT"(
	"OVALObjectComponentID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"OVALItemEntityName" TEXT NOT NULL,
	"OVALItemEntityRecord" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTCOMPONENTFOROVALCOMPONENTGROUP"(
	"OVALComponentGroupObjectComponentID" INTEGER NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL,
	"OVALObjectComponentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTDATATYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTDATATYPE"(
	"OVALObjectDataTypeID" INTEGER NOT NULL,
	"OVALObjectDataTypeName" TEXT NULL,
	"OVALObjectDataTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTFIELD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTFIELD"(
	"OVALObjectFieldID" INTEGER NOT NULL,
	"OVALEntityAttributeGroupID" INTEGER NULL,
	"FieldName" TEXT NOT NULL,
	"OperationEnumerationID" INTEGER NULL,
	"FieldValue" TEXT NULL,
	"DataTypeName" TEXT NULL,
	"OVALNamespaceID" INTEGER NULL,
	"Namespace" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"CheckEnumerationID" INTEGER NULL,
	"OVALVariableID" INTEGER NULL,
	"VarRef" TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTFIELDFOROVALOBJECTRECORD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTFIELDFOROVALOBJECTRECORD"(
	"OVALObjectRecordFieldID" INTEGER NOT NULL,
	"OVALObjectRecordID" INTEGER NOT NULL,
	"OVALObjectFieldID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTFILE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTFILE"(
	"OVALObjectFileID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NULL,
	"FileID" INTEGER NULL,
	"OVALVariableID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTFOROVALSET"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTFOROVALSET"(
	"OVALSetObjectID" INTEGER NOT NULL,
	"OVALSetID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTFOROVALTEST"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTFOROVALTEST"(
	"OVALTestObjectID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTRECORD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTRECORD"(
	"OVALObjectRecordID" INTEGER NOT NULL,
	"OVALObjectDataTypeID" INTEGER NULL,
	"OperationValue" TEXT NULL,
	"mask" INTEGER NULL,
	"OVALVariableIDPattern" TEXT NULL,
	"EnumerationValue" TEXT NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTRECORDFOROVALOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTRECORDFOROVALOBJECT"(
	"OVALObjectObjectRecordID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"OVALObjectRecordID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTTAG"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTTAG"(
	"OVALObjectTagID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALOBJECTWINDOWSREGISTRYKEY"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALOBJECTWINDOWSREGISTRYKEY"(
	"OVALObjectWindowsRegistryKeyID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"OVALObjectGUID" TEXT NULL,
	"operation" TEXT NULL,
	"WindowsRegistryKeyObjectID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	"CreationObjectID" INTEGER NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALRESULTS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALRESULTS"(
	"OVALResultsID" INTEGER NOT NULL,
	"GeneratorTypeID" INTEGER NOT NULL,
	"OVALDefaultDirectivesID" INTEGER NOT NULL,
	"OVALDefinitionsID" INTEGER NULL,
	"OVALResultsTypeID" INTEGER NOT NULL,
	"signature" TEXT NULL
)

;
/****** Object:  Table "OVALRESULTSTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALRESULTSTYPE"(
	"OVALResultsTypeId" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALSET"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSET"(
	"OVALSetID" INTEGER NOT NULL,
	"SetOperatorValue" TEXT NULL
)

;
/****** Object:  Table "OVALSETFOROVALSET"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSETFOROVALSET"(
	"OVALSetRefID" INTEGER NOT NULL,
	"OVALSetSubjectID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALSTATE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATE"(
	"OVALStateID" INTEGER NOT NULL,
	"OVALStateIDPattern" TEXT NOT NULL,
	"OVALStateVersion" INTEGER NULL,
	"OVALStateSimpleBaseID" INTEGER NULL,
	"OVALStateComplexBaseID" INTEGER NULL,
	"OVALStateTypeID" INTEGER NULL,
	"DataTypeName" TEXT NULL,
	"OperatorEnumerationID" INTEGER NULL,
	"comment" TEXT NOT NULL,
	"deprecated" INTEGER NULL,
	"notes" TEXT NULL,
	"signature" TEXT NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATECOMPLEXBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATECOMPLEXBASE"(
	"OVALStateComplexBaseID" INTEGER NOT NULL,
	"CheckEnumerationID" INTEGER NULL,
	"EnumerationValue" TEXT NULL,
	"DataTypeName" TEXT NULL
)

;
/****** Object:  Table "OVALSTATEFIELD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATEFIELD"(
	"OVALStateFieldID" INTEGER NOT NULL,
	"OVALEntityAttributeGroupID" INTEGER NULL,
	"FieldName" TEXT NULL,
	"DataTypeName" TEXT NULL,
	"OperationEnumerationID" INTEGER NULL,
	"CheckEnumerationID" INTEGER NULL,
	"FieldValue" TEXT NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"OVALVariableID" INTEGER NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATEFIELDFOROVALSTATERECORD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATEFIELDFOROVALSTATERECORD"(
	"OVALStateRecordStateFieldID" INTEGER NOT NULL,
	"OVALStateRecordID" INTEGER NOT NULL,
	"OVALStateFieldID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATEFOROVALTEST"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATEFOROVALTEST"(
	"OVALTestStateID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NOT NULL,
	"OVALStateID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATERECORD"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATERECORD"(
	"OVALStateRecordID" INTEGER NOT NULL,
	"OVALStateComplexBaseID" INTEGER NULL,
	"OVALStateTypeID" INTEGER NULL,
	"DataTypeName" TEXT NOT NULL,
	"OperationEnumerationID" INTEGER NULL,
	"mask" INTEGER NULL,
	"OVALVariableID" INTEGER NULL,
	"CheckEnumerationID" INTEGER NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATERECORDFOROVALSTATE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATERECORDFOROVALSTATE"(
	"OVALStateStateRecordID" INTEGER NOT NULL,
	"OVALStateID" INTEGER NOT NULL,
	"OVALStateRecordID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSTATESIMPLEBASE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATESIMPLEBASE"(
	"OVALStateSimpleBaseID" INTEGER NOT NULL,
	"CheckEnumerationID" INTEGER NULL,
	"EnumerationValue" TEXT NULL,
	"EntityValue" TEXT NULL,
	"DataTypeName" TEXT NULL
)

;
/****** Object:  Table "OVALSTATETYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSTATETYPE"(
	"OVALStateTypeID" INTEGER NOT NULL,
	"OVALStateTypeName" TEXT NULL,
	"OVALStateTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSYSTEMCHARACTERISTICS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSYSTEMCHARACTERISTICS"(
	"OVALSystemCharacteristicsID" INTEGER NOT NULL,
	"GeneratorTypeID" INTEGER NOT NULL,
	"signature" TEXT NULL
)

;
/****** Object:  Table "OVALSYSTEMOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSYSTEMOBJECT"(
	"OVALSystemObjectID" INTEGER NOT NULL,
	"OVALObjectID" INTEGER NOT NULL,
	"OVALObjectIDPattern" TEXT NOT NULL,
	"OVALObjectVersion" INTEGER NOT NULL,
	"VariableInstance" INTEGER NULL,
	"comment" TEXT NULL,
	"FlagID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALSYSTEMTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSYSTEMTYPE"(
	"OVALSystemTypeID" INTEGER NOT NULL,
	"OVALSystemCharacteristicsID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALSYSTEMTYPEFOROVALRESULTSTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALSYSTEMTYPEFOROVALRESULTSTYPE"(
	"OVALResultsTypeID" INTEGER NOT NULL,
	"OVALSystemTypeID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTEST"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTEST"(
	"OVALTestID" INTEGER NOT NULL,
	"OVALTestIDPattern" TEXT NOT NULL,
	"OVALTestVersion" INTEGER NOT NULL,
	"ExistenceEnumerationID" INTEGER NULL,
	"CheckEnumerationID" INTEGER NULL,
	"OperatorEnumerationID" INTEGER NULL,
	"comment" TEXT NOT NULL,
	"deprecated" INTEGER NULL,
	"notes" TEXT NULL,
	"signature" TEXT NULL,
	"OVALTestDataTypeID" INTEGER NULL,
	"OVALNamespaceID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"RepositoryID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALTESTDATATYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTDATATYPE"(
	"OVALTestDataTypeID" INTEGER NOT NULL,
	"OVALTestDataTypeName" TEXT NULL,
	"OVALTestDataTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALTESTEDITEM"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTEDITEM"(
	"OVALTestedItemID" INTEGER NOT NULL,
	"OVALItemID" INTEGER NULL,
	"OVALItemIDPattern" TEXT NOT NULL,
	"ResultEnumerationID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTEDITEMFOROVALTESTTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTEDITEMFOROVALTESTTYPE"(
	"OVALTestTypeID" INTEGER NOT NULL,
	"OVALTestedItemID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTEDVARIABLE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTEDVARIABLE"(
	"OVALTestedVariableID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NULL,
	"OVALVariableIDPattern" TEXT NOT NULL,
	"OVALVariableValue" TEXT NOT NULL
)

;
/****** Object:  Table "OVALTESTEDVARIABLEFOROVALTESTTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTEDVARIABLEFOROVALTESTTYPE"(
	"OVALTestTypeID" INTEGER NOT NULL,
	"OVALTestedVariableId" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTFOROVALTESTS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTFOROVALTESTS"(
	"OVALTestsTestID" INTEGER NOT NULL,
	"OVALTestsID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTS"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTS"(
	"OVALTestsID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTTAG"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTTAG"(
	"OVALTestTagID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALTESTTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTTYPE"(
	"OVALTestTypeID" INTEGER NOT NULL,
	"OVALTestID" INTEGER NULL,
	"OVALTestIDPattern" TEXT NOT NULL,
	"OVALTestVersion" INTEGER NOT NULL,
	"variable_instance" INTEGER NULL,
	"ExistenceEnumerationID" INTEGER NULL,
	"ExistenceValue" TEXT NULL,
	"CheckEnumerationID" INTEGER NULL,
	"EnumerationValue" TEXT NOT NULL,
	"OperatorEnumerationID" INTEGER NULL,
	"OperatorValue" TEXT NULL,
	"ResultEnumerationID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALTESTTYPEFOROVALSYSTEMTYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALTESTTYPEFOROVALSYSTEMTYPE"(
	"OVALSystemTypeTestTypeID" INTEGER NOT NULL,
	"OVALSystemTypeID" INTEGER NOT NULL,
	"OVALTestTypeID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLE"(
	"OVALVariableID" INTEGER NOT NULL,
	"OVALVariableIDPattern" TEXT NOT NULL,
	"OVALVariableVersion" INTEGER NOT NULL,
	"OVALVariableDataTypeID" INTEGER NULL,
	"comment" TEXT NOT NULL,
	"deprecated" INTEGER NULL,
	"signature" TEXT NULL,
	"OVALNamespaceID" INTEGER NULL,
	"OVALVariableTypeID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLECOMPONENT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLECOMPONENT"(
	"OVALVariableComponentID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NOT NULL,
	"OVALItemFieldName" TEXT NULL,
	"OVALObjectRefID" INTEGER NULL,
	"OVALVariableRefID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLECOMPONENTFOROVALCOMPONENTGROUP"(
	"OVALComponentGroupVariableComponentID" INTEGER NOT NULL,
	"OVALComponentGroupID" INTEGER NOT NULL,
	"OVALVariableComponentID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;
/****** Object:  Table "OVALVARIABLEDATATYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLEDATATYPE"(
	"OVALVariableDataTypeID" INTEGER NOT NULL,
	"OVALVariableDataTypeName" TEXT NULL,
	"OVALVariableDataTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLEFOROVALVARIABLES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLEFOROVALVARIABLES"(
	"OVALVariablesID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NOT NULL
)

;
/****** Object:  Table "OVALVARIABLES"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLES"(
	"OVALVariablesID" INTEGER NOT NULL,
	"OVALGeneratorTypeID" INTEGER NOT NULL,
	"signature" TEXT NULL
)

;
/****** Object:  Table "OVALVARIABLETAG"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLETAG"(
	"OVALVariableTagID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NULL,
	"TagID" INTEGER NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLETYPE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLETYPE"(
	"OVALVariableTypeID" INTEGER NOT NULL,
	"OVALVariableTypeName" TEXT NULL,
	"OVALVariableTypeDescription" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLEVALUE"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLEVALUE"(
	"OVALVariableValueID" INTEGER NOT NULL,
	"OVALVariableID" INTEGER NOT NULL,
	"OVALVariableGUID" TEXT NULL,
	"ValueID" INTEGER NOT NULL,
	"ValueValue" TEXT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL,
	"isEncrypted" INTEGER NULL,
	"VocabularyID" INTEGER NULL
)

;
/****** Object:  Table "OVALVARIABLEVALUEFOROVALSYSTEMOBJECT"    Script Date: 04/03/2015 19:56:31 ******/

;

;
CREATE TABLE "OVALVARIABLEVALUEFOROVALSYSTEMOBJECT"(
	"OVALSystemObjectVariableValueID" INTEGER NOT NULL,
	"OVALSystemObjectID" INTEGER NOT NULL,
	"OVALVariableValueID" INTEGER NOT NULL,
	"CreatedDate" TEXT NULL,
	BLOB TEXT NULL,
	"VocabularyID" INTEGER NULL,
	"isEncrypted" INTEGER NULL,
	"ValidFromDate" TEXT NULL,
	"ValidUntilDate" TEXT NULL
)

;

COMMIT;

-- ============================================================================
-- Schema sync — runtime tables/columns/indexes created by the server's ensure*
-- functions, appended to keep this canonical script in step with the live schema.
-- Generated 2026-06-29. Additive; safe to re-run the script.
-- ============================================================================
-- New tables (3)
CREATE TABLE IF NOT EXISTS CISBENCHMARK ( BenchmarkID INTEGER PRIMARY KEY, BenchmarkGUID TEXT, Name TEXT, Version TEXT, Platform TEXT, Category TEXT, Source TEXT, ExternalID TEXT, RecommendationCount INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS CISBENCHMARKRECOMMENDATION ( RecommendationID INTEGER PRIMARY KEY, RecommendationGUID TEXT, BenchmarkID INTEGER, Number TEXT, Title TEXT, Level TEXT, Section TEXT, Description TEXT, Remediation TEXT, AssessmentType TEXT, ExternalID TEXT, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS CISBENCHMARKRESULT ( ResultID INTEGER PRIMARY KEY, ResultGUID TEXT, BenchmarkID INTEGER, RecommendationID INTEGER, RecommendationNumber TEXT, AssetID INTEGER, Result TEXT, Severity TEXT, CheckedAt TEXT, Source TEXT, ExternalID TEXT, CreatedDate TEXT, TenantID INTEGER);
-- New columns (12)
ALTER TABLE "OVALDEFINITION" ADD COLUMN "BlobSha256" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "AssetID" INTEGER;
ALTER TABLE "OVALRESULTS" ADD COLUMN "OVALDefinitionID" INTEGER;
ALTER TABLE "OVALRESULTS" ADD COLUMN "OVALDefinitionIDPattern" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "ResultValue" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "ClassValue" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "Title" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "Severity" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "ScanDate" DATE;
ALTER TABLE "OVALRESULTS" ADD COLUMN "AgentName" TEXT;
ALTER TABLE "OVALRESULTS" ADD COLUMN "TenantID" INTEGER;
ALTER TABLE "OVALRESULTSTYPE" ADD COLUMN "ResultValue" TEXT;
-- New indexes (7)
CREATE INDEX IF NOT EXISTS "ix_OVALRESULTS_tenant" ON "OVALRESULTS" ("TenantID");
CREATE INDEX IF NOT EXISTS ix_cisrec_benchmark ON CISBENCHMARKRECOMMENDATION(BenchmarkID);
CREATE INDEX IF NOT EXISTS ix_cisres_asset ON CISBENCHMARKRESULT(AssetID);
CREATE INDEX IF NOT EXISTS ix_cisres_benchmark ON CISBENCHMARKRESULT(BenchmarkID);
CREATE INDEX IF NOT EXISTS ix_ovalresults_asset ON "OVALRESULTS"("AssetID");
CREATE INDEX IF NOT EXISTS ix_ovalresults_class ON "OVALRESULTS"("ClassValue");
CREATE INDEX IF NOT EXISTS ix_ovalresults_scan ON "OVALRESULTS"("ScanDate");
