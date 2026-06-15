// Shared TypeScript types for server and client

export interface DbRow {
  [key: string]: string | number | null;
}

export interface RowsResponse {
  total: number;
  rows: DbRow[];
}

export interface ExportResponse {
  rows: DbRow[];
  total: number;
  truncated: boolean;
  limit: number;
}

export interface ColumnInfo {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
}

// BIA types
export interface BiaAudit {
  BIAAuditID?: number;
  BIAAuditName: string;
  BIAAuditDescription?: string;
  BIAAuditScope?: string;
  BIAAuditDate?: string;
  BIAAuditStatus?: string;
  Auditor?: string;
  CreatedDate?: string;
  CreatedByPersonID?: number;
}

export interface BiaEntry {
  BIAEntryID?: number;
  BIAAuditID: number;
  AssetName?: string;
  AssetDescription?: string;
  AssetType?: string;
  CriticalityLevel?: string;
  OwnerName?: string;
  RiskDescription?: string;
  RiskLevel?: string;
  ImpactFinancial?: string;
  ImpactOperational?: string;
  ImpactLegal?: string;
  ImpactReputational?: string;
  MTD?: string;
  RTO?: string;
  RPO?: string;
  Notes?: string;
  CreatedDate?: string;
  ModifiedDate?: string;
}

export type SortDir = "asc" | "desc";

export interface ApiError {
  error: string;
}
