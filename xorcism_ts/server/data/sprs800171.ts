/**
 * sprs800171.ts — the 110 NIST SP 800-171 Rev 2 security requirements (14 families) with their DoD
 * SPRS point weights (1 / 3 / 5), used to compute the SPRS / NIST 800-171 self-assessment score.
 *
 * Scoring (DoD Assessment Methodology): start at 110, subtract a requirement's weight for each NOT-MET
 * requirement (a POA&M item still counts as not-met until closed); partial implementation gives partial
 * credit; the score floor is −203. Weights here follow the DoD Assessment Methodology and are EDITABLE
 * per requirement (WeightOverride) so an org can align them to its authoritative copy of the methodology.
 */
export const SPRS_FAMILIES: { code: string; name: string; count: number }[] = [
  { code: "3.1", name: "Access Control", count: 22 },
  { code: "3.2", name: "Awareness and Training", count: 3 },
  { code: "3.3", name: "Audit and Accountability", count: 9 },
  { code: "3.4", name: "Configuration Management", count: 9 },
  { code: "3.5", name: "Identification and Authentication", count: 11 },
  { code: "3.6", name: "Incident Response", count: 3 },
  { code: "3.7", name: "Maintenance", count: 6 },
  { code: "3.8", name: "Media Protection", count: 9 },
  { code: "3.9", name: "Personnel Security", count: 2 },
  { code: "3.10", name: "Physical Protection", count: 6 },
  { code: "3.11", name: "Risk Assessment", count: 3 },
  { code: "3.12", name: "Security Assessment", count: 4 },
  { code: "3.13", name: "System and Communications Protection", count: 16 },
  { code: "3.14", name: "System and Information Integrity", count: 7 },
];

// DoD Assessment Methodology v1.2.1 weighting — the 5-point and 3-point requirements (all others = 1).
const W5 = new Set([
  "3.1.1", "3.1.2", "3.1.12", "3.1.13", "3.1.16", "3.1.17", "3.1.18", "3.1.20",
  "3.3.1", "3.4.1", "3.4.2", "3.4.5", "3.4.6", "3.4.7", "3.5.1", "3.5.2",
  "3.6.1", "3.6.2", "3.8.3", "3.13.1", "3.13.2", "3.13.5", "3.13.6", "3.13.15",
  "3.14.1", "3.14.2", "3.14.4", "3.14.5", "3.14.6", "3.14.7",
]);
const W3 = new Set([
  "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.11", "3.1.14", "3.1.15", "3.1.21", "3.1.22",
  "3.4.8", "3.4.9", "3.5.5", "3.5.6", "3.5.10", "3.7.1", "3.7.2", "3.7.5",
  "3.8.1", "3.8.2", "3.8.4", "3.8.5", "3.8.6", "3.8.7", "3.8.8", "3.8.9",
  "3.10.1", "3.10.2", "3.11.1", "3.13.8", "3.13.11", "3.13.16", "3.14.3",
]);

export interface SprsReq { id: string; family: string; familyName: string; weight: number; }

/** The 110 requirements (3.<family>.<n>) with their family + SPRS weight. */
export const SPRS_REQUIREMENTS: SprsReq[] = SPRS_FAMILIES.flatMap((f) =>
  Array.from({ length: f.count }, (_v, i) => {
    const id = `${f.code}.${i + 1}`;
    return { id, family: f.code, familyName: f.name, weight: W5.has(id) ? 5 : W3.has(id) ? 3 : 1 };
  }),
);

export const SPRS_MAX = 110; // all requirements met
// The DoD methodology's documented floor is −203; the module derives the actual floor from the live
// weights (110 − Σ weights) so the score is always internally consistent with whatever weights are set.
