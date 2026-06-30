/**
 * aiSbomElements.ts — the CISA / G7 "Software Bill of Materials for AI — Minimum Elements"
 * (BSI/ACN/ANSSI/CSE/CISA/NCSC/NCO + EU Commission, May 2026): 7 clusters, 50 supplemental
 * minimum elements that an SBOM for AI should include *in addition to* the regular NTIA SBOM
 * minimum elements. Official cluster + element names; concise original summaries (the guidance
 * is public-sector consensus guidance, not mandatory). Used by the AI-SBOM conformance checklist.
 */
export interface AiSbomElementSeed { cluster: string; clusterName: string; element: string; description: string; example: string; }

export const AI_SBOM_CLUSTERS: { code: string; name: string }[] = [
  { code: "META", name: "Metadata" },
  { code: "SLP", name: "System Level Properties" },
  { code: "MODEL", name: "Models" },
  { code: "DATA", name: "Datasets" },
  { code: "INFRA", name: "Infrastructure" },
  { code: "SEC", name: "Security Properties" },
  { code: "KPI", name: "Key Performance Indicators" },
];

export const AI_SBOM_ELEMENTS: AiSbomElementSeed[] = [
  // — Metadata (about the SBOM-for-AI itself) —
  { cluster: "META", clusterName: "Metadata", element: "SBOM author", description: "The entity that created the SBOM-for-AI data (the operator, not the tool).", example: "Full legal name of the organization" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM version", description: "Version identifier of the SBOM document (e.g. SemVer; major 1 for these minimum elements).", example: "1.2.0 / serial number (RFC 9562)" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM data format name", description: "Name of the machine-processable data format the SBOM is expressed in.", example: "CycloneDX, SPDX" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM data format version", description: "Version of that data format (do not use deprecated versions).", example: "CycloneDX 1.6" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM author signature", description: "Digital signature by the SBOM author, using an approved algorithm (NIST DSS / ISO-IEC 14888-4 / ENISA).", example: "Detached signature over the SBOM" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM tool name", description: "The tool used by the author to generate or amend the SBOM.", example: "Tool full name" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM tool version", description: "Version of that generation tool (mark unknown if unavailable).", example: "" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM generation context", description: "Lifecycle phase / data available when the SBOM was generated.", example: "before build, build, after build" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM timestamp", description: "Date/time of the most recent update to the SBOM data (RFC 9557).", example: "" },
  { cluster: "META", clusterName: "Metadata", element: "SBOM dependency relationship", description: "Inclusion / derivation relationships between components, to build a dependency graph.", example: "X includes Y; A derived from B" },

  // — System Level Properties —
  { cluster: "SLP", clusterName: "System Level Properties", element: "System name", description: "Human-readable name of the AI system (allow alternate names).", example: "" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System components", description: "The components that make up the AI system.", example: "AI models, databases, other software tools" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System producer", description: "Entity that creates, defines and identifies the AI system.", example: "" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System version", description: "Version of the AI system (mark unknown if not provided).", example: "" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System timestamp", description: "Date/time of the most recent update to the system (model or software).", example: "" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System data flow", description: "Data flow between components: endpoints, external service APIs, multi-agent protocols, web grounding.", example: "source → destination" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System data usage", description: "How data in the system is processed and consumed (training reuse, API logging, derived metadata).", example: "Link to technical documentation" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "System input/output properties", description: "I/O data types, modality (text/audio/image/video), input preprocessing.", example: "Tokenizer type for LLMs" },
  { cluster: "SLP", clusterName: "System Level Properties", element: "Intended application area", description: "The type of application the AI system is deployed in.", example: "real-time; cybersecurity, healthcare, finance" },

  // — Models —
  { cluster: "MODEL", clusterName: "Models", element: "Model name", description: "Human-readable model name (allow alternate names).", example: "" },
  { cluster: "MODEL", clusterName: "Models", element: "Model identifier", description: "Machine-processable software identifier(s) for the model.", example: "CPE, PURL, UUID, commit hash, SWHID, OmniBOR" },
  { cluster: "MODEL", clusterName: "Models", element: "Model version", description: "Version of the model (mark unknown if not provided).", example: "" },
  { cluster: "MODEL", clusterName: "Models", element: "Model timestamp", description: "Date/time of last model update, or production release date.", example: "" },
  { cluster: "MODEL", clusterName: "Models", element: "Model producer", description: "Entity that pre-trained / post-trained / fine-tuned the model.", example: "" },
  { cluster: "MODEL", clusterName: "Models", element: "Model description", description: "Capabilities, known weaknesses/limitations, lineage (predecessor/derivative models) and dependencies.", example: "Distillation/finetuning source" },
  { cluster: "MODEL", clusterName: "Models", element: "Model hash value", description: "Cryptographic hash of the weights / model file / related artifacts.", example: "" },
  { cluster: "MODEL", clusterName: "Models", element: "Model hash algorithm", description: "Hash algorithm used (IANA textual name; NIST-approved).", example: "SHA-256" },
  { cluster: "MODEL", clusterName: "Models", element: "Model properties", description: "Architecture/type, parameter count/size, hyper-parameters.", example: "transformer, encoder-decoder; 7B params" },
  { cluster: "MODEL", clusterName: "Models", element: "Model input-output properties", description: "Model I/O data types, context length, modality, input preprocessing.", example: "context length; tokenizer" },
  { cluster: "MODEL", clusterName: "Models", element: "Model training properties", description: "Training techniques used (pre-/post-training, fine-tuning, RLHF, DPO/PPO/GRPO).", example: "Link to model card" },
  { cluster: "MODEL", clusterName: "Models", element: "Model license", description: "License type; whether open weight / open architecture / open data / open training.", example: "Apache-2.0; link to license" },
  { cluster: "MODEL", clusterName: "Models", element: "Model external references", description: "Links to model/system cards, public documentation, research papers.", example: "Model card JSON; paper URL" },

  // — Datasets —
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset name", description: "Public name of the dataset.", example: "" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset description", description: "Intended use w.r.t. training (pre-training, fine-tuning, benchmark, evaluation); private/public.", example: "" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset content", description: "Content type, structure/encoding, and data format.", example: "financial/medical; JSON/XML; image/audio/video" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset identifier", description: "Identifier that uniquely identifies the dataset.", example: "Dataset URL/URI" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset hash", description: "Cryptographic hash over the dataset.", example: "" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset provenance", description: "Origin, collection methods, curation/labelling steps, creator; synthetic-data methods.", example: "web crawl, commercial agreement" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset statistical properties", description: "Statistical characteristics of the dataset across its lifecycle.", example: "mean, variance, median, range, skewness" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset sensitivity", description: "Sensitivity level of the data it contains.", example: "PII, copyright, financial/medical, national security" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset dependency relationship", description: "Software used to create/modify/maintain it; derivation from other datasets.", example: "labeling/filtering tools" },
  { cluster: "DATA", clusterName: "Datasets", element: "Dataset license", description: "License type of the dataset.", example: "Link to dataset licensing document" },

  // — Infrastructure —
  { cluster: "INFRA", clusterName: "Infrastructure", element: "Infrastructure software", description: "Software dependencies required to deliver and run the AI system.", example: "firmware, package managers, libraries, frameworks, runtimes" },
  { cluster: "INFRA", clusterName: "Infrastructure", element: "Infrastructure hardware", description: "Link to a Hardware BOM (HBOM) for the deployment hardware, incl. AI accelerators.", example: "Link to HBOM" },

  // — Security Properties —
  { cluster: "SEC", clusterName: "Security Properties", element: "Security controls", description: "Implemented general + AI-specific cybersecurity controls (optionally a framework reference).", example: "encryption, access control; adversarial-robustness training, prompt-injection filters" },
  { cluster: "SEC", clusterName: "Security Properties", element: "Security compliance", description: "Cybersecurity standards/certifications the model/system is compliant with.", example: "certification schemes, standards" },
  { cluster: "SEC", clusterName: "Security Properties", element: "Cybersecurity policy information", description: "Link to the producer's published security.txt.", example: "" },
  { cluster: "SEC", clusterName: "Security Properties", element: "Vulnerability referencing", description: "Link to databases of known vulnerabilities / exploitability for the model/system.", example: "Security repository URL" },

  // — Key Performance Indicators —
  { cluster: "KPI", clusterName: "Key Performance Indicators", element: "Security metrics", description: "Metrics evaluating the security characteristics of the models / the system.", example: "robustness against third-party manipulation" },
  { cluster: "KPI", clusterName: "Key Performance Indicators", element: "Operational performance KPIs", description: "Operational-condition / threat-indicator KPIs of the AI system.", example: "uptime, incident resolution time, latency, throughput" },
];
