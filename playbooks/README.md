# XORCISM SOC Incident-Response Playbooks

42 incident-response playbooks exported as PDF (PICERL lifecycle: Preparation -> Detection & Analysis -> Containment -> Eradication -> Recovery -> Lessons Learned). 36 are adapted from the community SOC IR Playbook library (github.com/okanyildiz/cybersecurity-notes); 6 are XORCISM's built-in NIST SP 800-61 playbooks. Each carries the incident classification, MITRE ATT&CK mappings, tooling and success-metric SLA targets where available.

| # | Playbook | Category | Severity | PDF |
|---|---|---|---|---|
| 1 | Ransomware Infection response | Ransomware | High | [01_ransomware_infection_response.pdf](01_ransomware_infection_response.pdf) |
| 2 | Insider Data Exfiltration response | Data Exfiltration | High | [02_insider_data_exfiltration_response.pdf](02_insider_data_exfiltration_response.pdf) |
| 3 | Cloud Account Compromise response | Cloud | High | [03_cloud_account_compromise_response.pdf](03_cloud_account_compromise_response.pdf) |
| 4 | Web Application Exploitation response | Web / API | Critical | [04_web_application_exploitation_response.pdf](04_web_application_exploitation_response.pdf) |
| 5 | Supply Chain Attack response | Supply Chain / DevSecOps | Critical | [05_supply_chain_attack_response.pdf](05_supply_chain_attack_response.pdf) |
| 6 | Malware via USB Device response | Malware | High | [06_malware_via_usb_device_response.pdf](06_malware_via_usb_device_response.pdf) |
| 7 | DDoS Attack response | Availability | Critical | [07_ddos_attack_response.pdf](07_ddos_attack_response.pdf) |
| 8 | Business Email Compromise (BEC) response | Email / BEC | Critical | [08_business_email_compromise_bec_response.pdf](08_business_email_compromise_bec_response.pdf) |
| 9 | Unauthorised Privilege Escalation response | Intrusion | Critical | [09_unauthorised_privilege_escalation_response.pdf](09_unauthorised_privilege_escalation_response.pdf) |
| 10 | Cloud Storage Misconfiguration Exposure response | Cloud | Critical | [10_cloud_storage_misconfiguration_exposure_response.pdf](10_cloud_storage_misconfiguration_exposure_response.pdf) |
| 11 | Credential Stuffing Attack response | Intrusion | High | [11_credential_stuffing_attack_response.pdf](11_credential_stuffing_attack_response.pdf) |
| 12 | Unauthorised Internal Database Access response | Intrusion | High | [12_unauthorised_internal_database_access_response.pdf](12_unauthorised_internal_database_access_response.pdf) |
| 13 | Shadow IT Asset Discovery response | Shadow IT | High | [13_shadow_it_asset_discovery_response.pdf](13_shadow_it_asset_discovery_response.pdf) |
| 14 | RDP Brute-Force Attack response | Intrusion | High | [14_rdp_brute_force_attack_response.pdf](14_rdp_brute_force_attack_response.pdf) |
| 15 | Unauthorised Access to Development Environments response | Intrusion | High | [15_unauthorised_access_to_development_environments_.pdf](15_unauthorised_access_to_development_environments_.pdf) |
| 16 | Abuse of OAuth Integrations response | Identity / SaaS | Critical | [16_abuse_of_oauth_integrations_response.pdf](16_abuse_of_oauth_integrations_response.pdf) |
| 17 | Data Exfiltration via DNS Tunnelling response | Data Exfiltration | Critical | [17_data_exfiltration_via_dns_tunnelling_response.pdf](17_data_exfiltration_via_dns_tunnelling_response.pdf) |
| 18 | Unauthorised JavaScript Injection on Public Websites response | Web / API | Critical | [18_unauthorised_javascript_injection_on_public_webs.pdf](18_unauthorised_javascript_injection_on_public_webs.pdf) |
| 19 | Insecure API Endpoint Exploitation response | Web / API | Critical | [19_insecure_api_endpoint_exploitation_response.pdf](19_insecure_api_endpoint_exploitation_response.pdf) |
| 20 | Insider Credential Theft and Misuse response | Insider Threat | Critical | [20_insider_credential_theft_and_misuse_response.pdf](20_insider_credential_theft_and_misuse_response.pdf) |
| 21 | Cloud Identity Misconfiguration response | Cloud | Critical | [21_cloud_identity_misconfiguration_response.pdf](21_cloud_identity_misconfiguration_response.pdf) |
| 22 | CI/CD Pipeline Exploitation response | Supply Chain / DevSecOps | Critical | [22_ci_cd_pipeline_exploitation_response.pdf](22_ci_cd_pipeline_exploitation_response.pdf) |
| 23 | Unauthorised Use of Generative AI Tools in Production response | AI Security | Critical | [23_unauthorised_use_of_generative_ai_tools_in_produ.pdf](23_unauthorised_use_of_generative_ai_tools_in_produ.pdf) |
| 24 | OAuth Token Replay Abuse response | Identity / SaaS | Critical | [24_oauth_token_replay_abuse_response.pdf](24_oauth_token_replay_abuse_response.pdf) |
| 25 | Misconfigured Public Cloud Storage Access response | Cloud | Critical | [25_misconfigured_public_cloud_storage_access_respon.pdf](25_misconfigured_public_cloud_storage_access_respon.pdf) |
| 26 | Lateral Movement Across Cloud Workloads response | Cloud | Critical | [26_lateral_movement_across_cloud_workloads_response.pdf](26_lateral_movement_across_cloud_workloads_response.pdf) |
| 27 | Unauthorised Cloud Database Snapshot Exports response | Intrusion | Critical | [27_unauthorised_cloud_database_snapshot_exports_res.pdf](27_unauthorised_cloud_database_snapshot_exports_res.pdf) |
| 28 | Container Breakout Attempt response | Cloud | Critical | [28_container_breakout_attempt_response.pdf](28_container_breakout_attempt_response.pdf) |
| 29 | Shadow IT SaaS Usage & Data Exposure response | Identity / SaaS | High | [29_shadow_it_saas_usage_data_exposure_response.pdf](29_shadow_it_saas_usage_data_exposure_response.pdf) |
| 30 | API Key Leakage via Public GitHub Repositories response | Supply Chain / DevSecOps | Critical | [30_api_key_leakage_via_public_github_repositories_r.pdf](30_api_key_leakage_via_public_github_repositories_r.pdf) |
| 31 | Unauthorised Access to CI/CD Secrets response | Supply Chain / DevSecOps | Critical | [31_unauthorised_access_to_ci_cd_secrets_response.pdf](31_unauthorised_access_to_ci_cd_secrets_response.pdf) |
| 32 | Zero-Day Exploitation in Third-Party Libraries response | Supply Chain / DevSecOps | Critical | [32_zero_day_exploitation_in_third_party_libraries_r.pdf](32_zero_day_exploitation_in_third_party_libraries_r.pdf) |
| 33 | Abuse of Stolen Session Tokens in SaaS Platforms response | Identity / SaaS | Critical | [33_abuse_of_stolen_session_tokens_in_saas_platforms.pdf](33_abuse_of_stolen_session_tokens_in_saas_platforms.pdf) |
| 34 | Cloud-Native Ransomware in Object Storage response | Ransomware | Critical | [34_cloud_native_ransomware_in_object_storage_respon.pdf](34_cloud_native_ransomware_in_object_storage_respon.pdf) |
| 35 | Malicious Insider Staging Data in the Cloud response | Cloud | Critical | [35_malicious_insider_staging_data_in_the_cloud_resp.pdf](35_malicious_insider_staging_data_in_the_cloud_resp.pdf) |
| 36 | Unauthorised SaaS OAuth Application Integration response | Identity / SaaS | High | [36_unauthorised_saas_oauth_application_integration_.pdf](36_unauthorised_saas_oauth_application_integration_.pdf) |
| 37 | Phishing / credential-harvesting response | Phishing | Medium | [37_phishing_credential_harvesting_response.pdf](37_phishing_credential_harvesting_response.pdf) |
| 38 | Endpoint malware infection response | Malware | High | [38_endpoint_malware_infection_response.pdf](38_endpoint_malware_infection_response.pdf) |
| 39 | Ransomware outbreak response | Ransomware | Critical | [39_ransomware_outbreak_response.pdf](39_ransomware_outbreak_response.pdf) |
| 40 | BEC / invoice-fraud response | Business Email Compromise | High | [40_bec_invoice_fraud_response.pdf](40_bec_invoice_fraud_response.pdf) |
| 41 | Cloud/identity account takeover response | Account Compromise | High | [41_cloud_identity_account_takeover_response.pdf](41_cloud_identity_account_takeover_response.pdf) |
| 42 | Data exfiltration response | Data Exfiltration | High | [42_data_exfiltration_response.pdf](42_data_exfiltration_response.pdf) |
