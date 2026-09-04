# Sample corpus

Twenty hand-crafted `.eml` files used as fixtures for the deterministic
forensics engine and, later, for demoing the platform. All senders,
recipients, domains, IPs, and content are entirely fabricated for testing
purposes (`.test` TLDs, RFC 5737/1918 example address ranges) — none of it
reflects a real person, organization, or live threat infrastructure.

| # | File | Scenario |
|---|------|----------|
| 01 | `01_clean_newsletter.eml` | Clean mail — SPF/DKIM/DMARC all pass |
| 02 | `02_clean_internal_memo.eml` | Clean mail — internal corporate relay |
| 03 | `03_spf_fail_spoofed_bank.eml` | SPF fail — spoofed bank sender |
| 04 | `04_spf_softfail_marketing.eml` | SPF softfail (`~all`) — legit marketing sender |
| 05 | `05_dkim_fail_invoice_scam.eml` | DKIM fail — tampered body hash, invoice scam |
| 06 | `06_dkim_missing_signature.eml` | DKIM missing entirely despite DMARC reject policy |
| 07 | `07_display_name_spoof_ceo_fraud.eml` | Display-name spoof — CEO fraud / gift card scam |
| 08 | `08_display_name_spoof_it_support.eml` | Display-name spoof — fake IT help desk |
| 09 | `09_homoglyph_domain_paypal.eml` | Homoglyph domain — `paypaI.com` (capital I for l) |
| 10 | `10_homoglyph_domain_microsoft.eml` | Lookalike domain — `micr0soft-online.com` (digit for letter) |
| 11 | `11_long_relay_chain_9hops.eml` | Long relay chain — 9 hops, legitimate multi-region infra |
| 12 | `12_relay_chain_timezone_drift.eml` | Relay chain anomaly — negative time delta between hops |
| 13 | `13_forged_received_header_injected.eml` | Forged Received headers claiming false internal origin |
| 14 | `14_forged_received_header_private_ip_public_path.eml` | Private/bogon IPs (`127.0.0.1`, `192.168.1.50`) in public relay path |
| 15 | `15_base64_payload_hidden_script.eml` | Base64-encoded HTML part hiding an inline `<script>` |
| 16 | `16_base64_payload_exe_attachment.eml` | Base64 attachment with double extension (`.pdf.exe`) |
| 17 | `17_html_redirect_chain_phishing.eml` | Anchor-text/href mismatch + base64-encoded redirect target |
| 18 | `18_html_redirect_chain_shortener.eml` | URL shortener + IP-literal URL in one body |
| 19 | `19_expired_dkim_signature.eml` | DKIM signature present but expired (`x=` in the past) |
| 20 | `20_dmarc_fail_reject_policy.eml` | Full SPF+DKIM+DMARC failure against a `p=reject` policy |

Sample 16's attachment payload is fabricated placeholder text, not a
functional executable of any kind — it exists only to exercise
double-extension and `application/octet-stream` attachment detection.
