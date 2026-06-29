from models.finding import Finding
from models.enums import RiskLevel
from models.asset import Asset

class CorrelationEngine:
    def analyze(self, assets: list[Asset]) -> list[Finding]:
        findings = []
        
        for asset in assets:
            for ev in asset.evidence:
                # --- Web Intelligence (Subdomain Takeover) ---
                if ev.source.startswith("http_"):
                    data = ev.raw_data
                    server = data.get("server", "").lower()
                    title = data.get("title", "").lower()
                    status = ev.source.split("_")[1]
                    
                    if "github.com" in server or "github pages" in title:
                        if status == "404" or "not found" in title:
                            findings.append(Finding(
                                title="Potential GitHub Pages Subdomain Takeover",
                                description="The DNS configuration references GitHub Pages, but the corresponding GitHub Pages site does not appear to exist.",
                                risk=RiskLevel.HIGH,
                                asset=asset.value,
                                confidence=92,
                                impact=["Phishing", "Cookie theft", "Brand impersonation", "Same-Origin Policy abuse"],
                                recommendation=["Remove unused DNS records.", "Verify ownership of the GitHub Pages project.", "Recreate the project if the subdomain is still required."],
                                evidence=[ev]
                            ))
                            
                # --- Identity Intelligence (Email Spoofing) ---
                elif ev.source == "spf_record":
                    record = ev.raw_data.get("record", "")
                    if "+all" in record or "~all" not in record and "-all" not in record:
                        findings.append(Finding(
                            title="Weak SPF Configuration (Allows Spoofing)",
                            description="The SPF record is configured to allow all servers to send email on behalf of this domain, or lacks a strict '-all' mechanism.",
                            risk=RiskLevel.MEDIUM,
                            asset=asset.value,
                            confidence=95,
                            impact=["Email spoofing", "Phishing campaigns", "Domain reputation damage"],
                            recommendation=["Update SPF record to include only authorized mail servers.", "End the SPF record with '-all' to reject unauthorized senders."],
                            evidence=[ev]
                        ))
                        
                elif ev.source == "dmarc_record":
                    record = ev.raw_data.get("record", "")
                    if "p=none" in record:
                        findings.append(Finding(
                            title="DMARC Policy Set to 'None' (Monitoring Only)",
                            description="The DMARC policy is set to 'none', meaning the domain is only monitoring email failures but not actively blocking spoofed emails.",
                            risk=RiskLevel.MEDIUM,
                            asset=asset.value,
                            confidence=100,
                            impact=["Successful phishing attacks", "Brand impersonation"],
                            recommendation=["Transition DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' after verifying legitimate mail flow."],
                            evidence=[ev]
                        ))
                        
                # --- Cloud Intelligence (Exposed Buckets) ---
                elif ev.source == "cloud_bucket":
                    bucket = ev.raw_data.get("bucket", "")
                    provider = ev.raw_data.get("provider", "Cloud")
                    findings.append(Finding(
                        title=f"Exposed {provider} Storage Bucket",
                        description=f"The DNS record for {bucket} resolves, indicating the cloud storage bucket exists and may be publicly accessible.",
                        risk=RiskLevel.HIGH,
                        asset=asset.value,
                        confidence=90,
                        impact=["Data leakage", "Sensitive file exposure", "Ransomware target"],
                        recommendation=["Verify the bucket's access policies immediately.", "Ensure public access is blocked unless explicitly required.", "Enable bucket logging and versioning."],
                        evidence=[ev]
                    ))
                    
                # --- Git Intelligence (Leaked Secrets) ---
                elif ev.source == "github_secrets":
                    files = ev.raw_data.get("leaked_files", [])
                    file_list = ", ".join([f['file'] for f in files])
                    findings.append(Finding(
                        title="Potential Secrets Leaked on GitHub",
                        description=f"GitHub code search found references to sensitive keywords (passwords, API keys) associated with this domain in public repositories.",
                        risk=RiskLevel.CRITICAL,
                        asset=asset.value,
                        confidence=85,
                        impact=["Unauthorized access", "Cloud account takeover", "Data breach"],
                        recommendation=["Revoke and rotate all exposed credentials immediately.", "Remove the sensitive data from the Git history.", "Implement pre-commit hooks to prevent future leaks."],
                        evidence=[ev]
                    ))
                    
        return findings
