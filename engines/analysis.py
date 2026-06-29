from models.enums import RiskLevel, AssetType

class AnalysisEngine:
    def __init__(self, inventory, findings, coverage):
        self.inventory = inventory
        self.findings = findings
        self.coverage = coverage

    def calculate_exposure_score(self) -> int:
        score = 100
        for f in self.findings:
            if f.risk == RiskLevel.CRITICAL: score -= 30
            elif f.risk == RiskLevel.HIGH: score -= 15
            elif f.risk == RiskLevel.MEDIUM: score -= 10
            elif f.risk == RiskLevel.LOW: score -= 5
        return max(0, score)

    def get_intelligence_summary(self) -> dict:
        if not self.findings:
            return {
                "exposure_score": 100, "highest_risk": "NONE", "most_interesting": "N/A",
                "biggest_weakness": "None identified", "historical_risk": "UNKNOWN",
                "credential_risk": "UNKNOWN", "cloud_risk": "UNKNOWN",
                "recommendation": "No critical findings. Routine monitoring recommended."
            }

        score = self.calculate_exposure_score()
        risks = [f.risk.value.upper() for f in self.findings]
        highest = "CRITICAL" if "CRITICAL" in risks else "HIGH" if "HIGH" in risks else "MEDIUM"
        
        asset_counts = {}
        for f in self.findings:
            asset_counts[f.asset] = asset_counts.get(f.asset, 0) + 1
        most_interesting = max(asset_counts, key=asset_counts.get)
        biggest_weakness = next((f.title for f in self.findings if f.asset == most_interesting), "Unknown")
        
        hist_risk, cred_risk, cloud_risk = "LOW", "NONE", "LOW"
        for f in self.findings:
            if "github" in f.title.lower() and "secret" in f.title.lower(): cred_risk = "HIGH"
            if "cloud" in f.title.lower() or "bucket" in f.title.lower(): cloud_risk = "HIGH"
            if "wayback" in f.title.lower() or "historical" in f.title.lower(): hist_risk = "HIGH"

        return {
            "exposure_score": score, "highest_risk": highest, "most_interesting": most_interesting,
            "biggest_weakness": biggest_weakness, "historical_risk": hist_risk,
            "credential_risk": cred_risk, "cloud_risk": cloud_risk,
            "recommendation": "Manual validation recommended for high-risk assets." if score < 80 else "Routine monitoring. No immediate action required."
        }

    def generate_attack_paths(self) -> list[dict]:
        paths = []
        for f in self.findings:
            if "Subdomain Takeover" in f.title:
                paths.append({
                    "name": "Subdomain Takeover to Phishing",
                    "steps": ["Internet", "DNS Misconfiguration", "GitHub Pages", "Subdomain Takeover", "Session Cookie Theft", "Account Phishing"],
                    "confidence": f.confidence
                })
            elif "Secrets" in f.title:
                paths.append({
                    "name": "Credential Leak to Cloud Takeover",
                    "steps": ["GitHub Search", "Exposed API Key", "Cloud Provider Authentication", "Full Account Takeover"],
                    "confidence": f.confidence
                })
            elif "Cloud" in f.title or "Bucket" in f.title:
                paths.append({
                    "name": "Exposed Storage to Data Breach",
                    "steps": ["DNS Enumeration", "Open S3 Bucket", "Sensitive File Download", "Data Breach"],
                    "confidence": f.confidence
                })
        return paths

    def generate_investigation_queue(self) -> list[dict]:
        queue = []
        priority = 1
        sorted_findings = sorted(self.findings, key=lambda x: ["critical", "high", "medium", "low"].index(x.risk.value))
        
        for f in sorted_findings:
            if "Subdomain Takeover" in f.title:
                queue.append({"priority": priority, "action": f"Validate GitHub Pages takeover for {f.asset}."})
            elif "Secrets" in f.title:
                queue.append({"priority": priority, "action": "Revoke exposed credentials and audit Git history."})
            elif "Cloud" in f.title or "Bucket" in f.title:
                queue.append({"priority": priority, "action": f"Verify S3 bucket permissions for {f.asset}."})
            elif "Email" in f.title or "SPF" in f.title or "DMARC" in f.title:
                queue.append({"priority": priority, "action": "Review email spoofing configurations (SPF/DMARC)."})
            else:
                queue.append({"priority": priority, "action": f"Investigate {f.title} on {f.asset}."})
            priority += 1
            
        if not queue:
            queue.append({"priority": 1, "action": "No critical findings. Review historical Wayback endpoints."})
            
        return queue

    def generate_ai_assessment(self) -> str:
        domains = [a for a in self.inventory.get_all() if a.type == AssetType.DOMAIN]
        score = self.calculate_exposure_score()
        summary_data = self.get_intelligence_summary()
        
        summary = f"This organization exposes a {'relatively small' if len(domains) < 15 else 'significant'} public attack surface consisting of {len(domains)} internet-facing domains. "
        
        if self.findings:
            high_risk_count = sum(1 for f in self.findings if f.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL])
            summary += f"Intelligence analysis identified {high_risk_count} high-severity exposure(s), primarily involving {summary_data['biggest_weakness'].lower()}. "
        else:
            summary += "No critical exposures or misconfigurations were identified during this scan. "
            
        if not self.coverage.get("wayback", True):
            summary += "Historical data could not be fully retrieved because the Wayback service was unavailable during the scan. "
            
        summary += f"Based on the collected evidence, the overall exposure score is {score}/100. Manual validation should focus on the identified high-risk assets before investigating lower-priority surface areas."
        return summary
