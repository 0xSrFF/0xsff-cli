from models.finding import Finding

class ReasoningEngine:
    def analyze(self, findings: list[Finding]) -> list[dict]:
        assessments = []
        for finding in findings:
            assessments.append({
                "finding": finding,
                "narrative": self._generate_narrative(finding)
            })
        return assessments

    def _generate_narrative(self, finding: Finding) -> str:
        if "Subdomain Takeover" in finding.title:
            return (
                f"The DNS configuration references a third-party service, but the corresponding "
                f"resource does not appear to exist. If the namespace is available for registration, "
                f"an attacker may be able to claim the resource and serve arbitrary content from the affected subdomain."
            )
        return finding.description
