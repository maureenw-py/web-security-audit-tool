import json
from pathlib import Path
from textwrap import dedent

#Summary Report
def render_report(base_url, right_now):
    with open("audit_results.json") as f:
        results = json.load(f)

    with open("rules.json") as f2:
        RULES = json.load(f2)

    all_findings = [finding for category in results["findings"].values() for finding in category]

    high_risk_findings = [f for f in all_findings if f.get("severity") == "high"]

    medium_risk_findings = [f for f in all_findings if f.get("severity") == "medium"]

    informational_findings = [
    f for f in all_findings
    if (
        f.get("severity") == "low"
        or (
            f.get("issue") == "SSL certificate status"
            and f.get("result") == "valid_long"
        )
    )
]

    inconclusive_findings = [f for f in all_findings if f.get("status") == "inconclusive"]

    md = []
    num = 1

    
    #Title Section
    md.append("# Security Assessment Report\n")
    md.append(f"**Target**: {base_url}\n")
    md.append(f"**Assessment Date**: {right_now}\n")
    md.append("**Tool**: Custom Automated Web Security Scanner\n")
    md.append("**Analyst**: Maureen\n")
    md.append("\n---\n")

    #Executive Summary
    md.append(f"## {num}. Executive Summary\n")
    exec_summary(high_risk_findings, medium_risk_findings, inconclusive_findings, md, base_url)

    #Scope of Assessment
    num += 1
    md.append(f"## {num}. Scope of Assessment\n")
    md.append(load_text("scope.txt"))
    md.append("\n---\n")

    #Methodology
    num += 1
    md.append(f"## {num}. Methodology\n")
    md.append(load_text("methodology.txt"))
    md.append("\n---\n")
    
    #High Risk Findings
    if high_risk_findings:
        num += 1
        render_section(md, num, "High-Risk Findings", high_risk_findings, RULES)

    #Medium Risk Findings
    if medium_risk_findings:
        num += 1
        render_section(md, num, "Medium-Risk Findings", medium_risk_findings, RULES)

    #Low Risk Findings
    if informational_findings:
        num += 1
        render_section(md, num, "Informational Observations", informational_findings, RULES)

    #Inconclusive Checks
    if inconclusive_findings:
        num += 1
        render_section(md, num, "Inconclusive Checks", inconclusive_findings, RULES, found=False)

    #Limitations
    num += 1
    md.append(f"## {num}. Limitations\n")
    md.append(load_text("limitations.txt"))
    md.append("\n---\n")

    #Conclusion
    num += 1
    md.append(f"## {num}. Conclusion\n")
    md.append(load_text("conclusion.txt"))
    md.append("\n---\n")

    #Authorization and Disclaimer
    num += 1
    md.append(f"## {num}. Authorization and Disclaimer\n")
    md.append(load_text("disclaimer.txt"))

    return md


def render_section(md, section_num, title, findings, RULES, found=True):

    md.append(f"## {section_num}. {title}\n")
    item_num = 0

    for finding in findings:
        item_num += 1
        data = RULES.get(finding["issue"], {}) 
        result = finding.get("result")
        evidence_collected = format_evidence(finding.get("evidence"))


        if found:
            if result:
                content = data.get("found", {})
                rule = content.get(result, {})
            else:
                rule = data.get("found", {})
        else:
            rule = data.get("inconclusive", {})

        evidence_explained = rule.get("evidence")

        md.append(dedent(f"""### {section_num}.{item_num} {finding["issue"]}

- **Category:** {finding["category"]}
- **Severity:** {finding["severity"]}
- **Status:** {finding["status"]}
- **Confidence:** {finding["confidence"]}
- **Check Type:** {finding["check_type"]}

**Description**  
{rule.get("description", "No description available.")}
            """))

        if found:
            if result:
                md.append(dedent(f"""
**Evidence**  
Data collected:
                                 
{evidence_collected}

**Impact**  
{rule.get("impact", "No impact information available.")}

                """))
            else:
                md.append(dedent(f"""
**Evidence**  
{evidence_explained}
Data collected:

{evidence_collected}
                
**Impact**  
{rule.get("impact", "No impact information available.")}
"""))
        else:
            md.append(dedent(f"""
**Reason**  
{rule.get("reason", "No reason given.")}
            """))
                
        md.append(dedent(f"""
**Recommendation**  
{rule.get("recommendation", "No recommendation needed.")}
            """))
        md.append("\n---\n")


def exec_summary(high_risk_findings, medium_risk_findings, inconclusive_findings, md, base_url):
    key_findings = high_risk_findings + medium_risk_findings

    seen = set()
    main_issues = []

    for f in key_findings:
        issue = f["issue"]
        if issue not in seen:
            seen.add(issue)
            main_issues.append(issue)
    
    md.append(f"A security assessment was conducted against {base_url} to identify " \
              "common web application security misconfigurations and weaknesses.\n")

    if len(main_issues) >= 3:
        issues_text = ", ".join(i.lower() for i in main_issues[:2])
        md.append(
            f"The scan identified multiple security issues, including {issues_text}, "
            f"and other significant findings."
        )
    elif len(main_issues) == 2:
        md.append(
            f"The scan identified security issues related to "
            f"{main_issues[0].lower()} and {main_issues[1].lower()}."
        )
    elif len(main_issues) == 1:
        md.append(
            f"The scan identified a security issue related to "
            f"{main_issues[0].lower()}."
        )

    if inconclusive_findings:
        md.append("Some checks could not be completed due to network timeouts or restricted access and are marked as inconclusive.")
    md.append("\n---\n")


def load_text(filename):
    base_dir = Path(__file__).resolve().parent.parent
    sections_dir = base_dir / "report_sections"
    return (sections_dir / filename).read_text(encoding="utf-8")
   
def format_evidence(evidence):
    if not evidence:
        return "_No evidence collected._"

    if isinstance(evidence, dict):
        lines = []
        for key, value in evidence.items():
            lines.append(f"- **{key.replace('_', ' ').capitalize()}:** {value}")
        return "\n".join(lines)

    if isinstance(evidence, list):
        return "\n".join(f"- {item}" for item in evidence)

    return str(evidence)


#Markdown Report
def write_markdown_report(md, output_path):
    content = "\n".join(md)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

#JSON Summary Generation
def calc_summary(audit_results):
    summary = {
        "severity_count" : 
            {
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
            },
        "check_types" :
            {
            "definitive": 0,
            "heuristic": 0
            },
        "total_findings": 0
    }

    for category in audit_results["findings"].values():
        for finding in category:
            severity = finding.get("severity", "info").lower()
            type = finding.get("check_type")

            if severity in summary["severity_count"]:
                summary["severity_count"][severity] += 1
                summary["total_findings"] += 1
            
            if type in summary["check_types"]:
                summary["check_types"][type] += 1

    return summary



#JSON Report Generation
def json_report(audit_results):
    summary = calc_summary(audit_results)
    audit_results["summary"] = summary

    with open("audit_report.json", mode="w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2, sort_keys=True)


