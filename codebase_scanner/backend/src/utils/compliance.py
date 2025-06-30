"""
Compliance mapping and assessment utilities.
Maps vulnerabilities to compliance frameworks like OWASP, PCI-DSS, HIPAA, etc.
"""
from typing import Dict, List, Any, Set
from enum import Enum
import json

class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    OWASP_TOP10 = "OWASP Top 10"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC 2"
    ISO27001 = "ISO 27001"
    GDPR = "GDPR"
    NIST = "NIST Cybersecurity Framework"
    CIS = "CIS Controls"

class ComplianceMapper:
    """Maps security vulnerabilities to compliance requirements."""
    
    def __init__(self):
        self.mappings = self._load_compliance_mappings()
    
    def _load_compliance_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance framework mappings."""
        return {
            "OWASP Top 10": {
                "version": "2021",
                "categories": {
                    "A01": {
                        "name": "Broken Access Control",
                        "vulnerability_types": ["authentication", "authorization", "path-traversal", "idor"],
                        "cwe_ids": ["CWE-22", "CWE-284", "CWE-285", "CWE-639"]
                    },
                    "A02": {
                        "name": "Cryptographic Failures",
                        "vulnerability_types": ["weak-crypto", "hardcoded-secrets", "cleartext-storage"],
                        "cwe_ids": ["CWE-327", "CWE-328", "CWE-916", "CWE-798"]
                    },
                    "A03": {
                        "name": "Injection",
                        "vulnerability_types": ["sql-injection", "command-injection", "ldap-injection", "xss"],
                        "cwe_ids": ["CWE-79", "CWE-89", "CWE-78", "CWE-90"]
                    },
                    "A04": {
                        "name": "Insecure Design",
                        "vulnerability_types": ["business-logic", "design-flaw"],
                        "cwe_ids": ["CWE-73", "CWE-183", "CWE-209"]
                    },
                    "A05": {
                        "name": "Security Misconfiguration",
                        "vulnerability_types": ["misconfiguration", "default-passwords", "verbose-errors"],
                        "cwe_ids": ["CWE-16", "CWE-611"]
                    },
                    "A06": {
                        "name": "Vulnerable and Outdated Components",
                        "vulnerability_types": ["vulnerable-dependency", "outdated-library"],
                        "cwe_ids": ["CWE-1104"]
                    },
                    "A07": {
                        "name": "Identification and Authentication Failures",
                        "vulnerability_types": ["weak-password", "session-fixation", "broken-auth"],
                        "cwe_ids": ["CWE-287", "CWE-384", "CWE-521"]
                    },
                    "A08": {
                        "name": "Software and Data Integrity Failures",
                        "vulnerability_types": ["deserialization", "ci-cd-breach"],
                        "cwe_ids": ["CWE-502", "CWE-565", "CWE-784"]
                    },
                    "A09": {
                        "name": "Security Logging and Monitoring Failures",
                        "vulnerability_types": ["insufficient-logging", "log-injection"],
                        "cwe_ids": ["CWE-117", "CWE-223", "CWE-778"]
                    },
                    "A10": {
                        "name": "Server-Side Request Forgery (SSRF)",
                        "vulnerability_types": ["ssrf"],
                        "cwe_ids": ["CWE-918"]
                    }
                }
            },
            "PCI-DSS": {
                "version": "4.0",
                "requirements": {
                    "6.2": {
                        "name": "Protect Systems and Software from Malicious Software",
                        "vulnerability_types": ["malware", "vulnerable-dependency"]
                    },
                    "6.3": {
                        "name": "Security Vulnerabilities are Identified and Addressed",
                        "vulnerability_types": ["*"]  # All vulnerabilities
                    },
                    "6.4": {
                        "name": "Software Engineering and Software Development",
                        "vulnerability_types": ["injection", "xss", "authentication", "authorization"]
                    },
                    "8.3": {
                        "name": "Strong Cryptography",
                        "vulnerability_types": ["weak-crypto", "cleartext-storage"]
                    },
                    "8.4": {
                        "name": "Multi-Factor Authentication",
                        "vulnerability_types": ["authentication", "weak-password"]
                    }
                }
            },
            "HIPAA": {
                "safeguards": {
                    "164.308": {
                        "name": "Administrative Safeguards",
                        "vulnerability_types": ["authentication", "authorization", "audit-logging"]
                    },
                    "164.310": {
                        "name": "Physical Safeguards",
                        "vulnerability_types": ["physical-access"]
                    },
                    "164.312": {
                        "name": "Technical Safeguards",
                        "vulnerability_types": ["encryption", "authentication", "audit-controls"]
                    }
                }
            },
            "GDPR": {
                "articles": {
                    "32": {
                        "name": "Security of Processing",
                        "vulnerability_types": ["encryption", "authentication", "data-protection"]
                    },
                    "33": {
                        "name": "Notification of Personal Data Breach",
                        "vulnerability_types": ["data-exposure", "insufficient-logging"]
                    },
                    "25": {
                        "name": "Data Protection by Design",
                        "vulnerability_types": ["privacy", "data-minimization"]
                    }
                }
            }
        }
    
    def map_vulnerabilities_to_compliance(
        self,
        vulnerabilities: List[Dict[str, Any]],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """
        Map vulnerabilities to compliance framework requirements.
        
        Args:
            vulnerabilities: List of vulnerability findings
            frameworks: List of compliance frameworks to check
            
        Returns:
            Compliance mapping results
        """
        results = {
            "compliance_status": {},
            "gaps": {},
            "coverage": {},
            "recommendations": {}
        }
        
        for framework in frameworks:
            if framework in self.mappings:
                framework_result = self._assess_framework_compliance(
                    vulnerabilities,
                    framework,
                    self.mappings[framework]
                )
                results["compliance_status"][framework] = framework_result["status"]
                results["gaps"][framework] = framework_result["gaps"]
                results["coverage"][framework] = framework_result["coverage"]
                results["recommendations"][framework] = framework_result["recommendations"]
        
        # Overall compliance score
        results["overall_score"] = self._calculate_overall_compliance_score(results)
        
        return results
    
    def _assess_framework_compliance(
        self,
        vulnerabilities: List[Dict[str, Any]],
        framework_name: str,
        framework_mapping: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess compliance for a specific framework."""
        gaps = []
        covered_requirements = set()
        total_requirements = 0
        
        # Map vulnerabilities to framework requirements
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("vulnerability_type", "").lower()
            category = vuln.get("category", "").lower()
            
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
            
            if category not in vuln_by_type:
                vuln_by_type[category] = []
            vuln_by_type[category].append(vuln)
        
        # Check OWASP Top 10
        if framework_name == "OWASP Top 10":
            for cat_id, category in framework_mapping.get("categories", {}).items():
                total_requirements += 1
                has_vulnerabilities = False
                
                for vuln_type in category["vulnerability_types"]:
                    if vuln_type in vuln_by_type:
                        has_vulnerabilities = True
                        gaps.append({
                            "category": f"{cat_id}: {category['name']}",
                            "vulnerabilities": len(vuln_by_type[vuln_type]),
                            "severity": self._get_highest_severity(vuln_by_type[vuln_type])
                        })
                        break
                
                if not has_vulnerabilities:
                    covered_requirements.add(cat_id)
        
        # Check PCI-DSS
        elif framework_name == "PCI-DSS":
            for req_id, requirement in framework_mapping.get("requirements", {}).items():
                total_requirements += 1
                has_vulnerabilities = False
                
                if "*" in requirement["vulnerability_types"]:
                    # Requirement applies to all vulnerabilities
                    if vulnerabilities:
                        has_vulnerabilities = True
                        gaps.append({
                            "requirement": f"{req_id}: {requirement['name']}",
                            "vulnerabilities": len(vulnerabilities),
                            "severity": self._get_highest_severity(vulnerabilities)
                        })
                else:
                    for vuln_type in requirement["vulnerability_types"]:
                        if vuln_type in vuln_by_type:
                            has_vulnerabilities = True
                            gaps.append({
                                "requirement": f"{req_id}: {requirement['name']}",
                                "vulnerabilities": len(vuln_by_type[vuln_type]),
                                "severity": self._get_highest_severity(vuln_by_type[vuln_type])
                            })
                            break
                
                if not has_vulnerabilities:
                    covered_requirements.add(req_id)
        
        # Calculate coverage
        coverage_percentage = (len(covered_requirements) / total_requirements * 100) if total_requirements > 0 else 100
        
        # Generate recommendations
        recommendations = self._generate_compliance_recommendations(framework_name, gaps)
        
        return {
            "status": "compliant" if not gaps else "non-compliant",
            "gaps": gaps,
            "coverage": {
                "percentage": round(coverage_percentage, 1),
                "covered": len(covered_requirements),
                "total": total_requirements
            },
            "recommendations": recommendations
        }
    
    def _get_highest_severity(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get the highest severity from a list of vulnerabilities."""
        severity_order = ["critical", "high", "medium", "low", "info"]
        highest = "info"
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity_order.index(severity) < severity_order.index(highest):
                highest = severity
        
        return highest
    
    def _generate_compliance_recommendations(
        self,
        framework: str,
        gaps: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate specific compliance recommendations."""
        recommendations = []
        
        # Group gaps by severity
        critical_gaps = [g for g in gaps if g.get("severity") == "critical"]
        high_gaps = [g for g in gaps if g.get("severity") == "high"]
        
        if critical_gaps:
            recommendations.append({
                "priority": "urgent",
                "title": f"Address {len(critical_gaps)} critical {framework} compliance gaps",
                "description": f"Critical vulnerabilities affecting {framework} compliance must be remediated immediately.",
                "affected_areas": [g.get("category") or g.get("requirement") for g in critical_gaps]
            })
        
        if high_gaps:
            recommendations.append({
                "priority": "high",
                "title": f"Remediate {len(high_gaps)} high-severity compliance issues",
                "description": f"High-severity vulnerabilities pose significant {framework} compliance risks.",
                "affected_areas": [g.get("category") or g.get("requirement") for g in high_gaps]
            })
        
        # Framework-specific recommendations
        if framework == "PCI-DSS" and gaps:
            recommendations.append({
                "priority": "high",
                "title": "Implement compensating controls",
                "description": "Where vulnerabilities cannot be immediately fixed, implement compensating controls to maintain PCI compliance.",
                "actions": [
                    "Document all vulnerabilities and remediation plans",
                    "Implement additional monitoring for affected systems",
                    "Consider network segmentation to reduce scope"
                ]
            })
        
        elif framework == "OWASP Top 10" and gaps:
            recommendations.append({
                "priority": "medium",
                "title": "Security training and awareness",
                "description": "Implement developer security training focused on OWASP Top 10 vulnerabilities.",
                "actions": [
                    "Conduct secure coding training",
                    "Implement security champions program",
                    "Regular security awareness sessions"
                ]
            })
        
        return recommendations
    
    def _calculate_overall_compliance_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall compliance score across all frameworks."""
        if not results["coverage"]:
            return 100.0
        
        total_score = 0
        framework_count = 0
        
        for framework, coverage in results["coverage"].items():
            total_score += coverage["percentage"]
            framework_count += 1
        
        return round(total_score / framework_count, 1) if framework_count > 0 else 100.0
    
    def generate_compliance_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive compliance report.
        
        Args:
            vulnerabilities: List of vulnerability findings
            frameworks: List of compliance frameworks
            
        Returns:
            Comprehensive compliance report
        """
        mapping_results = self.map_vulnerabilities_to_compliance(vulnerabilities, frameworks)
        
        report = {
            "summary": {
                "overall_compliance_score": mapping_results["overall_score"],
                "frameworks_assessed": frameworks,
                "total_vulnerabilities": len(vulnerabilities),
                "compliance_impact": self._assess_compliance_impact(mapping_results)
            },
            "framework_details": {},
            "priority_actions": [],
            "compliance_roadmap": []
        }
        
        # Add framework-specific details
        for framework in frameworks:
            if framework in mapping_results["compliance_status"]:
                report["framework_details"][framework] = {
                    "status": mapping_results["compliance_status"][framework],
                    "coverage": mapping_results["coverage"][framework],
                    "gaps": mapping_results["gaps"][framework],
                    "recommendations": mapping_results["recommendations"][framework]
                }
        
        # Generate priority actions
        report["priority_actions"] = self._generate_priority_actions(mapping_results)
        
        # Generate compliance roadmap
        report["compliance_roadmap"] = self._generate_compliance_roadmap(mapping_results)
        
        return report
    
    def _assess_compliance_impact(self, mapping_results: Dict[str, Any]) -> str:
        """Assess overall compliance impact."""
        score = mapping_results["overall_score"]
        
        if score >= 95:
            return "Minimal - Strong compliance posture"
        elif score >= 80:
            return "Low - Minor compliance gaps"
        elif score >= 60:
            return "Medium - Significant compliance work needed"
        elif score >= 40:
            return "High - Major compliance gaps"
        else:
            return "Critical - Immediate action required"
    
    def _generate_priority_actions(self, mapping_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized action items."""
        actions = []
        
        # Collect all recommendations
        all_recommendations = []
        for framework, recommendations in mapping_results["recommendations"].items():
            for rec in recommendations:
                rec["framework"] = framework
                all_recommendations.append(rec)
        
        # Sort by priority
        priority_order = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
        all_recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 3))
        
        # Take top actions
        for rec in all_recommendations[:5]:  # Top 5 actions
            actions.append({
                "priority": rec["priority"],
                "framework": rec["framework"],
                "action": rec["title"],
                "description": rec["description"],
                "estimated_effort": self._estimate_effort(rec)
            })
        
        return actions
    
    def _estimate_effort(self, recommendation: Dict[str, Any]) -> str:
        """Estimate effort for a recommendation."""
        if recommendation.get("priority") == "urgent":
            return "1-2 weeks"
        elif recommendation.get("priority") == "high":
            return "2-4 weeks"
        else:
            return "1-2 months"
    
    def _generate_compliance_roadmap(self, mapping_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate compliance improvement roadmap."""
        roadmap = []
        
        # Phase 1: Critical gaps
        critical_items = []
        for framework, gaps in mapping_results["gaps"].items():
            critical_gaps = [g for g in gaps if g.get("severity") == "critical"]
            if critical_gaps:
                critical_items.extend(critical_gaps)
        
        if critical_items:
            roadmap.append({
                "phase": 1,
                "timeline": "0-30 days",
                "focus": "Critical vulnerability remediation",
                "objectives": [
                    f"Fix {len(critical_items)} critical vulnerabilities",
                    "Implement immediate compensating controls",
                    "Document remediation efforts"
                ]
            })
        
        # Phase 2: High-priority gaps
        roadmap.append({
            "phase": 2,
            "timeline": "30-90 days",
            "focus": "High-priority compliance gaps",
            "objectives": [
                "Address remaining high-severity vulnerabilities",
                "Implement security monitoring",
                "Conduct security training"
            ]
        })
        
        # Phase 3: Full compliance
        roadmap.append({
            "phase": 3,
            "timeline": "90-180 days",
            "focus": "Achieve full compliance",
            "objectives": [
                "Remediate all remaining vulnerabilities",
                "Implement continuous compliance monitoring",
                "Achieve certification/attestation"
            ]
        })
        
        return roadmap