"""
Export service for generating scan reports in various formats.
"""
import io
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import xlsxwriter

from src.database import get_supabase_client
from src.utils.logging import get_logger

logger = get_logger(__name__)

class ExportService:
    """Service for exporting scan results in various formats."""
    
    def __init__(self):
        self.supabase = get_supabase_client()
    
    async def export_scan_results(
        self,
        scan_id: str,
        format: str,
        include_ai_analysis: bool = True,
        include_code_snippets: bool = True
    ) -> bytes:
        """
        Export scan results in the specified format.
        
        Args:
            scan_id: Scan ID to export
            format: Export format (pdf, json, csv, excel)
            include_ai_analysis: Include AI analysis in export
            include_code_snippets: Include code snippets
            
        Returns:
            Exported data as bytes
        """
        try:
            # Get scan data
            scan_data = await self._get_scan_data(scan_id, include_ai_analysis)
            
            if format == "pdf":
                return self._generate_pdf(scan_data, include_code_snippets)
            elif format == "json":
                return self._generate_json(scan_data)
            elif format == "csv":
                return self._generate_csv(scan_data)
            elif format == "excel":
                return self._generate_excel(scan_data, include_code_snippets)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Export failed for scan {scan_id}: {e}")
            raise
    
    async def _get_scan_data(self, scan_id: str, include_ai_analysis: bool) -> Dict[str, Any]:
        """Get all scan data for export."""
        # Get scan details
        scan = self.supabase.table("scans")\
            .select("*, projects(name, description)")\
            .eq("id", scan_id)\
            .single()\
            .execute()
        
        if not scan.data:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Get scan results
        results = self.supabase.table("scan_results")\
            .select("*")\
            .eq("scan_id", scan_id)\
            .order("severity", desc=False)\
            .execute()
        
        scan_data = {
            "scan": scan.data,
            "results": results.data,
            "summary": self._calculate_summary(results.data),
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Get AI analysis if requested
        if include_ai_analysis and results.data:
            vuln_ids = [r["id"] for r in results.data]
            ai_analyses = self.supabase.table("ai_analyses")\
                .select("*")\
                .in_("vulnerability_id", vuln_ids)\
                .execute()
            
            # Map AI analysis to vulnerabilities
            ai_map = {a["vulnerability_id"]: a for a in ai_analyses.data}
            for result in scan_data["results"]:
                result["ai_analysis"] = ai_map.get(result["id"])
        
        return scan_data
    
    def _generate_pdf(self, scan_data: Dict[str, Any], include_code_snippets: bool) -> bytes:
        """Generate PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Project info
        project_name = scan_data["scan"]["projects"]["name"]
        story.append(Paragraph(f"<b>Project:</b> {project_name}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_data['scan']['created_at']}", styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {scan_data['scan']['status']}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary table
        story.append(Paragraph("<b>Summary</b>", styles['Heading2']))
        summary_data = [
            ['Severity', 'Count'],
            ['Critical', str(scan_data['summary']['critical'])],
            ['High', str(scan_data['summary']['high'])],
            ['Medium', str(scan_data['summary']['medium'])],
            ['Low', str(scan_data['summary']['low'])],
            ['Total', str(scan_data['summary']['total'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(PageBreak())
        
        # Vulnerability details
        story.append(Paragraph("<b>Vulnerability Details</b>", styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))
        
        for vuln in scan_data["results"]:
            # Vulnerability header
            severity_color = self._get_severity_color(vuln["severity"])
            vuln_style = ParagraphStyle(
                'VulnTitle',
                parent=styles['Heading3'],
                textColor=severity_color,
                spaceAfter=10
            )
            story.append(Paragraph(vuln["title"], vuln_style))
            
            # Details
            details = [
                f"<b>Severity:</b> {vuln['severity'].upper()}",
                f"<b>Category:</b> {vuln.get('category', 'N/A')}",
                f"<b>File:</b> {vuln.get('file_path', 'N/A')}",
                f"<b>Line:</b> {vuln.get('line_number', 'N/A')}"
            ]
            for detail in details:
                story.append(Paragraph(detail, styles['Normal']))
            
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph(vuln.get("description", ""), styles['Normal']))
            
            # Code snippet
            if include_code_snippets and vuln.get("code_snippet"):
                story.append(Spacer(1, 0.1*inch))
                code_style = ParagraphStyle(
                    'Code',
                    parent=styles['Code'],
                    fontSize=8,
                    leftIndent=20,
                    backColor=colors.HexColor('#f5f5f5')
                )
                story.append(Paragraph(vuln["code_snippet"], code_style))
            
            # AI Analysis
            if vuln.get("ai_analysis"):
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("<b>AI Analysis:</b>", styles['Normal']))
                ai_analysis = vuln["ai_analysis"]["analysis"]
                if isinstance(ai_analysis, dict):
                    if ai_analysis.get("fix_suggestion"):
                        story.append(Paragraph(f"Fix: {ai_analysis['fix_suggestion']}", styles['Normal']))
                    if ai_analysis.get("risk_assessment"):
                        story.append(Paragraph(f"Risk: {ai_analysis['risk_assessment']}", styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
        
        # Build PDF
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
    
    def _generate_json(self, scan_data: Dict[str, Any]) -> bytes:
        """Generate JSON export."""
        return json.dumps(scan_data, indent=2, default=str).encode('utf-8')
    
    def _generate_csv(self, scan_data: Dict[str, Any]) -> bytes:
        """Generate CSV export."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
        # Headers
        headers = [
            'Title', 'Severity', 'Category', 'Type', 'File', 'Line',
            'Description', 'OWASP Category', 'CWE ID', 'Scanner'
        ]
        writer.writerow(headers)
        
        # Data rows
        for result in scan_data["results"]:
            row = [
                result.get("title", ""),
                result.get("severity", ""),
                result.get("category", ""),
                result.get("vulnerability_type", ""),
                result.get("file_path", ""),
                result.get("line_number", ""),
                result.get("description", ""),
                result.get("owasp_category", ""),
                result.get("cwe_id", ""),
                result.get("scanner", "")
            ]
            writer.writerow(row)
        
        csv_data = buffer.getvalue().encode('utf-8')
        buffer.close()
        
        return csv_data
    
    def _generate_excel(self, scan_data: Dict[str, Any], include_code_snippets: bool) -> bytes:
        """Generate Excel export with multiple sheets."""
        buffer = io.BytesIO()
        workbook = xlsxwriter.Workbook(buffer)
        
        # Formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#2563eb',
            'font_color': 'white',
            'border': 1
        })
        
        severity_formats = {
            'critical': workbook.add_format({'bg_color': '#dc2626', 'font_color': 'white'}),
            'high': workbook.add_format({'bg_color': '#ea580c', 'font_color': 'white'}),
            'medium': workbook.add_format({'bg_color': '#f59e0b'}),
            'low': workbook.add_format({'bg_color': '#3b82f6', 'font_color': 'white'})
        }
        
        # Summary sheet
        summary_sheet = workbook.add_worksheet('Summary')
        summary_sheet.write_row(0, 0, ['Metric', 'Value'], header_format)
        
        summary_rows = [
            ['Project', scan_data["scan"]["projects"]["name"]],
            ['Scan Date', scan_data["scan"]["created_at"]],
            ['Total Vulnerabilities', scan_data["summary"]["total"]],
            ['Critical', scan_data["summary"]["critical"]],
            ['High', scan_data["summary"]["high"]],
            ['Medium', scan_data["summary"]["medium"]],
            ['Low', scan_data["summary"]["low"]]
        ]
        
        for i, row in enumerate(summary_rows, 1):
            summary_sheet.write_row(i, 0, row)
        
        # Vulnerabilities sheet
        vuln_sheet = workbook.add_worksheet('Vulnerabilities')
        vuln_headers = [
            'ID', 'Title', 'Severity', 'Category', 'Type', 
            'File', 'Line', 'Description', 'Fix Recommendation'
        ]
        vuln_sheet.write_row(0, 0, vuln_headers, header_format)
        
        for i, vuln in enumerate(scan_data["results"], 1):
            severity = vuln.get("severity", "").lower()
            row_format = severity_formats.get(severity)
            
            row_data = [
                i,
                vuln.get("title", ""),
                vuln.get("severity", "").upper(),
                vuln.get("category", ""),
                vuln.get("vulnerability_type", ""),
                vuln.get("file_path", ""),
                vuln.get("line_number", ""),
                vuln.get("description", ""),
                vuln.get("fix_recommendation", "")
            ]
            
            for j, value in enumerate(row_data):
                if j == 2 and row_format:  # Severity column
                    vuln_sheet.write(i, j, value, row_format)
                else:
                    vuln_sheet.write(i, j, value)
        
        # Auto-fit columns
        for i, header in enumerate(vuln_headers):
            vuln_sheet.set_column(i, i, len(header) + 5)
        
        workbook.close()
        excel_data = buffer.getvalue()
        buffer.close()
        
        return excel_data
    
    def _calculate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate vulnerability summary."""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": len(results)
        }
        
        for result in results:
            severity = result.get("severity", "").lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color for severity level."""
        severity_colors = {
            "critical": colors.HexColor('#dc2626'),
            "high": colors.HexColor('#ea580c'),
            "medium": colors.HexColor('#f59e0b'),
            "low": colors.HexColor('#3b82f6')
        }
        return severity_colors.get(severity.lower(), colors.black)