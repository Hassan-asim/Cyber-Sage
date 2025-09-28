from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
import os
from dotenv import load_dotenv
import json
import requests
from datetime import datetime
import google.generativeai as genai
import re
import uuid
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import io
import threading
import time
from security_scanner import SecurityScanner, AdvancedSecurityScanner

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyber-ai-secret-key-2024')
CORS(app)

# Configure Google Gemini
genai.configure(api_key=os.environ.get('GEMINI_API_KEY'))

# Initialize the model - Using Gemini 2.5 Flash (free tier)
model = genai.GenerativeModel('gemini-2.0-flash-exp')

# In-memory storage for vulnerability reports and penetration test data
vulnerability_reports = []
current_penetration_test = {
    'id': None,
    'name': '',
    'start_date': None,
    'vulnerabilities': [],
    'status': 'inactive'
}

# Agentic AI System
class CyberAIAgent:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        self.agents = {
            'researcher': self.research_agent,
            'assessor': self.assessment_agent,
            'remediator': self.remediation_agent,
            'reporter': self.reporting_agent,
            'web_scanner': self.web_scanner_agent
        }
    
    def research_agent(self, vulnerability_description):
        """Agent responsible for vulnerability research and CVE lookup"""
        try:
            prompt = f"""
            As a cybersecurity research agent, analyze this vulnerability:
            "{vulnerability_description}"
            
            Provide:
            1. Vulnerability classification (CWE, OWASP Top 10 mapping)
            2. CVE references and known exploits
            3. Attack vectors and techniques
            4. Real-world examples and case studies
            5. Current threat landscape relevance
            
            Format as structured JSON with research findings.
            """
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Research agent error: {str(e)}"
    
    def assessment_agent(self, vulnerability_data):
        """Agent responsible for CVSS scoring and risk assessment"""
        try:
            prompt = f"""
            As a vulnerability assessment agent, evaluate:
            {vulnerability_data}
            
            Calculate CVSS v3.1 scores for:
            - Attack Vector (AV)
            - Attack Complexity (AC)
            - Privileges Required (PR)
            - User Interaction (UI)
            - Scope (S)
            - Confidentiality (C)
            - Integrity (I)
            - Availability (A)
            
            Provide:
            1. Base Score calculation
            2. Temporal Score factors
            3. Environmental Score considerations
            4. Overall severity rating
            5. Business impact assessment
            
            Format as structured JSON.
            """
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Assessment agent error: {str(e)}"
    
    def remediation_agent(self, vulnerability_data):
        """Agent responsible for remediation strategies"""
        try:
            prompt = f"""
            As a remediation specialist agent, provide solutions for:
            {vulnerability_data}
            
            Generate:
            1. Immediate mitigation steps
            2. Long-term remediation plan
            3. Code fixes and patches
            4. Configuration changes
            5. Monitoring and detection rules
            6. Prevention strategies
            7. Training recommendations
            
            Format as structured JSON with actionable steps.
            """
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Remediation agent error: {str(e)}"
    
    def reporting_agent(self, all_data):
        """Agent responsible for professional report generation"""
        try:
            prompt = f"""
            As a cybersecurity reporting agent, create a professional report for:
            {all_data}
            
            Generate:
            1. Executive summary
            2. Technical details
            3. Risk assessment
            4. Remediation roadmap
            5. Compliance mapping
            6. Recommendations
            
            Format as professional security report.
            """
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Reporting agent error: {str(e)}"
    
    def web_scanner_agent(self, website_url):
        """Agent responsible for website vulnerability scanning"""
        try:
            prompt = f"""
            As a web security scanning agent, analyze the website: {website_url}
            
            Perform comprehensive security analysis including:
            1. OWASP Top 10 vulnerabilities testing
            2. Common web vulnerabilities (SQL injection, XSS, CSRF, etc.)
            3. Security headers analysis
            4. SSL/TLS configuration review
            5. Authentication and authorization flaws
            6. Input validation issues
            7. Session management problems
            8. File upload vulnerabilities
            9. Directory traversal risks
            10. Information disclosure issues
            
            For each vulnerability found, provide:
            - Vulnerability type and description
            - Severity level (Critical/High/Medium/Low)
            - CVSS score estimation
            - Proof of concept
            - Remediation steps
            - OWASP category mapping
            
            Format as structured JSON with detailed findings.
            """
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Web scanner agent error: {str(e)}"
    
    def orchestrate_analysis(self, vulnerability_description):
        """Orchestrate multiple agents for comprehensive analysis"""
        try:
            # Step 1: Research
            research_data = self.research_agent(vulnerability_description)
            
            # Step 2: Assessment
            assessment_data = self.assessment_agent(research_data)
            
            # Step 3: Remediation
            remediation_data = self.remediation_agent(assessment_data)
            
            # Step 4: Reporting
            report_data = self.reporting_agent({
                'description': vulnerability_description,
                'research': research_data,
                'assessment': assessment_data,
                'remediation': remediation_data
            })
            
            return {
                'research': research_data,
                'assessment': assessment_data,
                'remediation': remediation_data,
                'report': report_data
            }
        except Exception as e:
            return {'error': f"Agent orchestration error: {str(e)}"}

# Initialize AI Agent System
cyber_ai_agent = CyberAIAgent()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/app')
def main_app():
    return render_template('app.html')

@app.route('/website-test')
def website_test():
    return render_template('website_test.html')

@app.route('/test-website')
def test_website():
    return "Website test route is working! <a href='/website-test'>Go to Website Testing</a>"

@app.route('/api/vulnerability/assess', methods=['POST'])
def assess_vulnerability():
    try:
        data = request.json
        vulnerability_description = data.get('description', '')
        
        if not vulnerability_description:
            return jsonify({'error': 'Vulnerability description is required'}), 400
        
        # Use agentic AI system for comprehensive analysis
        agent_analysis = cyber_ai_agent.orchestrate_analysis(vulnerability_description)
        
        if 'error' in agent_analysis:
            return jsonify({'error': agent_analysis['error']}), 500
        
        # Extract structured data from agent analysis
        try:
            # Parse assessment data for CVSS scoring
            assessment_text = agent_analysis['assessment']
            cvss_match = re.search(r'"base_score":\s*(\d+\.?\d*)', assessment_text)
            cvss_score = cvss_match.group(1) if cvss_match else "7.5"
            
            severity_match = re.search(r'"severity":\s*"([^"]+)"', assessment_text)
            severity = severity_match.group(1) if severity_match else "High"
            
            # Parse OWASP mapping
            owasp_match = re.search(r'"owasp":\s*"([^"]+)"', assessment_text)
            owasp_category = owasp_match.group(1) if owasp_match else "A01:2021 - Broken Access Control"
            
            # Parse CVE references
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', assessment_text)
            cve_references = list(set(cve_matches))[:5]  # Limit to 5 CVE references
            
        except Exception as parse_error:
            # Fallback values if parsing fails
            cvss_score = "7.5"
            severity = "High"
            owasp_category = "A01:2021 - Broken Access Control"
            cve_references = []
        
        # Create comprehensive vulnerability report
        report = {
            'id': str(uuid.uuid4()),
            'title': f"Vulnerability Analysis: {vulnerability_description[:50]}...",
            'description': vulnerability_description,
            'severity': severity,
            'cvss_score': cvss_score,
            'owasp_category': owasp_category,
            'cve_references': cve_references,
            'exploit_details': agent_analysis['research'],
            'reproduction_steps': agent_analysis['remediation'],
            'remediation': agent_analysis['remediation'],
            'technical_details': agent_analysis['assessment'],
            'executive_summary': agent_analysis['report'],
            'agent_analysis': agent_analysis,
            'timestamp': datetime.now().isoformat(),
            'status': 'identified'
        }
        
        vulnerability_reports.append(report)
        
        return jsonify({
            'success': True,
            'report': report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability/reports', methods=['GET'])
def get_vulnerability_reports():
    return jsonify({
        'success': True,
        'reports': vulnerability_reports
    })

@app.route('/api/dashboard/analytics', methods=['GET'])
def get_dashboard_analytics():
    try:
        # Calculate vulnerability statistics
        total_vulns = len(vulnerability_reports)
        critical_vulns = len([v for v in vulnerability_reports if v['severity'].lower() == 'critical'])
        high_vulns = len([v for v in vulnerability_reports if v['severity'].lower() == 'high'])
        medium_vulns = len([v for v in vulnerability_reports if v['severity'].lower() == 'medium'])
        low_vulns = len([v for v in vulnerability_reports if v['severity'].lower() == 'low'])
        
        # Calculate average CVSS score
        cvss_scores = [float(v['cvss_score']) for v in vulnerability_reports if v['cvss_score'] != 'N/A']
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        # OWASP Top 10 distribution
        owasp_categories = {}
        for vuln in vulnerability_reports:
            category = vuln.get('owasp_category', 'Unknown')
            owasp_categories[category] = owasp_categories.get(category, 0) + 1
        
        # Recent vulnerabilities (last 5)
        recent_vulns = sorted(vulnerability_reports, key=lambda x: x['timestamp'], reverse=True)[:5]
        
        # Test duration calculation
        test_duration = 0
        if current_penetration_test['status'] == 'active' and current_penetration_test['start_date']:
            start_time = datetime.fromisoformat(current_penetration_test['start_date'])
            test_duration = (datetime.now() - start_time).total_seconds() / 3600  # hours
        
        analytics = {
            'vulnerability_stats': {
                'total': total_vulns,
                'critical': critical_vulns,
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns,
                'average_cvss': round(avg_cvss, 2)
            },
            'owasp_distribution': owasp_categories,
            'recent_vulnerabilities': recent_vulns,
            'test_status': {
                'active': current_penetration_test['status'] == 'active',
                'duration_hours': round(test_duration, 2),
                'vulnerabilities_found': len(current_penetration_test['vulnerabilities'])
            },
            'trends': {
                'vulnerabilities_per_hour': round(total_vulns / max(test_duration, 1), 2),
                'critical_percentage': round((critical_vulns / max(total_vulns, 1)) * 100, 2),
                'high_percentage': round((high_vulns / max(total_vulns, 1)) * 100, 2)
            }
        }
        
        return jsonify({
            'success': True,
            'analytics': analytics
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/penetration-test/start', methods=['POST'])
def start_penetration_test():
    try:
        data = request.json
        test_name = data.get('name', f'Penetration Test {datetime.now().strftime("%Y-%m-%d %H:%M")}')
        
        current_penetration_test.update({
            'id': len(vulnerability_reports) + 1,
            'name': test_name,
            'start_date': datetime.now().isoformat(),
            'vulnerabilities': [],
            'status': 'active'
        })
        
        return jsonify({
            'success': True,
            'test': current_penetration_test
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/penetration-test/end', methods=['POST'])
def end_penetration_test():
    try:
        current_penetration_test['status'] = 'completed'
        current_penetration_test['end_date'] = datetime.now().isoformat()
        
        # Generate final report
        final_report = generate_final_report(current_penetration_test)
        
        return jsonify({
            'success': True,
            'final_report': final_report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cybersage/chat', methods=['POST'])
def cybersage_chat():
    try:
        data = request.json
        message = data.get('message', '')
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Check if Gemini API key is configured
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key or api_key == 'your-gemini-api-key-here':
            return jsonify({
                'success': True,
                'response': "I'm CyberSage, your cybersecurity expert! I'd love to help you with your security questions. However, I need a valid Gemini API key to provide AI-powered responses. Please configure your API key in the .env file to unlock my full capabilities. For now, I can provide general security guidance: Always keep your systems updated, use strong passwords, enable 2FA, and follow the principle of least privilege."
            })
        
        # Use Gemini for CyberSage responses
        try:
            response = model.generate_content(f"""
            You are CyberSage, an expert cybersecurity consultant and penetration testing specialist with 15+ years of experience.
            
            User Query: {message}
            
            Provide a comprehensive, professional response that includes:
            
            ## Analysis
            - Clear understanding of the security concern
            - Risk assessment (Critical/High/Medium/Low)
            - Impact analysis
            
            ## Technical Details
            - Specific vulnerability explanations
            - Attack vectors and exploitation methods
            - Technical indicators and detection methods
            
            ## Recommendations
            - Immediate mitigation steps
            - Long-term security improvements
            - Configuration changes and code fixes
            - Monitoring and detection strategies
            
            ## Best Practices
            - Relevant security frameworks (OWASP, NIST, ISO 27001)
            - Industry standards and compliance requirements
            - Security testing methodologies
            
            ## Code Examples
            - Secure coding practices
            - Configuration snippets
            - Tool usage examples
            
            ## Additional Resources
            - Relevant CVE numbers
            - Security advisories
            - Further reading materials
            
            Format your response with proper markdown for excellent readability.
            Use emojis sparingly and professionally (🔒 🛡️ ⚠️ ✅ ❌).
            Keep responses detailed but actionable, typically 300-800 words.
            """)
            
            return jsonify({
                'success': True,
                'response': response.text
            })
        except Exception as gemini_error:
            # Fallback response if Gemini fails
            return jsonify({
                'success': True,
                'response': f"I'm CyberSage, your cybersecurity expert! I encountered an issue with the AI service, but I can still help. For your question about '{message}', here's some general guidance: Always follow security best practices, keep systems updated, use strong authentication, and implement proper access controls. For specific technical issues, I recommend consulting the latest security documentation and following industry standards like OWASP guidelines."
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/generate-pdf/<report_id>')
def generate_pdf_report(report_id):
    try:
        # Find the vulnerability report
        report = next((r for r in vulnerability_reports if r['id'] == report_id), None)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#1e40af'),
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#1e40af'),
            fontName='Helvetica-Bold'
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#374151'),
            fontName='Helvetica-Bold'
        )
        
        # Title and Header
        story.append(Paragraph("🛡️ Cyber AI Security Assessment", title_style))
        story.append(Paragraph("Professional Vulnerability Assessment Report", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Executive Summary Box
        exec_summary_style = ParagraphStyle(
            'ExecSummary',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=12,
            spaceBefore=12,
            leftIndent=20,
            rightIndent=20,
            backColor=colors.HexColor('#f8fafc'),
            borderColor=colors.HexColor('#e2e8f0'),
            borderWidth=1,
            borderPadding=10
        )
        
        story.append(Paragraph("📋 Executive Summary", heading_style))
        story.append(Paragraph(f"<b>Vulnerability:</b> {report['title']}", exec_summary_style))
        story.append(Paragraph(f"<b>Severity Level:</b> {report['severity']} (CVSS: {report['cvss_score']})", exec_summary_style))
        story.append(Paragraph(f"<b>OWASP Category:</b> {report['owasp_category']}", exec_summary_style))
        story.append(Spacer(1, 20))
        
        # Report Metadata Table
        story.append(Paragraph("📊 Report Information", heading_style))
        metadata_data = [
            ['Report ID', report['id']],
            ['Assessment Date', datetime.fromisoformat(report['timestamp']).strftime('%B %d, %Y at %H:%M:%S')],
            ['Severity Level', report['severity']],
            ['CVSS Score', report['cvss_score']],
            ['OWASP Category', report['owasp_category']],
            ['Status', report['status'].title()],
            ['Report Generated', datetime.now().strftime('%B %d, %Y at %H:%M:%S')]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2.5*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 25))
        
        # Vulnerability Description
        story.append(Paragraph("🔍 Vulnerability Description", heading_style))
        story.append(Paragraph(report['description'], styles['Normal']))
        story.append(Spacer(1, 15))
        
        # CVE References
        if report.get('cve_references') and len(report['cve_references']) > 0:
            story.append(Paragraph("🔗 CVE References", heading_style))
            cve_text = " • ".join(report['cve_references'])
            story.append(Paragraph(cve_text, styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Technical Analysis
        story.append(Paragraph("⚙️ Technical Analysis", heading_style))
        technical_content = report.get('technical_details', 'No technical details available.')
        if len(technical_content) > 1500:
            technical_content = technical_content[:1500] + "..."
        story.append(Paragraph(technical_content, styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Research Findings
        if report.get('exploit_details'):
            story.append(Paragraph("🔬 Research Findings", heading_style))
            research_content = report['exploit_details']
            if len(research_content) > 1000:
                research_content = research_content[:1000] + "..."
            story.append(Paragraph(research_content, styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Remediation Strategy
        story.append(Paragraph("🛠️ Remediation Strategy", heading_style))
        remediation_content = report.get('remediation', 'No remediation strategy available.')
        if len(remediation_content) > 1500:
            remediation_content = remediation_content[:1500] + "..."
        story.append(Paragraph(remediation_content, styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Executive Summary
        if report.get('executive_summary'):
            story.append(Paragraph("📈 Executive Summary", heading_style))
            exec_content = report['executive_summary']
            if len(exec_content) > 1000:
                exec_content = exec_content[:1000] + "..."
            story.append(Paragraph(exec_content, styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("Generated by Cyber AI Security Platform", 
                              ParagraphStyle('Footer', parent=styles['Normal'], 
                                           fontSize=8, alignment=1, 
                                           textColor=colors.HexColor('#6b7280'))))
        story.append(Paragraph(f"Report ID: {report_id} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              ParagraphStyle('Footer', parent=styles['Normal'], 
                                           fontSize=8, alignment=1, 
                                           textColor=colors.HexColor('#6b7280'))))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"cyber_ai_vulnerability_report_{report_id[:8]}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/generate-final-pdf')
def generate_final_pdf_report():
    try:
        if not vulnerability_reports:
            return jsonify({'error': 'No vulnerabilities found'}), 400
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#a78bfa')
        )
        story.append(Paragraph("Cyber AI - Penetration Test Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Paragraph(f"This penetration test identified {len(vulnerability_reports)} vulnerabilities across the target systems. The findings range from {min([r['severity'] for r in vulnerability_reports])} to {max([r['severity'] for r in vulnerability_reports])} severity levels.", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Vulnerability Summary Table
        story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
        
        vuln_data = [['ID', 'Title', 'Severity', 'CVSS Score', 'OWASP Category']]
        for report in vulnerability_reports:
            vuln_data.append([
                report['id'][:8] + "...",
                report['title'][:30] + "...",
                report['severity'],
                report['cvss_score'],
                report['owasp_category'][:20] + "..."
            ])
        
        vuln_table = Table(vuln_data, colWidths=[1*inch, 2*inch, 1*inch, 1*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#a78bfa')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(vuln_table)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", styles['Heading2']))
        for i, report in enumerate(vulnerability_reports, 1):
            story.append(Paragraph(f"Finding {i}: {report['title']}", styles['Heading3']))
            story.append(Paragraph(f"Severity: {report['severity']} (CVSS: {report['cvss_score']})", styles['Normal']))
            story.append(Paragraph(f"Description: {report['description'][:200]}...", styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"penetration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/website/scan', methods=['POST'])
def scan_website():
    try:
        data = request.json
        website_url = data.get('url', '').strip()
        
        if not website_url:
            return jsonify({'error': 'Website URL is required'}), 400
        
        # Validate URL format
        if not website_url.startswith(('http://', 'https://')):
            website_url = 'https://' + website_url
        
        # Initialize advanced security scanner for real cybersecurity testing
        scanner = AdvancedSecurityScanner()
        
        # Perform comprehensive security scan with real techniques
        scan_results = scanner.comprehensive_web_scan(website_url)
        
        # Create enhanced scan report
        scan_report = {
            'id': str(uuid.uuid4()),
            'website_url': website_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities_found': len(scan_results.get('vulnerabilities', [])),
            'vulnerabilities': scan_results.get('vulnerabilities', []),
            'security_headers': scan_results.get('security_headers', {}),
            'ssl_info': scan_results.get('ssl_info', {}),
            'dns_info': scan_results.get('dns_info', {}),
            'vulnerability_tests': scan_results.get('vulnerability_tests', {}),
            'directory_enumeration': scan_results.get('directory_enumeration', []),
            'subdomain_scan': scan_results.get('subdomain_scan', []),
            'port_scan': scan_results.get('port_scan', []),
            'content_analysis': scan_results.get('content_analysis', {}),
            'status': 'completed',
            'scan_duration': 'Real-time comprehensive scan completed'
        }
        
        return jsonify({
            'success': True,
            'scan_report': scan_report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# New cybersecurity features
@app.route('/api/network/scan', methods=['POST'])
def network_scan():
    """Perform network reconnaissance and port scanning"""
    try:
        data = request.json
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'basic')  # basic, comprehensive, stealth
        
        if not target:
            return jsonify({'error': 'Target IP or domain is required'}), 400
        
        # Use advanced security scanner for real network reconnaissance
        scanner = AdvancedSecurityScanner()
        
        # Perform advanced network scan with real cybersecurity tools
        if scan_type == 'comprehensive':
            # Advanced port scan with Nmap
            open_ports = scanner.advanced_port_scan(target)
            # Advanced DNS analysis
            dns_info = scanner.analyze_dns_advanced(target)
            # Advanced subdomain discovery
            subdomains = scanner.advanced_subdomain_discovery(target)
            # Network analysis
            network_analysis = scanner.perform_network_analysis(target)
            # Threat intelligence
            threat_intel = scanner.gather_threat_intelligence(target)
        else:
            # Basic scan with real tools
            open_ports = scanner.basic_port_scan(target)
            dns_info = scanner.analyze_dns_advanced(target)
            subdomains = []
            network_analysis = {}
            threat_intel = {}
        
        scan_report = {
            'id': str(uuid.uuid4()),
            'target': target,
            'scan_type': scan_type,
            'scan_date': datetime.now().isoformat(),
            'open_ports': open_ports,
            'dns_info': dns_info,
            'subdomains': subdomains,
            'network_analysis': network_analysis,
            'threat_intelligence': threat_intel,
            'status': 'completed'
        }
        
        return jsonify({
            'success': True,
            'scan_report': scan_report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability/scan', methods=['POST'])
def vulnerability_scan():
    """Perform comprehensive vulnerability scanning using real security tools"""
    try:
        data = request.json
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'comprehensive')  # web, network, comprehensive
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        scanner = AdvancedSecurityScanner()
        
        if scan_type == 'web' or scan_type == 'comprehensive':
            # Web vulnerability scan
            web_scan = scanner.comprehensive_web_scan(target)
        else:
            web_scan = {}
        
        if scan_type == 'network' or scan_type == 'comprehensive':
            # Network vulnerability scan
            network_scan = {
                'port_scan': scanner.advanced_port_scan(target),
                'dns_analysis': scanner.analyze_dns_advanced(target),
                'subdomain_discovery': scanner.advanced_subdomain_discovery(target),
                'network_analysis': scanner.perform_network_analysis(target),
                'threat_intelligence': scanner.gather_threat_intelligence(target)
            }
        else:
            network_scan = {}
        
        # Generate comprehensive vulnerability report
        vulnerability_report = {
            'id': str(uuid.uuid4()),
            'target': target,
            'scan_type': scan_type,
            'scan_date': datetime.now().isoformat(),
            'web_scan': web_scan,
            'network_scan': network_scan,
            'total_vulnerabilities': len(web_scan.get('vulnerabilities', [])) + len(network_scan.get('vulnerabilities', [])),
            'status': 'completed'
        }
        
        return jsonify({
            'success': True,
            'vulnerability_report': vulnerability_report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/penetration-test/automated', methods=['POST'])
def automated_penetration_test():
    """Perform automated penetration testing"""
    try:
        data = request.json
        targets = data.get('targets', [])
        test_scope = data.get('scope', 'comprehensive')
        
        if not targets:
            return jsonify({'error': 'At least one target is required'}), 400
        
        results = []
        scanner = AdvancedSecurityScanner()
        
        for target in targets:
            try:
                if target.startswith(('http://', 'https://')) or '.' in target:
                    # Advanced web application testing with real security tools
                    scan_result = scanner.comprehensive_web_scan(target)
                else:
                    # Advanced network testing with real cybersecurity tools
                    network_scan = {
                        'port_scan': scanner.advanced_port_scan(target),
                        'dns_analysis': scanner.analyze_dns_advanced(target),
                        'subdomain_discovery': scanner.advanced_subdomain_discovery(target),
                        'network_analysis': scanner.perform_network_analysis(target),
                        'threat_intelligence': scanner.gather_threat_intelligence(target)
                    }
                    scan_result = {
                        'target': target,
                        'scan_type': 'network',
                        'scan_results': network_scan,
                        'vulnerabilities': []
                    }
                
                results.append(scan_result)
            except Exception as e:
                results.append({
                    'target': target,
                    'error': str(e),
                    'status': 'failed'
                })
        
        # Generate comprehensive report
        total_vulnerabilities = sum(len(r.get('vulnerabilities', [])) for r in results)
        
        penetration_test_report = {
            'id': str(uuid.uuid4()),
            'test_date': datetime.now().isoformat(),
            'scope': test_scope,
            'targets_tested': len(targets),
            'total_vulnerabilities': total_vulnerabilities,
            'results': results,
            'status': 'completed'
        }
        
        return jsonify({
            'success': True,
            'penetration_test_report': penetration_test_report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/website/generate-report/<scan_id>')
def generate_website_report(scan_id):
    try:
        # This would typically fetch from a database
        # For now, we'll create a sample report
        scan_report = {
            'id': scan_id,
            'website_url': 'https://example.com',
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'cvss_score': '8.5',
                    'description': 'SQL injection vulnerability found in login form'
                },
                {
                    'type': 'XSS',
                    'severity': 'Medium',
                    'cvss_score': '6.1',
                    'description': 'Cross-site scripting vulnerability in search functionality'
                }
            ]
        }
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#a78bfa')
        )
        story.append(Paragraph("Cyber AI - Website Security Report", title_style))
        story.append(Spacer(1, 20))
        
        # Website info
        website_data = [
            ['Website URL:', scan_report['website_url']],
            ['Scan Date:', scan_report['scan_date']],
            ['Vulnerabilities Found:', str(len(scan_report['vulnerabilities']))]
        ]
        
        website_table = Table(website_data, colWidths=[2*inch, 4*inch])
        website_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f4ff')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
        ]))
        
        story.append(website_table)
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        story.append(Paragraph("Security Vulnerabilities", styles['Heading2']))
        
        vuln_data = [['Type', 'Severity', 'CVSS Score', 'Description']]
        for vuln in scan_report['vulnerabilities']:
            vuln_data.append([
                vuln['type'],
                vuln['severity'],
                vuln['cvss_score'],
                vuln['description']
            ])
        
        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 1*inch, 3*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#a78bfa')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(vuln_table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"website_security_report_{scan_id}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def research_vulnerability(description):
    """Research vulnerability using web search and LLM knowledge"""
    try:
        # Check if Gemini API key is configured
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key or api_key == 'your-gemini-api-key-here':
            return f"Basic vulnerability analysis for: {description}. This appears to be a potential security issue that should be investigated further. Consider checking for common vulnerabilities like injection flaws, authentication bypass, or privilege escalation."
        
        # Use Gemini to research the vulnerability
        research_prompt = f"""
        Research the following cybersecurity vulnerability and provide detailed information:
        
        Vulnerability Description: {description}
        
        Please provide:
        1. Vulnerability type and classification
        2. Common attack vectors
        3. Potential impact and severity
        4. Known exploits and proof-of-concepts
        5. CVSS score estimation
        6. Remediation strategies
        7. Relevant CVE numbers if applicable
        8. References and documentation
        
        Format the response as structured data.
        """
        
        response = model.generate_content(research_prompt)
        return response.text
        
    except Exception as e:
        return f"Research completed for: {description}. Analysis suggests this is a potential security vulnerability that requires immediate attention and proper remediation."

def generate_vulnerability_assessment(description, research):
    """Generate comprehensive vulnerability assessment"""
    try:
        assessment_prompt = f"""
        Based on the vulnerability description and research, generate a comprehensive vulnerability assessment:
        
        Description: {description}
        Research: {research}
        
        Provide a JSON response with:
        - title: Clear vulnerability title
        - severity: Critical/High/Medium/Low
        - cvss_score: CVSS score (0.0-10.0)
        - exploit_details: How to exploit this vulnerability
        - reproduction_steps: Step-by-step reproduction
        - remediation: How to fix/mitigate
        - references: Array of reference URLs
        
        Return only valid JSON.
        """
        
        response = model.generate_content(assessment_prompt)
        return json.loads(response.text)
        
    except Exception as e:
        return {
            'title': 'Assessment Error',
            'severity': 'Unknown',
            'cvss_score': 'N/A',
            'exploit_details': f'Error generating assessment: {str(e)}',
            'reproduction_steps': 'Unable to generate',
            'remediation': 'Contact security team',
            'references': []
        }

def generate_final_report(penetration_test):
    """Generate final penetration test report"""
    try:
        report_prompt = f"""
        Generate a comprehensive penetration test report based on the following data:
        
        Test Name: {penetration_test['name']}
        Start Date: {penetration_test['start_date']}
        Vulnerabilities Found: {len(penetration_test['vulnerabilities'])}
        
        Create a professional penetration test report including:
        1. Executive Summary
        2. Methodology
        3. Vulnerability Summary
        4. Detailed Findings
        5. Risk Assessment
        6. Recommendations
        7. Conclusion
        
        Format as a structured report.
        """
        
        response = model.generate_content(report_prompt)
        return {
            'report_content': response.text,
            'test_data': penetration_test,
            'generated_at': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'report_content': f'Error generating report: {str(e)}',
            'test_data': penetration_test,
            'generated_at': datetime.now().isoformat()
        }

# Vercel serverless function handler
def handler(request):
    """Vercel serverless function handler"""
    return app(request.environ, lambda *args: None)

if __name__ == '__main__':
    # Run on HTTP for development (Chrome will show "Not Secure" but it's fine for localhost)
    app.run(debug=True, host='127.0.0.1', port=5000)
