// Cyber AI Application JavaScript

class CyberAI {
    constructor() {
        this.currentTest = null;
        this.vulnerabilities = [];
        this.testStartTime = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadVulnerabilities();
        this.updateDashboard();
        this.startTestTimer();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // If it's an external link (like website-test), let it navigate normally
                if (item.getAttribute('href') && !item.dataset.section) {
                    return; // Allow default navigation
                }
                e.preventDefault();
                this.switchSection(item.dataset.section);
            });
        });

        // Test controls
        document.getElementById('startTestBtn').addEventListener('click', () => {
            this.startPenetrationTest();
        });

        document.getElementById('endTestBtn').addEventListener('click', () => {
            this.endPenetrationTest();
        });

        // Chat input
        document.getElementById('chatInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });

        // Modal close on outside click
        document.getElementById('assessmentModal').addEventListener('click', (e) => {
            if (e.target.id === 'assessmentModal') {
                this.closeAssessmentModal();
            }
        });
    }

    switchSection(sectionId) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');

        // Update content
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(sectionId).classList.add('active');

            // Update page title
            const titles = {
                dashboard: 'Dashboard',
                vulnerabilities: 'Vulnerabilities',
                assessment: 'Assessment',
                reports: 'Reports',
                cybersage: 'CyberSage',
                'network-scan': 'Network Scan',
                'automated-test': 'Automated Testing',
                'vulnerability-scan': 'Vulnerability Scan'
            };
        document.getElementById('pageTitle').textContent = titles[sectionId];
    }

    async startPenetrationTest() {
        try {
            const response = await fetch('/api/penetration-test/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: `Penetration Test ${new Date().toLocaleString()}`
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.currentTest = data.test;
                this.testStartTime = new Date();
                this.updateTestStatus('active');
                this.updateTestControls(true);
                this.showNotification('Penetration test started successfully', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error starting test: ${error.message}`, 'error');
        }
    }

    async endPenetrationTest() {
        try {
            const response = await fetch('/api/penetration-test/end', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();
            
            if (data.success) {
                this.currentTest = null;
                this.testStartTime = null;
                this.updateTestStatus('inactive');
                this.updateTestControls(false);
                this.showNotification('Penetration test ended successfully', 'success');
                
                // Show final report
                if (data.final_report) {
                    this.showFinalReport(data.final_report);
                }
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error ending test: ${error.message}`, 'error');
        }
    }

    updateTestStatus(status) {
        const statusElement = document.getElementById('testStatus');
        statusElement.textContent = status === 'active' ? 'Active' : 'Inactive';
        statusElement.className = `status-indicator ${status}`;
    }

    updateTestControls(testActive) {
        const startBtn = document.getElementById('startTestBtn');
        const endBtn = document.getElementById('endTestBtn');
        
        startBtn.disabled = testActive;
        endBtn.disabled = !testActive;
    }

    async assessVulnerability() {
        const description = document.getElementById('vulnDescription').value.trim();
        
        if (!description) {
            this.showNotification('Please enter a vulnerability description', 'error');
            return;
        }

        this.showLoading(true);

        try {
            const response = await fetch('/api/vulnerability/assess', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ description })
            });

            const data = await response.json();
            
            if (data.success) {
                this.vulnerabilities.push(data.report);
                this.displayAdvancedAssessmentResult(data.report);
                this.updateDashboard();
                this.loadVulnerabilities();
                this.showNotification('Vulnerability analyzed with AI agents successfully!', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error assessing vulnerability: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayAdvancedAssessmentResult(report) {
        const resultDiv = document.getElementById('assessmentResult');
        resultDiv.style.display = 'block';
        
        resultDiv.innerHTML = `
            <div class="vulnerability-card ${report.severity.toLowerCase()}">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">${report.title}</div>
                        <div class="vuln-severity ${report.severity.toLowerCase()}">${report.severity}</div>
                    </div>
                    <div class="agent-badges">
                        <span class="agent-badge research">🔍 Research</span>
                        <span class="agent-badge assess">📊 Assess</span>
                        <span class="agent-badge remediate">🛠️ Remediate</span>
                        <span class="agent-badge report">📋 Report</span>
                    </div>
                </div>
                <div class="vuln-description">${report.description}</div>
                <div class="vuln-details">
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">CVSS Score</div>
                        <div class="vuln-detail-value">${report.cvss_score}</div>
                    </div>
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">OWASP Category</div>
                        <div class="vuln-detail-value">${report.owasp_category || 'N/A'}</div>
                    </div>
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">Status</div>
                        <div class="vuln-detail-value">${report.status}</div>
                    </div>
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">Timestamp</div>
                        <div class="vuln-detail-value">${new Date(report.timestamp).toLocaleString()}</div>
                    </div>
                </div>
                
                ${report.cve_references && report.cve_references.length > 0 ? `
                    <div class="vuln-detail" style="margin-top: 16px;">
                        <div class="vuln-detail-label">CVE References</div>
                        <div class="vuln-detail-value">
                            ${report.cve_references.map(cve => `<span class="cve-badge">${cve}</span>`).join(' ')}
                        </div>
                    </div>
                ` : ''}
                
                ${report.exploit_details ? `
                    <div class="vuln-detail" style="margin-top: 16px;">
                        <div class="vuln-detail-label">Research Findings</div>
                        <div class="vuln-detail-value">${report.exploit_details.substring(0, 300)}...</div>
                    </div>
                ` : ''}
                
                ${report.technical_details ? `
                    <div class="vuln-detail" style="margin-top: 16px;">
                        <div class="vuln-detail-label">Technical Analysis</div>
                        <div class="vuln-detail-value">${report.technical_details.substring(0, 300)}...</div>
                    </div>
                ` : ''}
                
                ${report.remediation ? `
                    <div class="vuln-detail" style="margin-top: 16px;">
                        <div class="vuln-detail-label">Remediation Strategy</div>
                        <div class="vuln-detail-value">${report.remediation.substring(0, 300)}...</div>
                    </div>
                ` : ''}
                
                <div class="vuln-actions">
                    <button class="btn-primary btn-sm" onclick="downloadVulnReport('${report.id}')">
                        <i class="fas fa-download"></i> Download PDF
                    </button>
                    <button class="btn-secondary btn-sm" onclick="viewFullReport('${report.id}')">
                        <i class="fas fa-eye"></i> View Full Report
                    </button>
                </div>
            </div>
        `;
    }

    async loadVulnerabilities() {
        try {
            const response = await fetch('/api/vulnerability/reports');
            const data = await response.json();
            
            if (data.success) {
                this.vulnerabilities = data.reports;
                this.displayVulnerabilities();
            }
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
        }
    }

    displayVulnerabilities() {
        const container = document.getElementById('vulnerabilitiesList');
        
        if (this.vulnerabilities.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-bug"></i>
                    <p>No vulnerabilities identified yet</p>
                    <p>Start your penetration test to begin identifying vulnerabilities</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.vulnerabilities.map(vuln => `
            <div class="vulnerability-card ${vuln.severity.toLowerCase()}">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">${vuln.title}</div>
                        <div class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
                    </div>
                </div>
                <div class="vuln-description">${vuln.description}</div>
                <div class="vuln-details">
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">CVSS Score</div>
                        <div class="vuln-detail-value">${vuln.cvss_score}</div>
                    </div>
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">Status</div>
                        <div class="vuln-detail-value">${vuln.status}</div>
                    </div>
                    <div class="vuln-detail">
                        <div class="vuln-detail-label">Timestamp</div>
                        <div class="vuln-detail-value">${new Date(vuln.timestamp).toLocaleString()}</div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    updateDashboard() {
        const totalVulns = this.vulnerabilities.length;
        const criticalVulns = this.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length;
        const highVulns = this.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length;
        
        document.getElementById('totalVulnerabilities').textContent = totalVulns;
        document.getElementById('criticalVulns').textContent = criticalVulns;
        document.getElementById('highVulns').textContent = highVulns;
        
        // Update recent vulnerabilities
        this.updateRecentVulnerabilities();
    }

    updateRecentVulnerabilities() {
        const container = document.getElementById('recentVulnsList');
        const recentVulns = this.vulnerabilities.slice(-5).reverse();
        
        if (recentVulns.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <p>No vulnerabilities found yet</p>
                    <p>Start by identifying a potential vulnerability</p>
                </div>
            `;
            return;
        }

        container.innerHTML = recentVulns.map(vuln => `
            <div class="vulnerability-card ${vuln.severity.toLowerCase()}">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">${vuln.title}</div>
                        <div class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
                    </div>
                </div>
                <div class="vuln-description">${vuln.description}</div>
            </div>
        `).join('');
    }

    startTestTimer() {
        setInterval(() => {
            if (this.testStartTime) {
                const now = new Date();
                const diff = now - this.testStartTime;
                const hours = Math.floor(diff / (1000 * 60 * 60));
                const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                document.getElementById('testDuration').textContent = `${hours}h ${minutes}m`;
            }
        }, 1000);
    }

    async sendMessage() {
        const input = document.getElementById('chatInput');
        const message = input.value.trim();
        
        if (!message) return;

        // Add user message to chat
        this.addMessageToChat(message, 'user');
        input.value = '';

        try {
            const response = await fetch('/api/cybersage/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message })
            });

            const data = await response.json();
            
            if (data.success) {
                this.addMessageToChat(data.response, 'bot');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.addMessageToChat(`Sorry, I encountered an error: ${error.message}`, 'bot');
        }
    }

    addMessageToChat(message, sender) {
        const chatMessages = document.getElementById('chatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;
        
        const avatar = sender === 'bot' ? 'fas fa-robot' : 'fas fa-user';
        
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="${avatar}"></i>
            </div>
            <div class="message-content">
                <p>${message}</p>
            </div>
        `;
        
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    showAssessmentModal() {
        document.getElementById('assessmentModal').classList.add('active');
    }

    closeAssessmentModal() {
        document.getElementById('assessmentModal').classList.remove('active');
        document.getElementById('modalVulnDescription').value = '';
    }

    async assessVulnerabilityFromModal() {
        const description = document.getElementById('modalVulnDescription').value.trim();
        
        if (!description) {
            this.showNotification('Please enter a vulnerability description', 'error');
            return;
        }

        this.closeAssessmentModal();
        
        // Set the description in the main form and assess
        document.getElementById('vulnDescription').value = description;
        await this.assessVulnerability();
    }

    clearForm() {
        document.getElementById('vulnDescription').value = '';
        document.getElementById('assessmentResult').style.display = 'none';
    }

    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        overlay.classList.toggle('active', show);
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 3000;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;
        
        const colors = {
            success: '#48bb78',
            error: '#e53e3e',
            info: '#667eea'
        };
        
        notification.style.backgroundColor = colors[type] || colors.info;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 5000);
    }

    showFinalReport(report) {
        // This would show a modal or new page with the final report
        console.log('Final report generated:', report);
        this.showNotification('Final penetration test report generated', 'success');
    }

    async startNetworkScan() {
        const target = document.getElementById('networkTarget').value.trim();
        const scanType = document.getElementById('scanType').value;
        
        if (!target) {
            this.showNotification('Please enter a target IP or domain', 'error');
            return;
        }

        this.showLoading(true, 'Starting network scan...');

        try {
            const response = await fetch('/api/network/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.displayNetworkResults(data.scan_report);
                this.showNotification('Network scan completed successfully!', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error during network scan: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayNetworkResults(scanReport) {
        const resultsDiv = document.getElementById('networkResults');
        resultsDiv.style.display = 'block';
        
        resultsDiv.innerHTML = `
            <div class="scan-result-card">
                <div class="scan-header">
                    <h3>Network Scan Results</h3>
                    <div class="scan-meta">
                        <span class="scan-date">${new Date(scanReport.scan_date).toLocaleString()}</span>
                        <span class="scan-type">${scanReport.scan_type}</span>
                    </div>
                </div>
                
                <div class="scan-details">
                    <div class="detail-section">
                        <h4>Target Information</h4>
                        <p><strong>Target:</strong> ${scanReport.target}</p>
                        <p><strong>Scan Type:</strong> ${scanReport.scan_type}</p>
                        <p><strong>Status:</strong> ${scanReport.status}</p>
                    </div>
                    
                    ${scanReport.open_ports && scanReport.open_ports.length > 0 ? `
                        <div class="detail-section">
                            <h4>Open Ports (${scanReport.open_ports.length})</h4>
                            <div class="ports-list">
                                ${scanReport.open_ports.map(port => `
                                    <div class="port-item">
                                        <span class="port-number">${port.port}</span>
                                        <span class="port-service">${port.service}</span>
                                        <span class="port-status">${port.status}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                    
                    ${scanReport.dns_info && Object.keys(scanReport.dns_info).length > 0 ? `
                        <div class="detail-section">
                            <h4>DNS Information</h4>
                            ${Object.entries(scanReport.dns_info).map(([type, records]) => `
                                <div class="dns-record">
                                    <strong>${type}:</strong> ${Array.isArray(records) ? records.join(', ') : records}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                    
                    ${scanReport.subdomains && scanReport.subdomains.length > 0 ? `
                        <div class="detail-section">
                            <h4>Subdomains Found (${scanReport.subdomains.length})</h4>
                            <div class="subdomains-list">
                                ${scanReport.subdomains.map(sub => `
                                    <div class="subdomain-item">
                                        <span class="subdomain-name">${sub.subdomain}.${scanReport.target}</span>
                                        <span class="subdomain-status">${sub.status_code}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    async startAutomatedTest() {
        const targetsText = document.getElementById('testTargets').value.trim();
        const testScope = document.getElementById('testScope').value;
        
        if (!targetsText) {
            this.showNotification('Please enter at least one target', 'error');
            return;
        }

        const targets = targetsText.split('\n').filter(t => t.trim());
        
        this.showLoading(true, 'Starting automated penetration test...');

        try {
            const response = await fetch('/api/penetration-test/automated', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    targets: targets,
                    scope: testScope
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.displayAutomatedResults(data.penetration_test_report);
                this.showNotification('Automated penetration test completed!', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error during automated test: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async startVulnerabilityScan() {
        const target = document.getElementById('vulnTarget').value.trim();
        const scanType = document.getElementById('vulnScanType').value;
        
        if (!target) {
            this.showNotification('Please enter a target URL or IP', 'error');
            return;
        }

        this.showLoading(true, 'Starting advanced vulnerability scan...');

        try {
            const response = await fetch('/api/vulnerability/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.displayVulnerabilityResults(data.vulnerability_report);
                this.showNotification('Vulnerability scan completed!', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error during vulnerability scan: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayVulnerabilityResults(vulnReport) {
        const resultsDiv = document.getElementById('vulnResults');
        resultsDiv.style.display = 'block';
        
        const webVulns = vulnReport.web_scan?.vulnerabilities || [];
        const networkVulns = vulnReport.network_scan?.vulnerabilities || [];
        const allVulns = [...webVulns, ...networkVulns];
        
        resultsDiv.innerHTML = `
            <div class="scan-result-card">
                <div class="scan-header">
                    <h3>🛡️ Vulnerability Scan Results</h3>
                    <div class="scan-info">
                        <span class="scan-meta">Target: ${vulnReport.target}</span>
                        <span class="scan-meta">Type: ${vulnReport.scan_type}</span>
                        <span class="scan-meta">Date: ${new Date(vulnReport.scan_date).toLocaleString()}</span>
                    </div>
                </div>
                
                <div class="vulnerability-summary">
                    <h4>📊 Summary</h4>
                    <div class="summary-stats">
                        <div class="stat-item">
                            <span class="stat-label">Total Vulnerabilities:</span>
                            <span class="stat-value critical">${vulnReport.total_vulnerabilities}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Critical:</span>
                            <span class="stat-value critical">${allVulns.filter(v => v.severity === 'Critical').length}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">High:</span>
                            <span class="stat-value high">${allVulns.filter(v => v.severity === 'High').length}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Medium:</span>
                            <span class="stat-value medium">${allVulns.filter(v => v.severity === 'Medium').length}</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Low:</span>
                            <span class="stat-value low">${allVulns.filter(v => v.severity === 'Low').length}</span>
                        </div>
                    </div>
                </div>
                
                ${allVulns.length > 0 ? `
                <div class="vulnerabilities-list">
                    <h4>🔍 Vulnerabilities Found</h4>
                    ${allVulns.map(vuln => `
                        <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
                            <div class="vuln-header">
                                <h5>${vuln.type}</h5>
                                <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                            </div>
                            <p class="vuln-description">${vuln.description}</p>
                            <div class="vuln-details">
                                <p><strong>CVSS Score:</strong> ${vuln.cvss_score || 'N/A'}</p>
                                <p><strong>Recommendation:</strong> ${vuln.recommendation || 'No specific recommendation available'}</p>
                                ${vuln.evidence ? `<p><strong>Evidence:</strong> ${JSON.stringify(vuln.evidence)}</p>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
                ` : '<p class="no-vulns">✅ No vulnerabilities found!</p>'}
                
                <div class="scan-actions">
                    <button class="btn-secondary" onclick="downloadVulnerabilityReport('${vulnReport.id}')">
                        <i class="fas fa-download"></i>
                        Download Report
                    </button>
                </div>
            </div>
        `;
    }

    displayAutomatedResults(testReport) {
        const resultsDiv = document.getElementById('automatedResults');
        resultsDiv.style.display = 'block';
        
        resultsDiv.innerHTML = `
            <div class="test-result-card">
                <div class="test-header">
                    <h3>Automated Penetration Test Results</h3>
                    <div class="test-meta">
                        <span class="test-date">${new Date(testReport.test_date).toLocaleString()}</span>
                        <span class="test-scope">${testReport.scope}</span>
                    </div>
                </div>
                
                <div class="test-summary">
                    <div class="summary-stats">
                        <div class="stat-item">
                            <span class="stat-number">${testReport.targets_tested}</span>
                            <span class="stat-label">Targets Tested</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${testReport.total_vulnerabilities}</span>
                            <span class="stat-label">Vulnerabilities Found</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${testReport.status}</span>
                            <span class="stat-label">Status</span>
                        </div>
                    </div>
                </div>
                
                <div class="test-results">
                    <h4>Individual Target Results</h4>
                    ${testReport.results.map((result, index) => `
                        <div class="target-result">
                            <div class="target-header">
                                <h5>Target ${index + 1}: ${result.target || result.website_url || 'Unknown'}</h5>
                                <span class="target-status ${result.status || 'completed'}">${result.status || 'completed'}</span>
                            </div>
                            
                            ${result.vulnerabilities && result.vulnerabilities.length > 0 ? `
                                <div class="vulnerabilities-summary">
                                    <p><strong>Vulnerabilities Found:</strong> ${result.vulnerabilities.length}</p>
                                    <div class="vuln-list">
                                        ${result.vulnerabilities.slice(0, 3).map(vuln => `
                                            <div class="vuln-item ${vuln.severity?.toLowerCase() || 'medium'}">
                                                <span class="vuln-type">${vuln.type || 'Security Issue'}</span>
                                                <span class="vuln-severity">${vuln.severity || 'Medium'}</span>
                                            </div>
                                        `).join('')}
                                        ${result.vulnerabilities.length > 3 ? `<p>... and ${result.vulnerabilities.length - 3} more</p>` : ''}
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${result.open_ports && result.open_ports.length > 0 ? `
                                <div class="ports-summary">
                                    <p><strong>Open Ports:</strong> ${result.open_ports.length}</p>
                                    <div class="ports-list">
                                        ${result.open_ports.slice(0, 5).map(port => `
                                            <span class="port-tag">${port.port}/${port.service}</span>
                                        `).join('')}
                                        ${result.open_ports.length > 5 ? `<span class="more-ports">+${result.open_ports.length - 5} more</span>` : ''}
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${result.error ? `
                                <div class="error-message">
                                    <p><strong>Error:</strong> ${result.error}</p>
                                </div>
                            ` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
}

// Global functions for HTML onclick handlers
function showAssessmentModal() {
    window.cyberAI.showAssessmentModal();
}

function assessVulnerability() {
    window.cyberAI.assessVulnerability();
}

function assessVulnerabilityFromModal() {
    window.cyberAI.assessVulnerabilityFromModal();
}

function closeAssessmentModal() {
    window.cyberAI.closeAssessmentModal();
}

function clearForm() {
    window.cyberAI.clearForm();
}

function sendMessage() {
    window.cyberAI.sendMessage();
}

async function downloadVulnReport(reportId) {
    try {
        const response = await fetch(`/api/reports/generate-pdf/${reportId}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vulnerability_report_${reportId}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            window.cyberAI.showNotification('PDF report downloaded successfully!', 'success');
        } else {
            throw new Error('Failed to generate PDF');
        }
    } catch (error) {
        window.cyberAI.showNotification(`Error downloading PDF: ${error.message}`, 'error');
    }
}

async function generateFinalReport() {
    try {
        const response = await fetch('/api/reports/generate-final-pdf');
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `penetration_test_report_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            window.cyberAI.showNotification('Final penetration test report downloaded!', 'success');
        } else {
            throw new Error('Failed to generate final report');
        }
    } catch (error) {
        window.cyberAI.showNotification(`Error generating final report: ${error.message}`, 'error');
    }
}

function viewFullReport(reportId) {
    const report = window.cyberAI.vulnerabilities.find(v => v.id === reportId);
    if (report) {
        // Create a modal to display the full report
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 800px; max-height: 90vh; overflow-y: auto;">
                <div class="modal-header">
                    <h3>Full Vulnerability Report</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="full-report">
                        <h4>Executive Summary</h4>
                        <p>${report.executive_summary || 'No executive summary available'}</p>
                        
                        <h4>Technical Analysis</h4>
                        <p>${report.technical_details || 'No technical details available'}</p>
                        
                        <h4>Research Findings</h4>
                        <p>${report.exploit_details || 'No research findings available'}</p>
                        
                        <h4>Remediation Strategy</h4>
                        <p>${report.remediation || 'No remediation strategy available'}</p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-primary" onclick="downloadVulnReport('${reportId}')">
                        <i class="fas fa-download"></i> Download PDF
                    </button>
                    <button class="btn-secondary" onclick="this.closest('.modal').remove()">
                        Close
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
}

function generateVulnReport() {
    window.cyberAI.showNotification('Use the individual vulnerability download buttons for specific reports', 'info');
}

function startNetworkScan() {
    window.cyberAI.startNetworkScan();
}

function startAutomatedTest() {
    window.cyberAI.startAutomatedTest();
}

function startVulnerabilityScan() {
    window.cyberAI.startVulnerabilityScan();
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.cyberAI = new CyberAI();
});
