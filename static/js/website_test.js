// Website Security Testing JavaScript

class WebsiteSecurityTester {
    constructor() {
        this.currentScan = null;
        this.scanResults = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.updateScanStatus('ready');
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Check if it's the back button (no data-section attribute)
                if (!item.dataset.section) {
                    // Allow default navigation for external links
                    return;
                }
                e.preventDefault();
                this.switchSection(item.dataset.section);
            });
        });

        // Scan controls
        document.getElementById('startScanBtn').addEventListener('click', () => {
            this.startWebsiteScan();
        });

        document.getElementById('stopScanBtn').addEventListener('click', () => {
            this.stopWebsiteScan();
        });

        // Chat input
        document.getElementById('chatInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
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
            'website-scan': 'Website Scan',
            'scan-results': 'Scan Results',
            reports: 'Reports',
            cybersage: 'CyberSage'
        };
        document.getElementById('pageTitle').textContent = titles[sectionId] || 'Website Security Testing';
    }

    async startWebsiteScan() {
        const websiteUrl = document.getElementById('websiteUrl').value.trim();
        
        if (!websiteUrl) {
            this.showNotification('Please enter a website URL', 'error');
            return;
        }

        this.showLoading(true);
        this.updateScanStatus('scanning');
        this.showScanProgress(true);

        try {
            const response = await fetch('/api/website/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: websiteUrl })
            });

            const data = await response.json();
            
            if (data.success) {
                this.currentScan = data.scan_report;
                this.scanResults.push(data.scan_report);
                this.displayScanResults(data.scan_report);
                this.updateScanStatus('completed');
                this.showNotification('Website security scan completed successfully!', 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            this.showNotification(`Error scanning website: ${error.message}`, 'error');
            this.updateScanStatus('error');
        } finally {
            this.showLoading(false);
            this.showScanProgress(false);
        }
    }

    displayScanResults(scanReport) {
        const resultsDiv = document.getElementById('scanResultsList');
        
        if (this.scanResults.length === 0) {
            resultsDiv.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-alt"></i>
                    <p>No scan results yet</p>
                    <p>Start a website scan to see security analysis results</p>
                </div>
            `;
            return;
        }

        resultsDiv.innerHTML = this.scanResults.map(scan => `
            <div class="scan-result-card">
                <div class="scan-header">
                    <div class="scan-info">
                        <h3>${scan.website_url}</h3>
                        <div class="scan-meta">
                            <span class="scan-date">${new Date(scan.scan_date).toLocaleString()}</span>
                            <span class="vuln-count">${scan.vulnerabilities_found} vulnerabilities found</span>
                        </div>
                    </div>
                    <div class="scan-status">
                        <span class="status-badge ${scan.status}">${scan.status}</span>
                    </div>
                </div>
                
                <div class="vulnerabilities-list">
                    ${scan.vulnerabilities.map(vuln => `
                        <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
                            <div class="vuln-header">
                                <span class="vuln-type">${vuln.type}</span>
                                <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                            </div>
                            <div class="vuln-description">${vuln.description}</div>
                            <div class="vuln-details">
                                <span class="cvss-score">CVSS: ${vuln.cvss_score}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div class="scan-actions">
                    <button class="btn-primary btn-sm" onclick="downloadWebsiteReport('${scan.id}')">
                        <i class="fas fa-download"></i> Download Report
                    </button>
                    <button class="btn-secondary btn-sm" onclick="viewScanDetails('${scan.id}')">
                        <i class="fas fa-eye"></i> View Details
                    </button>
                </div>
            </div>
        `).join('');
    }

    showScanProgress(show) {
        const progressDiv = document.getElementById('scanProgress');
        progressDiv.style.display = show ? 'block' : 'none';
        
        if (show) {
            this.animateProgress();
        }
    }

    animateProgress() {
        const progressFill = document.getElementById('progressFill');
        let width = 0;
        const interval = setInterval(() => {
            if (width >= 100) {
                clearInterval(interval);
                return;
            }
            width += 2;
            progressFill.style.width = width + '%';
        }, 100);
    }

    updateScanStatus(status) {
        const statusElement = document.getElementById('scanStatus');
        const startBtn = document.getElementById('startScanBtn');
        const stopBtn = document.getElementById('stopScanBtn');
        
        statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        statusElement.className = `status-indicator ${status}`;
        
        startBtn.disabled = status === 'scanning';
        stopBtn.disabled = status !== 'scanning';
    }

    stopWebsiteScan() {
        this.updateScanStatus('stopped');
        this.showScanProgress(false);
        this.showNotification('Website scan stopped', 'info');
    }

    clearScanForm() {
        document.getElementById('websiteUrl').value = '';
        this.updateScanStatus('ready');
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
            success: '#34d399',
            error: '#f87171',
            info: '#a78bfa'
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
}

// Global functions for HTML onclick handlers
function startWebsiteScan() {
    window.websiteTester.startWebsiteScan();
}

function stopWebsiteScan() {
    window.websiteTester.stopWebsiteScan();
}

function clearScanForm() {
    window.websiteTester.clearScanForm();
}

function sendMessage() {
    window.websiteTester.sendMessage();
}

async function downloadWebsiteReport(scanId) {
    try {
        const response = await fetch(`/api/website/generate-report/${scanId}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `website_security_report_${scanId}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            window.websiteTester.showNotification('Website security report downloaded!', 'success');
        } else {
            throw new Error('Failed to generate report');
        }
    } catch (error) {
        window.websiteTester.showNotification(`Error downloading report: ${error.message}`, 'error');
    }
}

function viewScanDetails(scanId) {
    const scan = window.websiteTester.scanResults.find(s => s.id === scanId);
    if (scan) {
        // Create a modal to display scan details
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 900px; max-height: 90vh; overflow-y: auto;">
                <div class="modal-header">
                    <h3>Website Security Scan Details</h3>
                    <button class="modal-close" onclick="this.closest('.modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="scan-details">
                        <h4>Website: ${scan.website_url}</h4>
                        <p><strong>Scan Date:</strong> ${new Date(scan.scan_date).toLocaleString()}</p>
                        <p><strong>Vulnerabilities Found:</strong> ${scan.vulnerabilities_found}</p>
                        
                        <h4>Detailed Analysis</h4>
                        <div class="analysis-content">
                            ${scan.scan_results ? `<p>${scan.scan_results}</p>` : '<p>No detailed analysis available</p>'}
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-primary" onclick="downloadWebsiteReport('${scanId}')">
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

function generateWebsiteReport() {
    if (window.websiteTester.scanResults.length === 0) {
        window.websiteTester.showNotification('No scan results available to generate report', 'error');
        return;
    }
    
    // Generate report for the latest scan
    const latestScan = window.websiteTester.scanResults[window.websiteTester.scanResults.length - 1];
    downloadWebsiteReport(latestScan.id);
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.websiteTester = new WebsiteSecurityTester();
});
