
import React, { useState, useEffect } from 'react';
import '../styles/app.css';
import { Link } from 'react-router-dom';

function App() {
    const [currentTest, setCurrentTest] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [testStartTime, setTestStartTime] = useState(null);
    const [activeSection, setActiveSection] = useState('dashboard');
    const [loading, setLoading] = useState(false);
    const [modalOpen, setModalOpen] = useState(false);
    const [chatMessages, setChatMessages] = useState([
        {
            sender: 'bot',
            message: '🔒 **Welcome to CyberSage!**<br/>I\'m your expert cybersecurity consultant with 15+ years of experience in penetration testing, vulnerability assessment, and security architecture.<br/>I can help you with:<br/><ul><li>🛡️ Vulnerability analysis and remediation</li><li>🔍 Security testing methodologies</li><li>📊 Risk assessment and compliance</li><li>⚙️ Security tool recommendations</li><li>📋 Report generation and documentation</li></ul><p>How can I assist you with your security needs today?</p>'
        }
    ]);

    useEffect(() => {
        loadVulnerabilities();
        const timer = setInterval(() => {
            if (testStartTime) {
                const now = new Date();
                const diff = now - testStartTime;
                const hours = Math.floor(diff / (1000 * 60 * 60));
                const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                // Update UI with timer
            }
        }, 1000);
        return () => clearInterval(timer);
    }, [testStartTime]);

    const switchSection = (sectionId) => {
        setActiveSection(sectionId);
    };

    const startPenetrationTest = async () => {
        // API call to start test
    };

    const endPenetrationTest = async () => {
        // API call to end test
    };

    const assessVulnerability = async () => {
        // API call to assess vulnerability
    };

    const loadVulnerabilities = async () => {
        // API call to load vulnerabilities
    };

    const sendMessage = async () => {
        // API call to send chat message
    };

    return (
        <div className="app-container">
            {/* Sidebar */}
            <aside className="sidebar">
                <div className="sidebar-header">
                    <h2>Cyber AI</h2>
                    <p>Penetration Testing Platform</p>
                </div>

                <nav className="sidebar-nav">
                    <a href="#dashboard" className={`nav-item ${activeSection === 'dashboard' ? 'active' : ''}`} onClick={() => switchSection('dashboard')}>
                        <i className="fas fa-tachometer-alt"></i>
                        <span>Dashboard</span>
                    </a>
                    <a href="#vulnerabilities" className={`nav-item ${activeSection === 'vulnerabilities' ? 'active' : ''}`} onClick={() => switchSection('vulnerabilities')}>
                        <i className="fas fa-bug"></i>
                        <span>Vulnerabilities</span>
                    </a>
                    <a href="#assessment" className={`nav-item ${activeSection === 'assessment' ? 'active' : ''}`} onClick={() => switchSection('assessment')}>
                        <i className="fas fa-search"></i>
                        <span>Assessment</span>
                    </a>
                    <a href="#reports" className={`nav-item ${activeSection === 'reports' ? 'active' : ''}`} onClick={() => switchSection('reports')}>
                        <i className="fas fa-file-alt"></i>
                        <span>Reports</span>
                    </a>
                    <a href="#cybersage" className={`nav-item ${activeSection === 'cybersage' ? 'active' : ''}`} onClick={() => switchSection('cybersage')}>
                        <i className="fas fa-robot"></i>
                        <span>CyberSage</span>
                    </a>
                    <Link to="/website-test" className="nav-item">
                        <i className="fas fa-globe"></i>
                        <span>Website Testing</span>
                    </Link>
                    <a href="#network-scan" className={`nav-item ${activeSection === 'network-scan' ? 'active' : ''}`} onClick={() => switchSection('network-scan')}>
                        <i className="fas fa-network-wired"></i>
                        <span>Network Scan</span>
                    </a>
                    <a href="#automated-test" className={`nav-item ${activeSection === 'automated-test' ? 'active' : ''}`} onClick={() => switchSection('automated-test')}>
                        <i className="fas fa-robot"></i>
                        <span>Automated Testing</span>
                    </a>
                    <a href="#vulnerability-scan" className={`nav-item ${activeSection === 'vulnerability-scan' ? 'active' : ''}`} onClick={() => switchSection('vulnerability-scan')}>
                        <i className="fas fa-bug"></i>
                        <span>Vulnerability Scan</span>
                    </a>
                </nav>

                <div className="sidebar-footer">
                    <div className="test-controls">
                        <button id="startTestBtn" className="btn-test-start" onClick={startPenetrationTest}>
                            <i className="fas fa-play"></i>
                            Start Test
                        </button>
                        <button id="endTestBtn" className="btn-test-end" onClick={endPenetrationTest} disabled>
                            <i className="fas fa-stop"></i>
                            End Test
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="main-content">
                {/* Header */}
                <header className="app-header">
                    <div className="header-left">
                        <h1 id="pageTitle">{activeSection.charAt(0).toUpperCase() + activeSection.slice(1)}</h1>
                        <p id="pageSubtitle">Overview of your penetration testing activities</p>
                    </div>
                    <div className="header-right">
                        <div className="test-status">
                            <span className="status-indicator" id="testStatus">Inactive</span>
                        </div>
                        <Link to="/" className="btn-back">
                            <i className="fas fa-arrow-left"></i>
                            Back to Home
                        </Link>
                    </div>
                </header>

                {/* Dashboard Section */}
                <section id="dashboard" className={`content-section ${activeSection === 'dashboard' ? 'active' : ''}`}>
                    <div className="stats-grid">
                        <div className="stat-card">
                            <div className="stat-icon">
                                <i className="fas fa-bug"></i>
                            </div>
                            <div className="stat-content">
                                <h3 id="totalVulnerabilities">0</h3>
                                <p>Vulnerabilities Found</p>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-icon critical">
                                <i className="fas fa-exclamation-triangle"></i>
                            </div>
                            <div className="stat-content">
                                <h3 id="criticalVulns">0</h3>
                                <p>Critical Issues</p>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-icon high">
                                <i className="fas fa-exclamation-circle"></i>
                            </div>
                            <div className="stat-content">
                                <h3 id="highVulns">0</h3>
                                <p>High Severity</p>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-icon">
                                <i className="fas fa-clock"></i>
                            </div>
                            <div className="stat-content">
                                <h3 id="testDuration">0h 0m</h3>
                                <p>Test Duration</p>
                            </div>
                        </div>
                    </div>

                    <div className="dashboard-content">
                        <div className="recent-vulnerabilities">
                            <h3>Recent Vulnerabilities</h3>
                            <div id="recentVulnsList" className="vuln-list">
                                <div className="empty-state">
                                    <i className="fas fa-search"></i>
                                    <p>No vulnerabilities found yet</p>
                                    <p>Start by identifying a potential vulnerability</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Vulnerabilities Section */}
                <section id="vulnerabilities" className={`content-section ${activeSection === 'vulnerabilities' ? 'active' : ''}`}>
                    <div className="section-header">
                    <h2>Vulnerability Management</h2>
                    <button className="btn-primary" onClick={() => setModalOpen(true)}>
                        <i className="fas fa-plus"></i>
                        Add Vulnerability
                    </button>
                </div>
                
                <div className="vulnerabilities-list" id="vulnerabilitiesList">
                    <div className="empty-state">
                        <i className="fas fa-bug"></i>
                        <p>No vulnerabilities identified yet</p>
                        <p>Start your penetration test to begin identifying vulnerabilities</p>
                    </div>
                </div>
                </section>

                {/* Assessment Section */}
                <section id="assessment" className={`content-section ${activeSection === 'assessment' ? 'active' : ''}`}>
                    <div className="assessment-container">
                    <h2>Vulnerability Assessment</h2>
                    <p>Describe a potential vulnerability and let AI analyze it</p>
                    
                    <div className="assessment-form">
                        <div className="form-group">
                            <label htmlFor="vulnDescription">Vulnerability Description</label>
                            <textarea 
                                id="vulnDescription" 
                                placeholder="Describe the potential vulnerability you've discovered..."
                                rows="6"
                            ></textarea>
                        </div>
                        
                        <div className="form-actions">
                            <button className="btn-primary" onClick={assessVulnerability}>
                                <i className="fas fa-search"></i>
                                Analyze Vulnerability
                            </button>
                            <button className="btn-secondary" onClick={() => document.getElementById('vulnDescription').value = ''}>
                                <i className="fas fa-times"></i>
                                Clear
                            </button>
                        </div>
                    </div>
                    
                    <div id="assessmentResult" className="assessment-result" style={{display: 'none'}}>
                        {/* Assessment results will be displayed here */}
                    </div>
                </div>
                </section>

                {/* Reports Section */}
                <section id="reports" className={`content-section ${activeSection === 'reports' ? 'active' : ''}`}>
                    <div className="reports-container">
                    <h2>Reports & Documentation</h2>
                    
                    <div className="reports-actions">
                        <button className="btn-primary" onClick={() => {}}>
                            <i className="fas fa-file-alt"></i>
                            Generate Vulnerability Report
                        </button>
                        <button className="btn-primary" onClick={() => {}}>
                            <i className="fas fa-file-pdf"></i>
                            Generate Final Report
                        </button>
                    </div>
                    
                    <div className="reports-list" id="reportsList">
                        <div className="empty-state">
                            <i className="fas fa-file-alt"></i>
                            <p>No reports generated yet</p>
                            <p>Generate reports after completing vulnerability assessments</p>
                        </div>
                    </div>
                </div>
                </section>

                {/* Network Scan Section */}
                <section id="network-scan" className={`content-section ${activeSection === 'network-scan' ? 'active' : ''}`}>
                    <div className="network-scan-container">
                    <h2>Network Security Scanning</h2>
                    <p>Perform comprehensive network reconnaissance and port scanning</p>
                    
                    <div className="scan-form">
                        <div className="form-group">
                            <label htmlFor="networkTarget">Target IP or Domain</label>
                            <input type="text" id="networkTarget" placeholder="192.168.1.1 or example.com" />
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="scanType">Scan Type</label>
                            <select id="scanType">
                                <option value="basic">Basic Scan</option>
                                <option value="comprehensive">Comprehensive Scan</option>
                                <option value="stealth">Stealth Scan</option>
                            </select>
                        </div>
                        
                        <div className="form-actions">
                            <button className="btn-primary" onClick={() => {}}>
                                <i className="fas fa-search"></i>
                                Start Network Scan
                            </button>
                        </div>
                    </div>
                    
                    <div id="networkResults" className="scan-results" style={{display: 'none'}}>
                        {/* Network scan results will be displayed here */}
                    </div>
                </div>
                </section>

                {/* Automated Testing Section */}
                <section id="automated-test" className={`content-section ${activeSection === 'automated-test' ? 'active' : ''}`}>
                    <div className="automated-test-container">
                    <h2>Automated Penetration Testing</h2>
                    <p>Run comprehensive automated security tests across multiple targets</p>
                    
                    <div className="test-form">
                        <div className="form-group">
                            <label htmlFor="testTargets">Targets (one per line)</label>
                            <textarea id="testTargets" rows="4" placeholder="https://example.com&#10;192.168.1.1&#10;subdomain.example.com"></textarea>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="testScope">Test Scope</label>
                            <select id="testScope">
                                <option value="comprehensive">Comprehensive</option>
                                <option value="web-only">Web Applications Only</option>
                                <option value="network-only">Network Only</option>
                                <option value="vulnerability-only">Vulnerability Scan Only</option>
                            </select>
                        </div>
                        
                        <div className="form-actions">
                            <button className="btn-primary" onClick={() => {}}>
                                <i className="fas fa-play"></i>
                                Start Automated Test
                            </button>
                        </div>
                    </div>
                    
                    <div id="automatedResults" className="test-results" style={{display: 'none'}}>
                        {/* Automated test results will be displayed here */}
                    </div>
                </div>
                </section>

                {/* Vulnerability Scan Section */}
                <section id="vulnerability-scan" className={`content-section ${activeSection === 'vulnerability-scan' ? 'active' : ''}`}>
                    <div className="vulnerability-scan-container">
                    <h2>Advanced Vulnerability Scanning</h2>
                    <p>Perform comprehensive vulnerability assessment using real cybersecurity tools and techniques</p>
                    
                    <div className="scan-form">
                        <div className="form-group">
                            <label htmlFor="vulnTarget">Target URL or IP</label>
                            <input type="text" id="vulnTarget" placeholder="https://example.com or 192.168.1.1" />
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="vulnScanType">Scan Type</label>
                            <select id="vulnScanType">
                                <option value="comprehensive">Comprehensive Scan</option>
                                <option value="web">Web Application Only</option>
                                <option value="network">Network Only</option>
                            </select>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="vulnOptions">Advanced Options</label>
                            <div className="options-grid">
                                <div className="option-item">
                                    <input type="checkbox" id="sqlInjection" defaultChecked />
                                    <label htmlFor="sqlInjection">SQL Injection Testing</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="xssTesting" defaultChecked />
                                    <label htmlFor="xssTesting">XSS Testing</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="csrfTesting" defaultChecked />
                                    <label htmlFor="csrfTesting">CSRF Testing</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="directoryTraversal" defaultChecked />
                                    <label htmlFor="directoryTraversal">Directory Traversal</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="commandInjection" defaultChecked />
                                    <label htmlFor="commandInjection">Command Injection</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="xxeTesting" defaultChecked />
                                    <label htmlFor="xxeTesting">XXE Testing</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="ssrfTesting" defaultChecked />
                                    <label htmlFor="ssrfTesting">SSRF Testing</label>
                                </div>
                                <div className="option-item">
                                    <input type="checkbox" id="portScanning" defaultChecked />
                                    <label htmlFor="portScanning">Port Scanning</label>
                                </div>
                            </div>
                        </div>
                        
                        <div className="form-actions">
                            <button className="btn-primary" onClick={() => {}}>
                                <i className="fas fa-shield-alt"></i>
                                Start Vulnerability Scan
                            </button>
                        </div>
                    </div>
                    
                    <div id="vulnResults" className="scan-results" style={{display: 'none'}}>
                        {/* Vulnerability scan results will be displayed here */}
                    </div>
                </div>
                </section>

                {/* CyberSage Section */}
                <section id="cybersage" className={`content-section ${activeSection === 'cybersage' ? 'active' : ''}`}>
                    <div className="cybersage-container">
                        <div className="cybersage-header">
                            <h2>CyberSage Assistant</h2>
                            <p>Your expert cybersecurity consultant</p>
                        </div>

                        <div className="chat-container">
                            <div className="chat-messages" id="chatMessages">
                                {chatMessages.map((msg, index) => (
                                    <div key={index} className={`message ${msg.sender}-message`}>
                                        <div className="message-avatar">
                                            <i className={`fas ${msg.sender === 'bot' ? 'fa-robot' : 'fa-user'}`}></i>
                                        </div>
                                        <div className="message-content" dangerouslySetInnerHTML={{ __html: msg.message }}></div>
                                    </div>
                                ))}
                            </div>

                            <div className="chat-input">
                                <input type="text" id="chatInput" placeholder="Ask me anything about cybersecurity..." />
                                <button onClick={sendMessage}>
                                    <i className="fas fa-paper-plane"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </section>
            </main>

            {/* Assessment Modal */}
            <div id="assessmentModal" className={`modal ${modalOpen ? 'active' : ''}`}>
                <div id="assessmentModal" className={`modal ${modalOpen ? 'active' : ''}`}>
                <div className="modal-content">
                    <div className="modal-header">
                        <h3>Add New Vulnerability</h3>
                        <button className="modal-close" onClick={() => setModalOpen(false)}>
                            <i className="fas fa-times"></i>
                        </button>
                    </div>
                    <div className="modal-body">
                        <div className="form-group">
                            <label htmlFor="modalVulnDescription">Vulnerability Description</label>
                            <textarea 
                                id="modalVulnDescription" 
                                placeholder="Describe the potential vulnerability..."
                                rows="6"
                            ></textarea>
                        </div>
                    </div>
                    <div className="modal-footer">
                        <button className="btn-secondary" onClick={() => setModalOpen(false)}>Cancel</button>
                        <button className="btn-primary" onClick={assessVulnerability}>Analyze</button>
                    </div>
                </div>
            </div>
            </div>

            {/* Loading Overlay */}
            <div id="loadingOverlay" className={`loading-overlay ${loading ? 'active' : ''}`}>
                <div className="loading-spinner">
                    <i className="fas fa-spinner fa-spin"></i>
                    <p>Analyzing vulnerability...</p>
                </div>
            </div>
        </div>
    );
}

export default App;
