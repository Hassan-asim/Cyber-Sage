import React, { useState, useEffect } from 'react';
import '../styles/app.css';
import { Link } from 'react-router-dom';

function WebsiteTest() {
    const [currentScan, setCurrentScan] = useState(null);
    const [scanResults, setScanResults] = useState([]);
    const [activeSection, setActiveSection] = useState('website-scan');
    const [loading, setLoading] = useState(false);
    const [chatMessages, setChatMessages] = useState([
        {
            sender: 'bot',
            message: 'Hello! I\'m CyberSage, your web security expert. I can help you understand website vulnerabilities, OWASP Top 10, and provide guidance on securing web applications. How can I assist you today?'
        }
    ]);

    useEffect(() => {
        // Initial setup
    }, []);

    const switchSection = (sectionId) => {
        setActiveSection(sectionId);
    };

    const startWebsiteScan = async () => {
        // API call to start scan
    };

    const stopWebsiteScan = async () => {
        // API call to stop scan
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
                    <p>Website Security Testing</p>
                </div>

                <nav className="sidebar-nav">
                    <Link to="/app" className="nav-item">
                        <i className="fas fa-arrow-left"></i>
                        <span>Back to Main App</span>
                    </Link>
                    <a href="#dashboard" className={`nav-item ${activeSection === 'dashboard' ? 'active' : ''}`} onClick={() => switchSection('dashboard')}>
                        <i className="fas fa-tachometer-alt"></i>
                        <span>Dashboard</span>
                    </a>
                    <a href="#website-scan" className={`nav-item ${activeSection === 'website-scan' ? 'active' : ''}`} onClick={() => switchSection('website-scan')}>
                        <i className="fas fa-globe"></i>
                        <span>Website Scan</span>
                    </a>
                    <a href="#scan-results" className={`nav-item ${activeSection === 'scan-results' ? 'active' : ''}`} onClick={() => switchSection('scan-results')}>
                        <i className="fas fa-shield-alt"></i>
                        <span>Scan Results</span>
                    </a>
                    <a href="#reports" className={`nav-item ${activeSection === 'reports' ? 'active' : ''}`} onClick={() => switchSection('reports')}>
                        <i className="fas fa-file-alt"></i>
                        <span>Reports</span>
                    </a>
                    <a href="#cybersage" className={`nav-item ${activeSection === 'cybersage' ? 'active' : ''}`} onClick={() => switchSection('cybersage')}>
                        <i className="fas fa-robot"></i>
                        <span>CyberSage</span>
                    </a>
                </nav>

                <div className="sidebar-footer">
                    <div className="test-controls">
                        <button id="startScanBtn" className="btn-test-start" onClick={startWebsiteScan}>
                            <i className="fas fa-play"></i>
                            Start Scan
                        </button>
                        <button id="stopScanBtn" className="btn-test-end" onClick={stopWebsiteScan} disabled>
                            <i className="fas fa-stop"></i>
                            Stop Scan
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
                        <p id="pageSubtitle">Comprehensive web vulnerability scanning with AI</p>
                    </div>
                    <div className="header-right">
                        <div className="test-status">
                            <span className="status-indicator" id="scanStatus">Ready</span>
                        </div>
                        <Link to="/app" className="btn-back">
                            <i className="fas fa-arrow-left"></i>
                            Back to App
                        </Link>
                    </div>
                </header>

                {/* Website Scan Section */}
                <section id="website-scan" className={`content-section ${activeSection === 'website-scan' ? 'active' : ''}`}>
                    <div className="scan-container">
                    <h2>Website Vulnerability Scanner</h2>
                    <p>Enter a website URL to perform comprehensive security testing using AI-powered analysis</p>
                    
                    <div className="scan-form">
                        <div className="form-group">
                            <label htmlFor="websiteUrl">Website URL</label>
                            <div className="url-input-container">
                                <span className="url-prefix">https://</span>
                                <input 
                                    type="text" 
                                    id="websiteUrl" 
                                    placeholder="example.com"
                                    className="url-input"
                                />
                            </div>
                        </div>
                        
                        <div className="scan-options">
                            <h3>Scan Options</h3>
                            <div className="options-grid">
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    OWASP Top 10 Testing
                                </label>
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    SQL Injection Testing
                                </label>
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    XSS Testing
                                </label>
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    CSRF Testing
                                </label>
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    Security Headers Analysis
                                </label>
                                <label className="option-item">
                                    <input type="checkbox" defaultChecked />
                                    <span className="checkmark"></span>
                                    SSL/TLS Configuration
                                </label>
                            </div>
                        </div>
                        
                        <div className="form-actions">
                            <button className="btn-primary" onClick={startWebsiteScan}>
                                <i className="fas fa-search"></i>
                                Start Security Scan
                            </button>
                            <button className="btn-secondary" onClick={() => document.getElementById('websiteUrl').value = ''}>
                                <i className="fas fa-times"></i>
                                Clear
                            </button>
                        </div>
                    </div>
                    
                    <div id="scanProgress" className="scan-progress" style={{display: 'none'}}>
                        <div className="progress-header">
                            <h3>Scanning in Progress</h3>
                            <div className="progress-status">
                                <span className="status-dot processing"></span>
                                <span>AI agents are analyzing the website...</span>
                            </div>
                        </div>
                        <div className="progress-bar">
                            <div className="progress-fill" id="progressFill"></div>
                        </div>
                        <div className="agent-status">
                            <div className="agent-item">
                                <span className="agent-badge research">🔍</span>
                                <span>Research Agent</span>
                                <span className="agent-status-dot processing"></span>
                            </div>
                            <div className="agent-item">
                                <span className="agent-badge assess">📊</span>
                                <span>Assessment Agent</span>
                                <span className="agent-status-dot"></span>
                            </div>
                            <div className="agent-item">
                                <span className="agent-badge remediate">🛠️</span>
                                <span>Remediation Agent</span>
                                <span className="agent-status-dot"></span>
                            </div>
                            <div className="agent-item">
                                <span className="agent-badge report">📋</span>
                                <span>Reporting Agent</span>
                                <span className="agent-status-dot"></span>
                            </div>
                        </div>
                    </div>
                </div>
                </section>

                {/* Scan Results Section */}
                <section id="scan-results" className={`content-section ${activeSection === 'scan-results' ? 'active' : ''}`}>
                    <div className="results-container">
                    <h2>Scan Results</h2>
                    <div id="scanResultsList" className="scan-results-list">
                        <div className="empty-state">
                            <i className="fas fa-shield-alt"></i>
                            <p>No scan results yet</p>
                            <p>Start a website scan to see security analysis results</p>
                        </div>
                    </div>
                </div>
                </section>

                {/* Reports Section */}
                <section id="reports" className={`content-section ${activeSection === 'reports' ? 'active' : ''}`}>
                    <div className="reports-container">
                    <h2>Website Security Reports</h2>
                    
                    <div className="reports-actions">
                        <button className="btn-primary" onClick={() => {}}>
                            <i className="fas fa-file-pdf"></i>
                            Generate Security Report
                        </button>
                    </div>
                    
                    <div className="reports-list" id="websiteReportsList">
                        <div className="empty-state">
                            <i className="fas fa-file-alt"></i>
                            <p>No website reports generated yet</p>
                            <p>Complete a website scan to generate security reports</p>
                        </div>
                    </div>
                </div>
                </section>

                {/* CyberSage Section */}
                <section id="cybersage" className={`content-section ${activeSection === 'cybersage' ? 'active' : ''}`}>
                    <div className="cybersage-container">
                        <div className="cybersage-header">
                            <h2>CyberSage Assistant</h2>
                            <p>Your expert web security consultant</p>
                        </div>

                        <div className="chat-container">
                            <div className="chat-messages" id="chatMessages">
                                {chatMessages.map((msg, index) => (
                                    <div key={index} className={`message ${msg.sender}-message`}>
                                        <div className="message-avatar">
                                            <i className={`fas ${msg.sender === 'bot' ? 'fa-robot' : 'fa-user'}`}></i>
                                        </div>
                                        <div className="message-content">
                                            <p>{msg.message}</p>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div className="chat-input">
                                <input type="text" id="chatInput" placeholder="Ask me about web security..." />
                                <button onClick={sendMessage}>
                                    <i className="fas fa-paper-plane"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </section>
            </main>

            {/* Loading Overlay */}
            <div id="loadingOverlay" className={`loading-overlay ${loading ? 'active' : ''}`}>
                <div className="loading-spinner">
                    <i className="fas fa-spinner fa-spin"></i>
                    <p>Scanning website for vulnerabilities...</p>
                </div>
            </div>
        </div>
    );
}

export default WebsiteTest;