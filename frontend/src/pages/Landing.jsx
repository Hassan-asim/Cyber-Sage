
import React, { useEffect } from 'react';
import '../styles/landing.css';

function Landing() {
    useEffect(() => {
        // Smooth scrolling for navigation links
        const links = document.querySelectorAll('a[href^="#"]');
        links.forEach(link => {
            link.addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);

                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Add scroll effect to navbar
        const navbar = document.querySelector('.navbar');
        const handleScroll = () => {
            if (window.scrollY > 50) {
                navbar.style.background = 'rgba(255, 255, 255, 0.98)';
                navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
            } else {
                navbar.style.background = 'rgba(255, 255, 255, 0.95)';
                navbar.style.boxShadow = 'none';
            }
        };
        window.addEventListener('scroll', handleScroll);

        // Add intersection observer for animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver(function (entries) {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        // Observe feature cards for animation
        const featureCards = document.querySelectorAll('.feature-card');
        featureCards.forEach(card => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(30px)';
            card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(card);
        });

        // Observe workflow steps for animation
        const workflowSteps = document.querySelectorAll('.workflow-step');
        workflowSteps.forEach(step => {
            step.style.opacity = '0';
            step.style.transform = 'translateY(30px)';
            step.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(step);
        });

        return () => {
            window.removeEventListener('scroll', handleScroll);
            links.forEach(link => link.removeEventListener('click', () => {}));
            featureCards.forEach(card => observer.unobserve(card));
            workflowSteps.forEach(step => observer.unobserve(step));
        };
    }, []);

    const startApp = () => {
        window.location.href = '/app';
    };

    const scrollToFeatures = () => {
        document.getElementById('features').scrollIntoView({
            behavior: 'smooth'
        });
    };

    return (
        <div className="container">
            {/* Navigation */}
            <nav className="navbar">
                <div className="nav-brand">
                    <h1>Cyber AI</h1>
                </div>
                <div className="nav-links">
                    <a href="#features">Features</a>
                    <a href="#about">About</a>
                    <a href="#contact">Contact</a>
                </div>
            </nav>

            {/* Hero Section */}
            <section className="hero">
                <div className="hero-content">
                    <h1 className="hero-title">
                        Advanced <span className="highlight">Penetration Testing</span><br />
                        Powered by AI
                    </h1>
                    <p className="hero-description">
                        Comprehensive vulnerability assessment, research, and documentation tool for cybersecurity professionals.
                        Leverage AI-powered analysis to identify, assess, and report security vulnerabilities with precision.
                    </p>
                    <div className="hero-buttons">
                        <button className="btn-primary" onClick={startApp}>
                            Get Started
                        </button>
                        <button className="btn-secondary" onClick={scrollToFeatures}>
                            Learn More
                        </button>
                    </div>
                </div>
                <div className="hero-visual">
                    <div className="cyber-grid">
                        {[...Array(9)].map((_, i) => <div className="grid-item" key={i}></div>)}
                    </div>
                </div>
            </section>

            {/* Features Section */}
            <section id="features" className="features">
                <div className="section-header">
                    <h2>Powerful Features</h2>
                    <p>Everything you need for comprehensive penetration testing</p>
                </div>
                <div className="features-grid">
                    <div className="feature-card">
                        <div className="feature-icon">🔍</div>
                        <h3>AI-Powered Research</h3>
                        <p>Automated vulnerability research using advanced AI models and real-time web intelligence</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📊</div>
                        <h3>Severity Assessment</h3>
                        <p>Intelligent CVSS scoring and risk assessment for accurate vulnerability prioritization</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">🛠️</div>
                        <h3>Exploit Generation</h3>
                        <p>Detailed exploit instructions and reproduction steps for each identified vulnerability</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📋</div>
                        <h3>Report Generation</h3>
                        <p>Professional vulnerability reports and comprehensive penetration test documentation</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">🤖</div>
                        <h3>CyberSage Assistant</h3>
                        <p>Expert cybersecurity chatbot for guidance and technical support during testing</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📈</div>
                        <h3>Progress Tracking</h3>
                        <p>Real-time tracking of vulnerabilities and comprehensive test management</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">🌐</div>
                        <h3>Website Security Testing</h3>
                        <p>Automated web vulnerability scanning with AI-powered analysis and comprehensive reporting</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">🤖</div>
                        <h3>Agentic AI System</h3>
                        <p>Multi-agent AI workflow for comprehensive vulnerability research, assessment, and remediation</p>
                    </div>
                </div>
            </section>

            {/* About Section */}
            <section id="about" className="about">
                <div className="about-content">
                    <div className="about-text">
                        <h2>Why Choose Cyber AI?</h2>
                        <p>
                            Cyber AI revolutionizes penetration testing by combining artificial intelligence with
                            comprehensive security research capabilities. Our platform streamlines the entire
                            vulnerability assessment process, from initial discovery to final reporting.
                        </p>
                        <ul className="benefits-list">
                            <li>Automated vulnerability research and analysis</li>
                            <li>AI-powered severity assessment and CVSS scoring</li>
                            <li>Detailed exploit generation and reproduction steps</li>
                            <li>Professional report generation and documentation</li>
                            <li>Expert cybersecurity assistance via CyberSage</li>
                            <li>Comprehensive penetration test management</li>
                        </ul>
                    </div>
                    <div className="about-visual">
                        <div className="workflow-diagram">
                            <div className="workflow-step">
                                <div className="step-number">1</div>
                                <div className="step-text">Identify Vulnerability</div>
                            </div>
                            <div className="workflow-arrow">→</div>
                            <div className="workflow-step">
                                <div className="step-number">2</div>
                                <div className="step-text">AI Research</div>
                            </div>
                            <div className="workflow-arrow">→</div>
                            <div className="workflow-step">
                                <div className="step-number">3</div>
                                <div className="step-text">Generate Report</div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="cta">
                <div className="cta-content">
                    <h2>Ready to Enhance Your Security Testing?</h2>
                    <p>Start your comprehensive penetration testing journey with Cyber AI today</p>
                    <button className="btn-primary btn-large" onClick={startApp}>
                        Launch Cyber AI
                    </button>
                </div>
            </section>

            {/* Footer */}
            <footer id="contact" className="footer">
                <div className="footer-content">
                    <div className="footer-brand">
                        <h3>Cyber AI</h3>
                        <p>Advanced Penetration Testing Platform</p>
                    </div>
                    <div className="footer-links">
                        <div className="link-group">
                            <h4>Product</h4>
                            <a href="#features">Features</a>
                            <a href="#about">About</a>
                        </div>
                        <div className="link-group">
                            <h4>Support</h4>
                            <a href="#">Documentation</a>
                            <a href="#">Help Center</a>
                        </div>
                        <div className="link-group">
                            <h4>Contact</h4>
                            <a href="#">Email</a>
                            <a href="#">Support</a>
                        </div>
                    </div>
                </div>
                <div className="footer-bottom">
                    <p>&copy; 2024 Cyber AI. All rights reserved.</p>
                </div>
            </footer>
        </div>
    );
}

export default Landing;
