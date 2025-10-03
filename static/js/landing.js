// Landing page JavaScript functionality

function startApp() {
    // Redirect to the main application
    window.location.href = '/app';
}

function scrollToFeatures() {
    document.getElementById('features').scrollIntoView({
        behavior: 'smooth'
    });
}

// Smooth scrolling for navigation links
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling to all anchor links
    const links = document.querySelectorAll('a[href^="#"]');

    links.forEach(link => {
        link.addEventListener('click', function(e) {
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
    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(255, 255, 255, 0.98)';
            navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
        } else {
            navbar.style.background = 'rgba(255, 255, 255, 0.95)';
            navbar.style.boxShadow = 'none';
        }
    });

    // Add intersection observer for animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
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
});

// Add loading animation for buttons
function addLoadingState(button) {
    const originalText = button.textContent;
    button.textContent = 'Loading...';
    button.disabled = true;

    setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
    }, 2000);
}

// Enhanced button click handlers
document.addEventListener('DOMContentLoaded', function() {
    const primaryButtons = document.querySelectorAll('.btn-primary');

    primaryButtons.forEach(button => {
        button.addEventListener('click', function() {
            addLoadingState(this);
        });
    });
});

// Mobile Menu Dropdown Functionality
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerIcon = document.getElementById('hamburger-icon');
    const closeIcon = document.getElementById('close-icon');
    let isMenuOpen = false;

    // Function to open mobile menu dropdown
    function openMobileMenu() {
        mobileMenu.classList.remove('scale-95', 'opacity-0', 'pointer-events-none');
        mobileMenu.classList.add('scale-100', 'opacity-100');

        // Toggle icons
        hamburgerIcon.classList.add('hidden');
        closeIcon.classList.remove('hidden');

        isMenuOpen = true;

        // Update aria attributes
        mobileMenuButton.setAttribute('aria-label', 'Close menu');
        mobileMenuButton.setAttribute('title', 'Close menu');
        mobileMenuButton.setAttribute('aria-expanded', 'true');
    }

    // Function to close mobile menu dropdown
    function closeMobileMenu() {
        mobileMenu.classList.remove('scale-100', 'opacity-100');
        mobileMenu.classList.add('scale-95', 'opacity-0', 'pointer-events-none');

        // Toggle icons
        hamburgerIcon.classList.remove('hidden');
        closeIcon.classList.add('hidden');

        isMenuOpen = false;

        // Update aria attributes
        mobileMenuButton.setAttribute('aria-label', 'Open menu');
        mobileMenuButton.setAttribute('title', 'Open menu');
        mobileMenuButton.setAttribute('aria-expanded', 'false');
    }

    // Toggle mobile menu on button click
    if (mobileMenuButton) {
        mobileMenuButton.addEventListener('click', function(e) {
            e.stopPropagation();
            if (isMenuOpen) {
                closeMobileMenu();
            } else {
                openMobileMenu();
            }
        });
    }

    // Close menu when clicking outside
    document.addEventListener('click', function(e) {
        if (isMenuOpen && mobileMenu && !mobileMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
            closeMobileMenu();
        }
    });

    // Close menu on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && isMenuOpen) {
            closeMobileMenu();
        }
    });

    // Close menu when clicking on menu links
    if (mobileMenu) {
        const mobileMenuLinks = mobileMenu.querySelectorAll('a');
        mobileMenuLinks.forEach(link => {
            link.addEventListener('click', function() {
                closeMobileMenu();
            });
        });
    }

    // Close menu on window resize to desktop size
    window.addEventListener('resize', function() {
        if (window.innerWidth >= 1024 && isMenuOpen) { // lg breakpoint
            closeMobileMenu();
        }
    });
});

// Features Section Interactive Functionality
document.addEventListener('DOMContentLoaded', function() {
    const featureItems = document.querySelectorAll('.feature-item');

    function setActiveFeature(activeFeature) {
        // First, reset all features to inactive state
        featureItems.forEach(feature => {
            const description = feature.querySelector('.feature-description');

            // Remove active class and add opacity
            feature.classList.remove('active');
            feature.classList.add('opacity-50');

            // Hide description
            if (description) {
                description.classList.add('hidden');
            }
        });

        // Then activate the selected feature
        if (activeFeature) {
            const activeDescription = activeFeature.querySelector('.feature-description');

            // Add active class and remove opacity
            activeFeature.classList.add('active');
            activeFeature.classList.remove('opacity-50');

            // Show description
            if (activeDescription) {
                activeDescription.classList.remove('hidden');
            }
        }
    }

    // Add click event listeners to feature items
    featureItems.forEach(feature => {
        feature.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('Feature clicked:', this.id); // Debug log
            setActiveFeature(this);
        });
    });

    // Set the first feature as active by default
    if (featureItems.length > 0) {
        setActiveFeature(featureItems[0]);
    }
});

// Testimonials Carousel Functionality
document.addEventListener('DOMContentLoaded', function() {
    const testimonials = [
        {
            text: "Working with Cyber Sage was a pleasure from start to finish. Their application was very thorough, collaborative, and delivered exceptional results that perfectly aligned with our needs.",
            name: "Sam Altman",
            role: "Head of Cyber Security",
            logo: "https://cdn.worldvectorlogo.com/logos/crowdstrike-logo.svg"
        },
        {
            text: "Cyber Sage transformed our security testing approach. The AI-powered vulnerability assessment saved us countless hours and identified critical issues we might have missed.",
            name: "Sarah Chen",
            role: "CISO",
            logo: "https://cdn.worldvectorlogo.com/logos/era-5.svg"
        },
        {
            text: "The automated CVSS scoring and detailed reporting features are game-changers. Our team can now focus on remediation rather than manual assessment tasks.",
            name: "Marcus Rodriguez",
            role: "Senior Security Engineer",
            logo: "https://cdn.worldvectorlogo.com/logos/figma-icon.svg"
        },
        {
            text: "Implementation was seamless and the results exceeded our expectations. Cyber Sage has become an essential part of our security testing workflow indeed.",
            name: "Jennifer Park",
            role: "IT Security Manager",
            logo: "https://cdn.worldvectorlogo.com/logos/dotcover-1.svg"
        }
    ];

    let currentTestimonialIndex = 0;

    const testimonialText = document.getElementById('testimonial-text');
    const testimonialName = document.getElementById('testimonial-name');
    const testimonialRole = document.getElementById('testimonial-role');
    const testimonialLogo = document.getElementById('testimonial-logo');
    const prevButton = document.getElementById('testimonial-prev');
    const nextButton = document.getElementById('testimonial-next');

    function updateTestimonial(index) {
        if (!testimonials[index]) return;

        const testimonial = testimonials[index];

        // Add fade out effect
        const elements = [testimonialText, testimonialName, testimonialRole, testimonialLogo];
        elements.forEach(element => {
            if (element) {
                element.style.opacity = '0';
            }
        });

        // Update content after fade out
        setTimeout(() => {
            if (testimonialText) testimonialText.textContent = `"${testimonial.text}"`;
            if (testimonialName) testimonialName.textContent = testimonial.name;
            if (testimonialRole) testimonialRole.textContent = testimonial.role;
            if (testimonialLogo) {
                testimonialLogo.src = testimonial.logo;
                testimonialLogo.alt = `${testimonial.name} Company Logo`;
            }

            // Fade back in
            elements.forEach(element => {
                if (element) {
                    element.style.opacity = '1';
                }
            });
        }, 150);
    }

    function nextTestimonial() {
        currentTestimonialIndex = (currentTestimonialIndex + 1) % testimonials.length;
        updateTestimonial(currentTestimonialIndex);
    }

    function prevTestimonial() {
        currentTestimonialIndex = (currentTestimonialIndex - 1 + testimonials.length) % testimonials.length;
        updateTestimonial(currentTestimonialIndex);
    }

    // Add event listeners
    if (nextButton) {
        nextButton.addEventListener('click', nextTestimonial);
    }

    if (prevButton) {
        prevButton.addEventListener('click', prevTestimonial);
    }

    // Optional: Add keyboard navigation
    document.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowRight') {
            nextTestimonial();
        } else if (e.key === 'ArrowLeft') {
            prevTestimonial();
        }
    });
});




// Landing page functionality
class LandingPage {
    constructor() {
        this.init();
    }

    init() {
        this.initAOS();
        this.initVideoModal();
        this.initSpotlightEffect();
        this.initMobileMenu();
        this.initSmoothScrolling();
    }

    // Initialize AOS (Animate On Scroll)
    initAOS() {
        if (typeof AOS !== 'undefined') {
            AOS.init({
                once: true,
                disable: 'phone',
                duration: 600,
                easing: 'ease-out-sine',
            });
        }
    }

    // Video Modal functionality
    initVideoModal() {
        const modal = document.getElementById('videoModal');
        const video = document.getElementById('modalVideo');
        const playButton = document.querySelector('[onclick="openVideoModal()"]');

        // Open modal function
        window.openVideoModal = () => {
            if (modal && video) {
                modal.classList.add('active');
                video.play();
                document.body.style.overflow = 'hidden';
            }
        };

        // Close modal function
        window.closeVideoModal = () => {
            if (modal && video) {
                modal.classList.remove('active');
                video.pause();
                video.currentTime = 0;
                document.body.style.overflow = 'auto';
            }
        };

        // Close modal when clicking outside
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    window.closeVideoModal();
                }
            });
        }

        // Close modal with escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                window.closeVideoModal();
            }
        });
    }

    // Spotlight effect for cards
    initSpotlightEffect() {
        const spotlightCards = document.querySelectorAll('.spotlight-card');

        spotlightCards.forEach((card) => {
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                card.style.setProperty('--mouse-x', `${x}px`);
                card.style.setProperty('--mouse-y', `${y}px`);
            });

            card.addEventListener('mouseleave', () => {
                card.style.removeProperty('--mouse-x');
                card.style.removeProperty('--mouse-y');
            });
        });
    }

    // Mobile menu functionality
    initMobileMenu() {
        const mobileMenuButton = document.getElementById('mobile-menu-button');
        const mobileMenu = document.getElementById('mobile-menu');

        if (mobileMenuButton && mobileMenu) {
            mobileMenuButton.addEventListener('click', () => {
                mobileMenu.classList.toggle('active');
                mobileMenuButton.setAttribute('aria-expanded',
                    mobileMenuButton.getAttribute('aria-expanded') === 'false' ? 'true' : 'false'
                );
            });

            // Close mobile menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!mobileMenuButton.contains(e.target) && !mobileMenu.contains(e.target)) {
                    mobileMenu.classList.remove('active');
                    mobileMenuButton.setAttribute('aria-expanded', 'false');
                }
            });
        }
    }

    // Smooth scrolling for anchor links
    initSmoothScrolling() {
        const anchorLinks = document.querySelectorAll('a[href^="#"]');

        anchorLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                const href = link.getAttribute('href');
                if (href !== '#0' && href !== '#') {
                    e.preventDefault();
                    const target = document.querySelector(href);
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                }
            });
        });
    }

    // Utility function to debounce scroll events
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Add scroll-based animations
    initScrollAnimations() {
        const elements = document.querySelectorAll('[data-scroll-animation]');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });

        elements.forEach(el => observer.observe(el));
    }

    // Handle form submissions (if any)
    initForms() {
        const forms = document.querySelectorAll('form');

        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                // Add your form handling logic here
                console.log('Form submitted:', new FormData(form));
            });
        });
    }
}

// Initialize the landing page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new LandingPage();
});

// Handle window resize events
window.addEventListener('resize', () => {
    // Reinitialize AOS on resize
    if (typeof AOS !== 'undefined') {
        AOS.refresh();
    }
});

// Add loading animation
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
});

// Export for module use if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LandingPage;
}




// Landing page JavaScript functionality

function startApp() {
    // Redirect to the main application
    window.location.href = '/app';
}

function scrollToFeatures() {
    document.getElementById('features').scrollIntoView({
        behavior: 'smooth'
    });
}

// Smooth scrolling for navigation links
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling to all anchor links
    const links = document.querySelectorAll('a[href^="#"]');

    links.forEach(link => {
        link.addEventListener('click', function(e) {
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
    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(255, 255, 255, 0.98)';
            navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
        } else {
            navbar.style.background = 'rgba(255, 255, 255, 0.95)';
            navbar.style.boxShadow = 'none';
        }
    });

    // Add intersection observer for animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
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
});

// Add loading animation for buttons
function addLoadingState(button) {
    const originalText = button.textContent;
    button.textContent = 'Loading...';
    button.disabled = true;

    setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
    }, 2000);
}

// Enhanced button click handlers
document.addEventListener('DOMContentLoaded', function() {
    const primaryButtons = document.querySelectorAll('.btn-primary');

    primaryButtons.forEach(button => {
        button.addEventListener('click', function() {
            addLoadingState(this);
        });
    });
});

// Mobile Menu Dropdown Functionality
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerIcon = document.getElementById('hamburger-icon');
    const closeIcon = document.getElementById('close-icon');
    let isMenuOpen = false;

    // Function to open mobile menu dropdown
    function openMobileMenu() {
        mobileMenu.classList.remove('scale-95', 'opacity-0', 'pointer-events-none');
        mobileMenu.classList.add('scale-100', 'opacity-100');

        // Toggle icons
        hamburgerIcon.classList.add('hidden');
        closeIcon.classList.remove('hidden');

        isMenuOpen = true;

        // Update aria attributes
        mobileMenuButton.setAttribute('aria-label', 'Close menu');
        mobileMenuButton.setAttribute('title', 'Close menu');
        mobileMenuButton.setAttribute('aria-expanded', 'true');
    }

    // Function to close mobile menu dropdown
    function closeMobileMenu() {
        mobileMenu.classList.remove('scale-100', 'opacity-100');
        mobileMenu.classList.add('scale-95', 'opacity-0', 'pointer-events-none');

        // Toggle icons
        hamburgerIcon.classList.remove('hidden');
        closeIcon.classList.add('hidden');

        isMenuOpen = false;

        // Update aria attributes
        mobileMenuButton.setAttribute('aria-label', 'Open menu');
        mobileMenuButton.setAttribute('title', 'Open menu');
        mobileMenuButton.setAttribute('aria-expanded', 'false');
    }

    // Toggle mobile menu on button click
    if (mobileMenuButton) {
        mobileMenuButton.addEventListener('click', function(e) {
            e.stopPropagation();
            if (isMenuOpen) {
                closeMobileMenu();
            } else {
                openMobileMenu();
            }
        });
    }

    // Close menu when clicking outside
    document.addEventListener('click', function(e) {
        if (isMenuOpen && mobileMenu && !mobileMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
            closeMobileMenu();
        }
    });

    // Close menu on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && isMenuOpen) {
            closeMobileMenu();
        }
    });

    // Close menu when clicking on menu links
    if (mobileMenu) {
        const mobileMenuLinks = mobileMenu.querySelectorAll('a');
        mobileMenuLinks.forEach(link => {
            link.addEventListener('click', function() {
                closeMobileMenu();
            });
        });
    }

    // Close menu on window resize to desktop size
    window.addEventListener('resize', function() {
        if (window.innerWidth >= 1024 && isMenuOpen) { // lg breakpoint
            closeMobileMenu();
        }
    });
});

// Features Section Interactive Functionality
document.addEventListener('DOMContentLoaded', function() {
    const featureItems = document.querySelectorAll('.feature-item');

    function setActiveFeature(activeFeature) {
        // First, reset all features to inactive state
        featureItems.forEach(feature => {
            const description = feature.querySelector('.feature-description');

            // Remove active class and add opacity
            feature.classList.remove('active');
            feature.classList.add('opacity-50');

            // Hide description
            if (description) {
                description.classList.add('hidden');
            }
        });

        // Then activate the selected feature
        if (activeFeature) {
            const activeDescription = activeFeature.querySelector('.feature-description');

            // Add active class and remove opacity
            activeFeature.classList.add('active');
            activeFeature.classList.remove('opacity-50');

            // Show description
            if (activeDescription) {
                activeDescription.classList.remove('hidden');
            }
        }
    }

    // Add click event listeners to feature items
    featureItems.forEach(feature => {
        feature.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('Feature clicked:', this.id); // Debug log
            setActiveFeature(this);
        });
    });

    // Set the first feature as active by default
    if (featureItems.length > 0) {
        setActiveFeature(featureItems[0]);
    }
});

// Testimonials Carousel Functionality
document.addEventListener('DOMContentLoaded', function() {
    const testimonials = [
        {
            text: "Working with Cyber Sage was a pleasure from start to finish. Their application was very thorough, collaborative, and delivered exceptional results that perfectly aligned with our needs.",
            name: "Sam Altman",
            role: "Head of Cyber Security",
            logo: "https://cdn.worldvectorlogo.com/logos/crowdstrike-logo.svg"
        },
        {
            text: "Cyber Sage transformed our security testing approach. The AI-powered vulnerability assessment saved us countless hours and identified critical issues we might have missed.",
            name: "Sarah Chen",
            role: "CISO",
            logo: "https://cdn.worldvectorlogo.com/logos/era-5.svg"
        },
        {
            text: "The automated CVSS scoring and detailed reporting features are game-changers. Our team can now focus on remediation rather than manual assessment tasks.",
            name: "Marcus Rodriguez",
            role: "Senior Security Engineer",
            logo: "https://cdn.worldvectorlogo.com/logos/figma-icon.svg"
        },
        {
            text: "Implementation was seamless and the results exceeded our expectations. Cyber Sage has become an essential part of our security testing workflow indeed.",
            name: "Jennifer Park",
            role: "IT Security Manager",
            logo: "https://cdn.worldvectorlogo.com/logos/dotcover-1.svg"
        }
    ];

    let currentTestimonialIndex = 0;

    const testimonialText = document.getElementById('testimonial-text');
    const testimonialName = document.getElementById('testimonial-name');
    const testimonialRole = document.getElementById('testimonial-role');
    const testimonialLogo = document.getElementById('testimonial-logo');
    const prevButton = document.getElementById('testimonial-prev');
    const nextButton = document.getElementById('testimonial-next');

    function updateTestimonial(index) {
        if (!testimonials[index]) return;

        const testimonial = testimonials[index];

        // Add fade out effect
        const elements = [testimonialText, testimonialName, testimonialRole, testimonialLogo];
        elements.forEach(element => {
            if (element) {
                element.style.opacity = '0';
            }
        });

        // Update content after fade out
        setTimeout(() => {
            if (testimonialText) testimonialText.textContent = `"${testimonial.text}"`;
            if (testimonialName) testimonialName.textContent = testimonial.name;
            if (testimonialRole) testimonialRole.textContent = testimonial.role;
            if (testimonialLogo) {
                testimonialLogo.src = testimonial.logo;
                testimonialLogo.alt = `${testimonial.name} Company Logo`;
            }

            // Fade back in
            elements.forEach(element => {
                if (element) {
                    element.style.opacity = '1';
                }
            });
        }, 150);
    }

    function nextTestimonial() {
        currentTestimonialIndex = (currentTestimonialIndex + 1) % testimonials.length;
        updateTestimonial(currentTestimonialIndex);
    }

    function prevTestimonial() {
        currentTestimonialIndex = (currentTestimonialIndex - 1 + testimonials.length) % testimonials.length;
        updateTestimonial(currentTestimonialIndex);
    }

    // Add event listeners
    if (nextButton) {
        nextButton.addEventListener('click', nextTestimonial);
    }

    if (prevButton) {
        prevButton.addEventListener('click', prevTestimonial);
    }

    // Optional: Add keyboard navigation
    document.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowRight') {
            nextTestimonial();
        } else if (e.key === 'ArrowLeft') {
            prevTestimonial();
        }
    });
});

// Navbar Glass Effect on Scroll
document.addEventListener('DOMContentLoaded', function() {
    const navbar = document.getElementById('navbar');
    const navbarContent = document.getElementById('navbar-content');

    if (navbar && navbarContent) {
        window.addEventListener('scroll', function() {
            if (window.scrollY > 50) {
                // Apply glass effect on scroll
                navbarContent.classList.remove('bg-white', 'border-gray-200', 'shadow-lg');
                navbarContent.classList.add('bg-white/5', 'backdrop-blur-xl', 'border-white/20', 'shadow-[0_8px_32px_0px_rgba(31,38,135,0.37)]');

                // Change text colors for glass background
                const navLinks = navbarContent.querySelectorAll('a:not(.bg-orange-500)');
                const icons = navbarContent.querySelectorAll('svg');

                navLinks.forEach(link => {
                    link.classList.remove('text-gray-600', 'hover:text-gray-900');
                    link.classList.add('text-white/90', 'hover:text-white');
                });

                icons.forEach(icon => {
                    icon.classList.remove('text-gray-600', 'text-gray-400');
                    icon.classList.add('text-white/90');
                });

                // Update login button for glass background
                const loginBtn = navbarContent.querySelector('a[title="Log in"]');
                if (loginBtn) {
                    loginBtn.classList.remove('border-gray-300', 'bg-white', 'text-gray-600', 'hover:bg-gray-50', 'hover:border-gray-400');
                    loginBtn.classList.add('border-white/20', 'bg-white/10', 'text-white', 'hover:bg-white/15', 'hover:border-white/30', 'backdrop-blur-sm');
                }
            } else {
                // Return to solid white background
                navbarContent.classList.remove('bg-white/5', 'backdrop-blur-xl', 'border-white/20', 'shadow-[0_8px_32px_0px_rgba(31,38,135,0.37)]');
                navbarContent.classList.add('bg-white', 'border-gray-200', 'shadow-lg');

                // Change text colors back for white background
                const navLinks = navbarContent.querySelectorAll('a:not(.bg-orange-500)');
                const icons = navbarContent.querySelectorAll('svg');

                navLinks.forEach(link => {
                    link.classList.remove('text-white/90', 'hover:text-white');
                    link.classList.add('text-gray-600', 'hover:text-gray-900');
                });

                icons.forEach(icon => {
                    icon.classList.remove('text-white/90');
                    if (icon.classList.contains('text-gray-400') === false) {
                        icon.classList.add('text-gray-600');
                    } else {
                        icon.classList.add('text-gray-400');
                    }
                });

                // Update login button for white background
                const loginBtn = navbarContent.querySelector('a[title="Log in"]');
                if (loginBtn) {
                    loginBtn.classList.remove('border-white/20', 'bg-white/10', 'text-white', 'hover:bg-white/15', 'hover:border-white/30', 'backdrop-blur-sm');
                    loginBtn.classList.add('border-gray-300', 'bg-white', 'text-gray-600', 'hover:bg-gray-50', 'hover:border-gray-400');
                }
            }
        });
    }
});
