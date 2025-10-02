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
