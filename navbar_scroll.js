// Navbar Glass Effect on Scroll
document.addEventListener('DOMContentLoaded', function() {
    const navbar = document.getElementById('navbar');
    const navbarContent = document.getElementById('navbar-content');

    if (navbar && navbarContent) {
        window.addEventListener('scroll', function() {
            if (window.scrollY > 50) {
                // Enhanced glass effect on scroll
                navbarContent.classList.remove('bg-white/10', 'backdrop-blur-md');
                navbarContent.classList.add('bg-white/5', 'backdrop-blur-xl');
            } else {
                // Default glass effect
                navbarContent.classList.remove('bg-white/5', 'backdrop-blur-xl');
                navbarContent.classList.add('bg-white/10', 'backdrop-blur-md');
            }
        });
    }
});
