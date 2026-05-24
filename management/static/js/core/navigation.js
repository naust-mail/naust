/**
 * Navigation module
 * Handles mobile menu toggle and dropdown functionality
 */

/**
 * Initialize navigation functionality
 * Sets up mobile menu toggle and dropdown interactions
 */
export const initNavigation = () => {
  const navbarToggle = document.getElementById('navbar-toggle');
  const navbarNav = document.querySelector('.navbar-nav');
  const dropdowns = document.querySelectorAll('.nav-item.dropdown');

  // Toggle mobile menu
  if (navbarToggle && navbarNav) {
    navbarToggle.addEventListener('click', () => {
      navbarToggle.classList.toggle('active');
      navbarNav.classList.toggle('active');
    });
  }

  // Handle dropdown clicks on mobile
  dropdowns.forEach(dropdown => {
    const dropdownToggle = dropdown.querySelector('.dropdown-toggle');
    if (dropdownToggle) {
      dropdownToggle.addEventListener('click', (e) => {
        // On mobile, toggle dropdown
        if (window.innerWidth <= 768) {
          e.preventDefault();
          dropdown.classList.toggle('active');
        }
      });
    }
  });

  // Close menu when clicking outside
  document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768 && navbarNav) {
      if (!e.target.closest('.navbar') && navbarNav.classList.contains('active')) {
        navbarToggle.classList.remove('active');
        navbarNav.classList.remove('active');
      }
    }
  });

  // Close menu when clicking on a non-dropdown link
  const navLinks = document.querySelectorAll('.nav-link:not(.dropdown-toggle), .dropdown-item');
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      if (window.innerWidth <= 768 && navbarToggle && navbarNav) {
        navbarToggle.classList.remove('active');
        navbarNav.classList.remove('active');
        dropdowns.forEach(d => d.classList.remove('active'));
      }
    });
  });
};
