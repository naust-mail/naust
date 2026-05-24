/**
 * Main application entry point
 * Initializes the application and all modules
 */

import { state, subscribe } from './core/state.js';
import { loadStoredCredentials, logout } from './core/auth.js';
import { showPanel, initRouter } from './core/router.js';
import { updateMenuVisibility, showModalConfirm } from './core/ui.js';
import { initNavigation } from './core/navigation.js';

/**
 * Initialize the application
 */
const init = async () => {
  // Initialize navigation
  initNavigation();

  // Setup logout button
  const logoutLink = document.getElementById('logout-link');
  if (logoutLink) {
    logoutLink.addEventListener('click', (e) => {
      e.preventDefault();
      showModalConfirm('Confirm Logout', 'Are you sure you want to log out?', 'Logout', () => {
        logout();
      });
      return false;
    });
  }

  // Load stored credentials
  await loadStoredCredentials();

  // Initialize router
  initRouter();

  // Subscribe to state changes
  subscribe((newState) => {
    updateMenuVisibility();
  });

  // Initial menu state
  updateMenuVisibility();

  // Initial navigation
  if (state.credentials && window.location.hash) {
    const panelId = window.location.hash.substring(1);
    showPanel(panelId);
  } else if (state.credentials) {
    showPanel('welcome');
  } else {
    showPanel('login');
  }
};

// Start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

