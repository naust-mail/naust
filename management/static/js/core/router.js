/**
 * Hash-based routing system
 */

import { state, setState } from './state.js'
import { show_system_status } from '../pages/system-status.js';
import { initSsl } from '../pages/ssl.js';
import { onBackupInit } from "../pages/system-backup.js";
import { initUserManagement } from "../pages/users.js";
import { initAliases } from "../pages/aliases.js";
import { initCustomDns } from "../pages/custom-dns.js";
import { initExternalDns } from "../pages/external-dns.js";
import { initWeb } from "../pages/web.js";
import { showMunin } from "../pages/munin.js";
import { showMfa } from "../pages/mfa.js";
import { showLogin } from "../pages/login.js";

const pageControllers = {
    'system_status': () => {
        show_system_status();
    },
    'tls': () => {
        initSsl();
    },
    'system_backup': () => {
        onBackupInit();
    },
    'users': () => {
        initUserManagement();
    },
    'aliases': () => {
        initAliases();
    },
    'custom_dns': () => {
        initCustomDns();
    },
    'external_dns': () => {
        initExternalDns();
    },
    'web': () => {
        initWeb();
    },
    'munin': () => {
        showMunin();
    },
    'mfa': () => {
        showMfa();
    },
    'login': () => {
      showLogin();
    }
};

/**
 * Register a page controller
 * @type {(pageId: string, controller: () => void) => void}
 */
export const registerPage = (pageId, controller) => {
  pageControllers[pageId] = controller;
};

/**
 * Show a specific panel
 * @type {(panelId: string | HTMLElement) => void}
 */
export const showPanel = (panelId) => {
  if (panelId && panelId.getAttribute) {
    panelId = panelId.getAttribute('href').substring(1);
  }

  document.querySelectorAll('.admin_panel').forEach(panel => {
    panel.style.display = 'none';
  });

  const panel = document.getElementById('panel_' + panelId);
  if (panel) {
    panel.style.display = 'block';
  } else {
      // Find the 404 panel
      const panel404 = document.getElementById('panel_404');
      if (panel404) {
          panel404.style.display = 'block';
          setState({
              currentPanel: '404',
              switchBackToPanel: null
          });
      }
      return;
  }

  // Inject panel styles
  injectStyles(panel);

  // Call page controller if exists
  if (pageControllers[panelId]) {
    pageControllers[panelId]();
  }

  // if twemoji is available, parse the panel for emojis
  if (window.twemoji) {
      window.twemoji.parse(panel);
  }

  setState({
    currentPanel: panelId,
    switchBackToPanel: null
  });
};

/**
 * Initialize router
 */
export const initRouter = () => {
    const handleHash = () => {
        const panelId = window.location.hash.substring(1) || 'default'; // fallback panel

        // Check credentials before showing panel
        if (!state.credentials) {
            showPanel('login');
            return;
        }

        if (panelId) {
            showPanel(panelId);
        }
    };

    // Trigger on hash change
    window.addEventListener('hashchange', handleHash);

    // Trigger once on initial load
    handleHash();
};

const injectStyles = (panelElement) => {
    // If the panel has any <style> tags, we should inject them into the document head
    const injectedStyles = document.getElementById('injected-panel-styles');
    if (injectedStyles) {
        injectedStyles.remove();
    }

    // we only support inline styles for panels, anything which
    // should be global should go into index.html as a global stylesheet
    const styleTags = panelElement.getElementsByTagName('style');
    if (styleTags.length > 0) {
        const styles = document.createElement('style');
        styles.id = 'injected-panel-styles';
        for (let i = 0; i < styleTags.length; i++) {
            styles.appendChild(document.createTextNode(styleTags[i].innerHTML));
        }
        document.head.appendChild(styles);
    }
}
