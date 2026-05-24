/**
 * UI utilities - modals, loading indicators, menu visibility
 */

import { state } from './state.js';

let ajaxNumExecutingRequests = 0;
let loadingTimeout = null;

/**
 * Show loading indicator
 */
export const showLoadingIndicator = () => {
  ajaxNumExecutingRequests++;

  if (!loadingTimeout) {
    loadingTimeout = setTimeout(() => {
      if (ajaxNumExecutingRequests > 0) {
        const indicator = document.getElementById('ajax_loading_indicator');
        if (indicator) {
          indicator.style.display = 'flex';
        }
      }
    }, 100);
  }
};

/**
 * Hide loading indicator
 */
export const hideLoadingIndicator = () => {
  ajaxNumExecutingRequests--;

  if (ajaxNumExecutingRequests === 0) {
    if (loadingTimeout) {
      clearTimeout(loadingTimeout);
      loadingTimeout = null;
    }
    const indicator = document.getElementById('ajax_loading_indicator');
    if (indicator) {
      indicator.style.display = 'none';
    }
  }
};

/**
 * Show error modal
 * @type {(title: string, message: string | HTMLElement, callback?: () => void) => boolean}
 */
export const showModalError = (title, message, callback = undefined) => {
  const dialog = document.getElementById('global_modal');
  if (!dialog) return false;

  const titleEl = dialog.querySelector('.modal-title');
  const bodyEl = dialog.querySelector('.modal-body');
  const cancelBtn = document.getElementById('modal-cancel-btn');
  const confirmBtn = document.getElementById('modal-confirm-btn');

  titleEl.textContent = title;
  bodyEl.innerHTML = '';

  if (typeof message === 'string') {
    const p = document.createElement('p');
    p.textContent = message;
    bodyEl.appendChild(p);
  } else {
    bodyEl.appendChild(message);
  }

  cancelBtn.style.display = 'none';
  confirmBtn.style.display = '';
  confirmBtn.textContent = 'OK';

  const handleClose = () => {
    dialog.removeEventListener('close', handleClose);
    if (callback) callback();
  };

  dialog.addEventListener('close', handleClose);
  dialog.showModal();

  return false;
};

/**
 * Show confirmation modal
 * @type {(title: string, question: string | HTMLElement, verb: string | string[], yes_callback?: () => void, cancel_callback?: () => void) => boolean}
 */
export const showModalConfirm = (title, question, verb, yes_callback, cancel_callback) => {
  const dialog = document.getElementById('global_modal');
  if (!dialog) return false;

  const titleEl = dialog.querySelector('.modal-title');
  const bodyEl = dialog.querySelector('.modal-body');
  const cancelBtn = document.getElementById('modal-cancel-btn');
  const confirmBtn = document.getElementById('modal-confirm-btn');

  titleEl.textContent = title;
  bodyEl.innerHTML = '';

  if (typeof question === 'string') {
    const p = document.createElement('p');
    p.textContent = question;
    bodyEl.appendChild(p);
  } else {
    bodyEl.appendChild(question);
  }

  if (typeof verb === 'string') {
    cancelBtn.textContent = 'Cancel';
    confirmBtn.textContent = verb;
  } else {
    confirmBtn.textContent = verb[0];
    cancelBtn.textContent = verb[1];
  }

  cancelBtn.style.display = '';
  confirmBtn.style.display = '';

  const handleConfirm = () => {
    dialog.close();
    if (yes_callback) yes_callback();
  };

  const handleCancel = () => {
    dialog.close();
    if (cancel_callback) cancel_callback();
  };

  // Remove old listeners
  const newConfirmBtn = confirmBtn.cloneNode(true);
  const newCancelBtn = cancelBtn.cloneNode(true);
  confirmBtn.replaceWith(newConfirmBtn);
  cancelBtn.replaceWith(newCancelBtn);

  document.getElementById('modal-confirm-btn').addEventListener('click', handleConfirm);
  document.getElementById('modal-cancel-btn').addEventListener('click', handleCancel);

  dialog.showModal();

  return false;
};

/**
 * Update menu visibility based on auth state
 */
export const updateMenuVisibility = () => {
  const isLoggedIn = (state.credentials !== null);
  const privs = state.credentials ? state.credentials.privileges : [];

  document.querySelectorAll('.if-logged-in').forEach(el => {
    el.style.display = isLoggedIn ? '' : 'none';
  });

  document.querySelectorAll('.if-not-logged-in').forEach(el => {
    el.style.display = isLoggedIn ? 'none' : '';
  });

  document.querySelectorAll('.if-logged-in-admin, .if-logged-in-not-admin').forEach(el => {
    el.style.display = 'none';
  });

  if (isLoggedIn) {
    document.querySelectorAll('.if-logged-in-not-admin').forEach(el => {
      el.style.display = '';
    });

    privs.forEach(priv => {
      document.querySelectorAll('.if-logged-in-' + priv).forEach(el => {
        el.style.display = '';
      });

      document.querySelectorAll('.if-logged-in-not-' + priv).forEach(el => {
        el.style.display = 'none';
      });
    });
  }
};
