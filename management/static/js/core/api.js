/**
 * Modern fetch-based API wrapper
 * Handles authentication, loading indicators, and error handling
 */

import { state, setState } from './state.js';
import { showLoadingIndicator, hideLoadingIndicator, showModalError } from './ui.js';
import { clear as clearCredentials } from './auth.js';
import { showPanel } from './router.js';

/**
 * Base64 encode for Basic Auth
 * @type {(input: string) => string}
 */
const base64Encode = (input) => {
  return btoa(unescape(encodeURIComponent(input)));
};

/**
 * API wrapper function
 * @type {(url: string, method: string, data?: any, callback?: (response: any) => void, callback_error?: (error: string, response: Response) => void, headers?: Record<string, string>, skipAuthRedirect?: boolean) => void}
 */
export const api = (url, method, data, callback, callback_error, headers, skipAuthRedirect = false) => {
  headers = headers || {};

  const options = {
    method: method,
    cache: 'no-cache',
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  };

  Object.assign(options.headers, headers);

  // Add Authorization header
  if (state.credentials) {
    options.headers['Authorization'] = 'Basic ' + base64Encode(
      state.credentials.username + ':' + state.credentials.session_key
    );
  }

  // Handle data
  if (data) {
    if (method === 'GET') {
      // For GET requests, append data as query parameters
      if (typeof data === 'object') {
        const params = new URLSearchParams(data);
        const queryString = params.toString();
        if (queryString) {
          url += (url.includes('?') ? '&' : '?') + queryString;
        }
      }
    } else {
      // For non-GET requests, send data in body
      if (typeof data === 'string') {
        options.body = data;
        options.headers['Content-Type'] = 'text/plain; charset=ascii';
      } else {
        options.body = new URLSearchParams(data);
      }
    }
  }

  showLoadingIndicator();

  fetch('/admin' + url, options)
    .then(async (response) => {
      hideLoadingIndicator();

      // Handle 403 Forbidden (unless skipAuthRedirect is true for credential validation)
      if ((response.status === 403 || response.status === 401) && !skipAuthRedirect) {
        const p = state.currentPanel;
        clearCredentials();
        showPanel('login');
        setState({ switchBackToPanel: p });
        return;
      }

      // Parse response
      const contentType = response.headers.get('content-type');
      let result;
      if (contentType && contentType.includes('application/json')) {
        result = await response.json();
      } else {
        result = await response.text();
      }

      // Handle errors
      if (!response.ok) {
        const error = result.reason || result.message || result || 'Something went wrong, sorry.';
        if (callback_error) {
          callback_error(error, response);
        } else {
          showModalError('Error', error);
        }
        return;
      }

      // Check for API error status
      if (result && result.status === 'error') {
        showModalError('Error', result.reason || result.message || 'An error occurred');
        return;
      }

      // Success
      if (callback) callback(result);
    })
    .catch((error) => {
      hideLoadingIndicator();
      if (callback_error) {
        callback_error(error.message, null);
      } else {
        showModalError('Error', 'Something went wrong, sorry.');
      }
    });
};

/** Promise-based API wrapper
 * @type {(url: string, method?: string, data?: any, headers?: Record<string, string>) => Promise<any>}
 */
export const apiAsync = (url, method = 'GET', data = null, headers = {}) => {
    return new Promise((resolve, reject) => {
        api(url, method, data, resolve, reject, headers);
    });
};
