import { api } from '../core/api.js';
import { getState, setState } from '../core/state.js';
import { saveCredentials, clear } from '../core/auth.js'
import { showPanel } from '../core/router.js'
import { showModalError } from '../core/ui.js';

function doLogin() {
  const emailInput = document.getElementById('loginEmail');
  const passwordInput = document.getElementById('loginPassword');
  const otpInput = document.getElementById('loginOtpInput');
  const rememberCheckbox = document.getElementById('loginRemember');

  const email = emailInput.value.trim();
  const password = passwordInput.value;
  const otp = otpInput.value;

  if (!email) { showModalError('Login Failed', 'Enter your email address.', () => emailInput.focus()); return false; }
  if (!password) { showModalError('Login Failed', 'Enter your email password.', () => passwordInput.focus()); return false; }

  setState({ credentials: { username: email, session_key: password, privileges: [] } });

  api('/login','POST',{},(response)=>{
    if (response.status !== 'ok') {
      if (response.status === 'missing-totp-token' || (response.status === 'invalid' && response.reason === 'invalid-totp-token')) {
        document.getElementById('loginForm').classList.add('is-twofactor');
        if (response.reason === 'invalid-totp-token') {
          showModalError('Login Failed', 'Incorrect two factor authentication token.');
        } else { setTimeout(() => otpInput.focus(), 100); }
      } else {
        document.getElementById('loginForm').classList.remove('is-twofactor');
        showModalError('Login Failed', response.reason || 'Login failed. Please try again.');
        clear();
      }
    } else if (!response.api_key) {
      showModalError('Login Failed', 'You are not an administrator on this system.');
      clear();
    } else {
      const credentials = { username: response.email, session_key: response.api_key, privileges: response.privileges };
      emailInput.value = ''; passwordInput.value = ''; otpInput.value = '';
      document.getElementById('loginForm').classList.remove('is-twofactor');
      saveCredentials(credentials, rememberCheckbox.checked);
      setTimeout(() => {
        const state = getState();
        let targetPanel = window.location.hash ? window.location.hash.substring(1) : (!state.switchBackToPanel || state.switchBackToPanel === 'login') ? 'welcome' : state.switchBackToPanel;
        showPanel(targetPanel);
      }, 300);
    }
  }, (error) => {
    // Handle network errors and HTTP errors
    document.getElementById('loginForm').classList.remove('is-twofactor');
    showModalError('Login Failed', typeof error === 'string' ? error : 'Unable to connect to the server. Please try again.');
    clear();
  }, { 'x-auth-token': otp });

  return false;
}

const handleLoginSubmit = (e) => {
  e.preventDefault();
  doLogin();
};

export function showLogin() {
  const form = document.getElementById('loginForm');
  const emailInput = document.getElementById('loginEmail');
  const passwordInput = document.getElementById('loginPassword');
  const otpInput = document.getElementById('loginOtpInput');

  // we need to remove previous listener to avoid multiple registrations
  // I prefered to do this over using
  form.removeEventListener('submit', handleLoginSubmit);
  form.addEventListener('submit', handleLoginSubmit);
  form.classList.remove('is-twofactor');
  otpInput.value = '';

  if (!emailInput.value.trim()) { emailInput.focus(); }
  else if (!passwordInput.value) { passwordInput.focus(); }
}
