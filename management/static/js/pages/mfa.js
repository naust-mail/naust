import { api } from '../core/api.js';
import { logout } from "../core/auth.js";

const el = {
    disableForm: null,
    output: null,
    totpSetupForm: null,
    totpSetupToken: null,
    totpSetupSecret: null,
    totpSetupLabel: null,
    totpQr: null,
    totpSetupSubmit: null,
    wrapper: null
};

function updateSetupDisabled(evt) {
    const val = evt.target.value.trim();

    if (
        typeof val !== 'string' ||
        typeof el.totpSetupSecret.value !== 'string' ||
        val.length !== 6 ||
        el.totpSetupSecret.value.length !== 32 ||
        !(/^\+?\d+$/.test(val))
    ) {
        el.totpSetupSubmit.setAttribute('disabled', '');
    } else {
        el.totpSetupSubmit.removeAttribute('disabled');
    }
}

function renderTotpSetup(provisionedTotp) {
    const img = document.createElement('img');
    img.src = "data:image/png;base64," + provisionedTotp.qr_code_base64;

    const code = document.createElement('div');
    code.textContent = `Secret: ${provisionedTotp.secret}`;

    el.totpQr.appendChild(img);
    el.totpQr.appendChild(code);

    el.totpSetupToken.removeEventListener('input', updateSetupDisabled);
    el.totpSetupToken.addEventListener('input', updateSetupDisabled);

    el.totpSetupForm.removeEventListener('submit', doEnableTotp);
    el.totpSetupForm.addEventListener('submit', doEnableTotp);

    el.totpSetupSecret.setAttribute('value', provisionedTotp.secret);

    el.wrapper.classList.add('disabled');
}

function renderDisable(mfa) {
    el.disableForm.removeEventListener('submit', doDisable);
    el.disableForm.addEventListener('submit', doDisable);

    el.wrapper.classList.add('enabled');

    if (mfa.label) {
        const deviceLabel = document.getElementById('mfa-device-label');
        deviceLabel.textContent = " on device '" + mfa.label + "'";
    }
}

function hideError() {
    el.output.querySelector('.panel-body').innerHTML = '';
    el.output.classList.remove('visible');
}

function renderError(msg) {
    el.output.querySelector('.panel-body').innerHTML = msg;
    el.output.classList.add('visible');
}

function resetView() {
    el.wrapper.classList.remove('loaded', 'disabled', 'enabled');

    el.disableForm.removeEventListener('submit', doDisable);

    hideError();

    el.totpSetupForm.reset();
    el.totpSetupForm.removeEventListener('submit', doEnableTotp);

    el.totpSetupSecret.setAttribute('value', '');
    el.totpSetupToken.removeEventListener('input', updateSetupDisabled);

    el.totpSetupSubmit.setAttribute('disabled', '');
    el.totpQr.innerHTML = '';
}

function doDisable(evt) {
    evt.preventDefault();
    hideError();

    api('/mfa/disable', 'POST', {}, () => {
        logout();
    });

    return false;
}

function doEnableTotp(evt) {
    evt.preventDefault();
    hideError();

    api('/mfa/totp/enable', 'POST', {
        token: el.totpSetupToken.value,
        secret: el.totpSetupSecret.value,
        label: el.totpSetupLabel.value
    }, () => {
        logout();
    }, (res) => {
        renderError(res);
    });

    return false;
}

export function showMfa() {
    // Initialize element references
    el.disableForm = document.getElementById('disable-2fa');
    el.output = document.getElementById('output-2fa');
    el.totpSetupForm = document.getElementById('totp-setup');
    el.totpSetupToken = document.getElementById('totp-setup-token');
    el.totpSetupSecret = document.getElementById('totp-setup-secret');
    el.totpSetupLabel = document.getElementById('totp-setup-label');
    el.totpQr = document.getElementById('totp-setup-qr');
    el.totpSetupSubmit = document.querySelector('#totp-setup-submit');
    el.wrapper = document.querySelector('.twofactor');

    resetView();

    api('/mfa/status', 'POST', {}, (res) => {
        el.wrapper.classList.add('loaded');

        let hasMfa = false;
        res.enabled_mfa.forEach(mfa => {
            if (mfa.type === "totp") {
                renderDisable(mfa);
                hasMfa = true;
            }
        });

        if (!hasMfa) {
            renderTotpSetup(res.new_mfa.totp);
        }
    });
}
