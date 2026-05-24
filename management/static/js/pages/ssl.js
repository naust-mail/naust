import { api } from '../core/api.js';
import { showModalError } from '../core/ui.js';

export function show_tls(keepProvisioningShown = false) {
    api("/ssl/status", "GET", {}, (res) => {
        const sslProvision = document.getElementById('ssl_provision');
        const sslProvisionP = document.getElementById('ssl_provision_p');
        const ssldomainSelect = document.getElementById('ssldomain');
        const sslDomainsTable = document.getElementById('ssl_domains').querySelector('tbody');

        // provisioning status
        if (!keepProvisioningShown) sslProvision.style.display = res.can_provision.length > 0 ? '' : 'none';
        sslProvisionP.style.display = res.can_provision.length > 0 ? '' : 'none';

        if (res.can_provision.length > 0) {
            sslProvisionP.querySelector('span').textContent = res.can_provision.join(", ");
        }

        // certificate status
        sslDomainsTable.innerHTML = '';
        ssldomainSelect.innerHTML = '<option value="">(select)</option>';
        document.getElementById('ssl_domains').style.display = '';

        for (const domain of res.status) {
            const tr = document.createElement('tr');
            tr.dataset.domain = domain.domain;

            // Create domain column
            const th = document.createElement('th');
            th.scope = 'row';
            th.className = 'domain';
            const domainLink = document.createElement('a');
            domainLink.href = `https://${domain.domain}`;
            domainLink.textContent = domain.domain;
            th.appendChild(domainLink);
            tr.appendChild(th);

            // Create status column
            const statusTd = document.createElement('td');
            statusTd.className = 'status';
            statusTd.textContent = domain.text;
            tr.appendChild(statusTd);

            // Create actions column
            const actionsTd = document.createElement('td');
            actionsTd.className = 'actions';
            if (domain.status !== 'not-applicable') {
                const btnClass = domain.status === 'success' ? 'btn btn-xs btn-default' : 'btn btn-xs btn-primary';
                const btnText = domain.status === 'success' ? 'Replace Certificate' : 'Install Certificate';
                const btn = document.createElement('a');
                btn.href = '#';
                btn.className = btnClass;
                btn.dataset.action = 'install-cert';
                btn.textContent = btnText;
                actionsTd.appendChild(btn);
            }
            tr.appendChild(actionsTd);

            if (domain.status === 'not-applicable') {
                domain.status = 'muted';
            }

            tr.classList.add(`text-${domain.status}`);
            sslDomainsTable.appendChild(tr);

            const option = document.createElement('option');
            option.textContent = domain.domain;
            ssldomainSelect.appendChild(option);
        }
    });
}

function sslInstall(elem) {
    const tr = elem.closest('tr');
    const domain = tr.dataset.domain;

    const ssldomain = document.getElementById('ssldomain');
    ssldomain.value = domain;

    showCsr();

    const offset = document.getElementById('ssl_install_header').offsetTop - document.querySelector('.navbar-fixed-top').offsetHeight - 20;
    window.scrollTo({ top: offset, behavior: 'smooth' });
}

function showCsr() {
    const ssldomain = document.getElementById('ssldomain').value;
    const sslcc = document.getElementById('sslcc').value;

    if (!ssldomain || !sslcc) return;

    const csrInfo = document.getElementById('csr_info');
    const sslCsr = document.getElementById('ssl_csr');

    csrInfo.style.display = '';
    sslCsr.textContent = 'Loading...';

    api(`/ssl/csr/${ssldomain}`, "POST", { countrycode: sslcc }, (data) => {
        sslCsr.textContent = data;
    });
}

function installCert() {
    const ssldomain = document.getElementById('ssldomain').value;
    const cert = document.getElementById('ssl_paste_cert').value;
    const chain = document.getElementById('ssl_paste_chain').value;

    api("/ssl/install", "POST", { domain: ssldomain, cert, chain }, (status) => {
        if (/^OK($|\n)/.test(status)) {
            console.log(status);
            showModalError(
                "TLS Certificate Installation",
                "Certificate has been installed. Check that you have no connection problems to the domain.",
                () => {
                    show_tls();
                    document.getElementById('csr_info').style.display = 'none';
                }
            );
        } else {
            showModalError("TLS Certificate Installation", status);
        }
    });
}

function provisionTlsCert() {
    const provisionBtn = document.getElementById('provision-tls-btn');
    provisionBtn.disabled = true;

    api("/ssl/provision", "POST", {}, (status) => {
        const resultContainer = document.getElementById('ssl_provision_result');
        resultContainer.textContent = '';

        let mayReenableProvisionButton = true;

        if (status.requests.length === 0) {
            showModalError("TLS Certificate Provisioning", "There were no domain names to provision certificates for.");
        }

        for (const r of status.requests) {
            if (r.result === "skipped") continue;

            const div = document.createElement('div');
            const h4 = document.createElement('h4');
            const p = document.createElement('p');
            div.append(h4, p);

            if (typeof r === 'string') {
                p.textContent = r;
            } else {
                if (status.requests.length > 1) h4.textContent = r.domains.join(", ");

                if (r.result === "error") {
                    p.classList.add('text-danger');
                    p.textContent = r.message;
                } else if (r.result === "installed") {
                    p.classList.add('text-success');
                    p.textContent = "The TLS certificate was provisioned and installed.";
                    setTimeout(() => show_tls(true), 1);
                }

                const traceDiv = document.createElement('div');
                traceDiv.className = 'small text-muted';
                traceDiv.style.marginTop = '1.5em';
                traceDiv.textContent = 'Log:';
                div.appendChild(traceDiv);

                for (const logLine of r.log) {
                    const logEntry = document.createElement('div');
                    logEntry.textContent = logLine;
                    traceDiv.appendChild(logEntry);
                }
            }

            resultContainer.appendChild(div);
        }

        if (mayReenableProvisionButton) provisionBtn.disabled = false;
    });
}

const handleProvisionClick = (e) => {
    e.preventDefault();
    provisionTlsCert();
};

const handleInstallCertClick = (e) => {
    e.preventDefault();
    installCert();
};

const handleSslTableClick = (e) => {
    const action = e.target.dataset.action;
    if (action === 'install-cert') {
        e.preventDefault();
        sslInstall(e.target);
    }
};

// Initialize event listeners
export function initSsl() {
    // Load SSL status
    show_tls();

    // Provision button
    const provisionBtn = document.getElementById('provision-tls-btn');
    if (provisionBtn) {
        provisionBtn.removeEventListener('click', handleProvisionClick);
        provisionBtn.addEventListener('click', handleProvisionClick);
    }

    // Domain and country selects
    const ssldomainSelect = document.getElementById('ssldomain');
    if (ssldomainSelect) {
        ssldomainSelect.removeEventListener('change', showCsr);
        ssldomainSelect.addEventListener('change', showCsr);
    }

    const sslccSelect = document.getElementById('sslcc');
    if (sslccSelect) {
        sslccSelect.removeEventListener('change', showCsr);
        sslccSelect.addEventListener('change', showCsr);
    }

    // Install cert button
    const installBtn = document.getElementById('install-cert-btn');
    if (installBtn) {
        installBtn.removeEventListener('click', handleInstallCertClick);
        installBtn.addEventListener('click', handleInstallCertClick);
    }

    // Delegate cert install links in table
    const sslDomainsTable = document.getElementById('ssl_domains');
    if (sslDomainsTable) {
        sslDomainsTable.removeEventListener('click', handleSslTableClick);
        sslDomainsTable.addEventListener('click', handleSslTableClick);
    }
}
