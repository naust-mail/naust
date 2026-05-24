import { api } from '../core/api.js';
import { showModalError, showModalConfirm } from '../core/ui.js';

function showWeb() {
    api("/web/domains", "GET", {}, (domains) => {
        const tbody = document.querySelector('#web_domains_existing tbody');
        tbody.innerHTML = '';

        domains.forEach(domain => {
            if (!domain.static_enabled) return;

            const row = document.createElement('tr');
            row.dataset.domain = domain.domain;
            row.dataset.customWebRoot = domain.custom_root;

            // Domain column
            const domainTh = document.createElement('th');
            domainTh.scope = 'row';
            domainTh.className = 'domain';
            const domainLink = document.createElement('a');
            domainLink.href = `https://${domain.domain}`;
            domainLink.textContent = `https://${domain.domain}`;
            domainTh.appendChild(domainLink);
            row.appendChild(domainTh);

            // Directory column
            const directoryTd = document.createElement('td');
            directoryTd.className = 'directory';
            const directoryTt = document.createElement('tt');
            directoryTt.textContent = domain.root;
            directoryTd.appendChild(directoryTt);
            row.appendChild(directoryTd);

            // Change button column
            const changeRootTd = document.createElement('td');
            changeRootTd.className = 'change-root';
            if (domain.root !== domain.custom_root) {
                const changeBtn = document.createElement('button');
                changeBtn.className = 'btn btn-default btn-xs';
                changeBtn.textContent = 'Change';
                changeBtn.dataset.action = 'change-root';
                changeRootTd.appendChild(changeBtn);
            } else {
                changeRootTd.classList.add('hidden');
            }
            row.appendChild(changeRootTd);

            tbody.appendChild(row);
        });
    });
}

function doWebUpdate() {
    api("/web/update", "POST", {}, (data) => {
        let message;
        if (data === "") {
            message = "Nothing changed.";
        } else {
            const pre = document.createElement('pre');
            pre.textContent = data;
            message = pre.outerHTML;
        }
        showModalError("Web Update", message, () => {
            showWeb();
        });
    });
}

function showChangeWebRoot(elem) {
    const row = elem.closest('tr');
    const domain = row.dataset.domain;
    const root = row.dataset.customWebRoot;

    const message = `
        <p>You can change the static directory for <tt>${domain}</tt> to:</p>
        <p><tt>${root}</tt></p>
        <p>First create this directory on the server. Then click Update to scan for the directory and update web settings.</p>
    `;

    showModalConfirm(
        `Change Root Directory for ${domain}`,
        message,
        'Update',
        () => {
            doWebUpdate();
        }
    );
}

const handleWebTableClick = (e) => {
    const action = e.target.dataset.action;
    if (action === 'change-root') {
        e.preventDefault();
        showChangeWebRoot(e.target);
    }
};

export function initWeb() {
    // Load web domains
    showWeb();

    // Delegate click events for change buttons
    const table = document.getElementById('web_domains_existing');
    if (table) {
        table.removeEventListener('click', handleWebTableClick);
        table.addEventListener('click', handleWebTableClick);
    }
}
