import { api } from '../core/api.js';
import { showModalError, showModalConfirm } from '../core/ui.js';

let isAliasAddUpdate = false;

function showAliases() {
    const tbody = document.querySelector('#alias_table tbody');
    tbody.innerHTML = "<tr><td colspan='2' class='text-muted'>Loading...</td></tr>";

    api("/mail/aliases", "GET", { format: 'json' }, (r) => {
        tbody.innerHTML = "";

        r.forEach(domainEntry => {
            const hdr = document.createElement('tr');
            const th = document.createElement('th');
            th.setAttribute('colspan', '4');
            th.setAttribute('role', 'heading');
            th.setAttribute('aria-level', '4');
            th.style.backgroundColor = '#EEE';
            th.textContent = domainEntry.domain;
            hdr.appendChild(th);
            tbody.appendChild(hdr);

            domainEntry.aliases.forEach(alias => {
                const row = document.getElementById('alias-template').cloneNode(true);
                row.id = '';

                if (alias.auto) row.classList.add('alias-auto');
                row.dataset.address = alias.address_display;

                row.querySelector('td.address').textContent = alias.address_display;

                const forwardsTd = row.querySelector('td.forwardsTo');
                alias.forwards_to.forEach(forward => {
                    const div = document.createElement('div');
                    div.textContent = forward;
                    forwardsTd.appendChild(div);
                });

                const sendersTd = row.querySelector('td.senders');
                if (alias.permitted_senders) {
                    alias.permitted_senders.forEach(sender => {
                        const div = document.createElement('div');
                        div.textContent = sender;
                        sendersTd.appendChild(div);
                    });
                }

                tbody.appendChild(row);
            });
        });
    });

    initAliasTypeButtons();
}

function initAliasTypeButtons() {
    const buttons = document.querySelectorAll('#alias_type_buttons button');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('#addalias-form .regularalias, #addalias-form .catchall, #addalias-form .domainalias')
                .forEach(el => el.classList.add('hidden'));

            const mode = btn.dataset.mode;
            const addressInput = document.getElementById('addaliasAddress');
            const forwardsToInput = document.getElementById('addaliasForwardsTo');
            const modeInfo = document.getElementById('alias_mode_info');

            if (mode === "regular") {
                addressInput.type = 'email';
                addressInput.placeholder = 'you@yourdomain.com (incoming email address)';
                forwardsToInput.placeholder = 'one address per line or separated by commas';
                modeInfo.style.display = 'none';
                document.querySelectorAll('#addalias-form .regularalias').forEach(el => el.classList.remove('hidden'));
            } else if (mode === "catchall") {
                addressInput.type = 'text';
                addressInput.placeholder = '@yourdomain.com (incoming catch-all domain)';
                forwardsToInput.placeholder = 'one address per line or separated by commas';
                modeInfo.style.display = 'block';
                document.querySelectorAll('#addalias-form .catchall').forEach(el => el.classList.remove('hidden'));
            } else if (mode === "domainalias") {
                addressInput.type = 'text';
                addressInput.placeholder = '@yourdomain.com (incoming catch-all domain)';
                forwardsToInput.placeholder = '@otherdomain.com (forward to other domain)';
                modeInfo.style.display = 'block';
                document.querySelectorAll('#addalias-form .domainalias').forEach(el => el.classList.remove('hidden'));
            }
        });
    });

    // Initialize with regular mode
    const regularBtn = document.querySelector('#alias_type_buttons button[data-mode="regular"]');
    if (regularBtn) regularBtn.click();
}

function doAddAlias() {
    const title = (!isAliasAddUpdate) ? "Add Alias" : "Update Alias";
    const formAddress = document.getElementById('addaliasAddress').value;
    const formForwardsTo = document.getElementById('addaliasForwardsTo').value;
    const isAdvanced = document.getElementById('addaliasForwardsToAdvanced').checked;
    const formSenders = isAdvanced ? document.getElementById('addaliasSenders').value : '';

    if (isAdvanced && !/\S/.exec(document.getElementById('addaliasSenders').value)) {
        showModalError(title, "You did not enter any permitted senders.");
        return false;
    }

    api("/mail/aliases/add", "POST", {
        update_if_exists: isAliasAddUpdate ? '1' : '0',
        address: formAddress,
        forwards_to: formForwardsTo,
        permitted_senders: formSenders
    }, (r) => {
        const pre = document.createElement('pre');
        pre.textContent = r;
        showModalError(title, pre.outerHTML);
        showAliases();
        aliasesResetForm();
    }, (r) => {
        showModalError(title, r);
    });

    return false;
}

function aliasesResetForm() {
    document.getElementById('addaliasAddress').disabled = false;
    document.getElementById('addaliasAddress').value = '';
    document.getElementById('addaliasForwardsTo').value = '';
    document.getElementById('addaliasSenders').value = '';
    document.getElementById('alias-cancel').classList.add('hidden');
    document.getElementById('add-alias-button').textContent = 'Add Alias';
    isAliasAddUpdate = false;
}

function aliasesEdit(elem) {
    const row = elem.closest('tr');
    const address = row.dataset.address;
    const receiverDivs = row.querySelectorAll('.forwardsTo div');
    const senderDivs = row.querySelectorAll('.senders div');

    let forwardsTo = "";
    receiverDivs.forEach(div => {
        forwardsTo += div.textContent + "\n";
    });

    let senders = "";
    senderDivs.forEach(div => {
        senders += div.textContent + "\n";
    });

    if (address.charAt(0) === '@' && forwardsTo.charAt(0) === '@') {
        document.querySelector('#alias_type_buttons button[data-mode="domainalias"]').click();
    } else if (address.charAt(0) === '@') {
        document.querySelector('#alias_type_buttons button[data-mode="catchall"]').click();
    } else {
        document.querySelector('#alias_type_buttons button[data-mode="regular"]').click();
    }

    document.getElementById('alias-cancel').classList.remove('hidden');
    document.getElementById('addaliasAddress').disabled = true;
    document.getElementById('addaliasAddress').value = address;
    document.getElementById('addaliasForwardsTo').value = forwardsTo;
    document.getElementById('addaliasForwardsToAdvanced').checked = senders !== "";
    document.getElementById('addaliasForwardsToNotAdvanced').checked = senders === "";
    document.getElementById('addaliasSenders').value = senders;
    document.getElementById('add-alias-button').textContent = 'Update';
    window.scrollTo({ top: 0, behavior: 'smooth' });
    isAliasAddUpdate = true;
}

function aliasesRemove(elem) {
    const row = elem.closest('tr');
    const rowAddress = row.dataset.address;

    const modalContent = document.createElement('p');
    modalContent.appendChild(document.createTextNode('Remove '));
    modalContent.appendChild(document.createTextNode(rowAddress));
    modalContent.appendChild(document.createTextNode('?'));

    showModalConfirm("Remove Alias", modalContent, "Remove", () => {
        api("/mail/aliases/remove", "POST", { address: rowAddress }, (r) => {
            const pre = document.createElement('pre');
            pre.textContent = r;
            showModalError("Remove Alias", pre.outerHTML);
            showAliases();
        });
    });
}

const handleAddAliasSubmit = (e) => {
    e.preventDefault();
    doAddAlias();
};

const handleAliasCancel = (e) => {
    e.preventDefault();
    aliasesResetForm();
};

const handleNotAdvancedChange = () => {
    const notAdvancedRadio = document.getElementById('addaliasForwardsToNotAdvanced');
    const sendersDiv = document.getElementById('addaliasForwardsToDiv');
    if (notAdvancedRadio.checked) {
        sendersDiv.style.display = 'none';
    }
};

const handleAdvancedChange = () => {
    const advancedRadio = document.getElementById('addaliasForwardsToAdvanced');
    const sendersDiv = document.getElementById('addaliasForwardsToDiv');
    if (advancedRadio.checked) {
        sendersDiv.style.display = 'block';
    }
};

const handleAliasTableClick = (e) => {
    const action = e.target.closest('a')?.dataset.action;
    if (!action) return;

    e.preventDefault();
    const elem = e.target.closest('a');

    if (action === 'edit') {
        aliasesEdit(elem);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    if (action === 'remove') aliasesRemove(elem);
};

export function initAliases() {
    // Load aliases immediately
    showAliases();

    // Form submission
    const addForm = document.getElementById('addalias-form');
    if (addForm) {
        addForm.removeEventListener('submit', handleAddAliasSubmit);
        addForm.addEventListener('submit', handleAddAliasSubmit);
    }

    // Cancel button
    const cancelBtn = document.getElementById('alias-cancel');
    if (cancelBtn) {
        cancelBtn.removeEventListener('click', handleAliasCancel);
        cancelBtn.addEventListener('click', handleAliasCancel);
    }

    // Radio button toggles for permitted senders
    const notAdvancedRadio = document.getElementById('addaliasForwardsToNotAdvanced');
    const advancedRadio = document.getElementById('addaliasForwardsToAdvanced');

    if (notAdvancedRadio) {
        notAdvancedRadio.removeEventListener('change', handleNotAdvancedChange);
        notAdvancedRadio.addEventListener('change', handleNotAdvancedChange);
    }

    if (advancedRadio) {
        advancedRadio.removeEventListener('change', handleAdvancedChange);
        advancedRadio.addEventListener('change', handleAdvancedChange);
    }

    // Delegate edit/remove actions in table
    const aliasTable = document.getElementById('alias_table');
    if (aliasTable) {
        aliasTable.removeEventListener('click', handleAliasTableClick);
        aliasTable.addEventListener('click', handleAliasTableClick);
    }
}
