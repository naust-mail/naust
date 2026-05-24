import { api } from '../core/api.js';
import { showModalConfirm, showModalError } from '../core/ui.js';

function showUsers() {
    const tbody = document.querySelector('#user_table tbody');
    tbody.innerHTML = `<tr><td colspan="2" class="text-muted">Loading...</td></tr>`;

    api('/mail/users', 'GET', { format: 'json' }, (r) => {
        tbody.innerHTML = '';

        r.forEach(domainEntry => {
            const hdr = document.createElement('tr');
            const th = document.createElement('th');
            th.setAttribute('colspan', '6');
            th.style.backgroundColor = '#EEE';
            th.textContent = domainEntry.domain;
            hdr.appendChild(th);
            tbody.appendChild(hdr);

            domainEntry.users.forEach(user => {
                const row = document.getElementById('user-template').cloneNode(true);
                const extra = document.getElementById('user-extra-template').cloneNode(true);

                row.id = '';
                extra.id = '';

                tbody.appendChild(row);
                tbody.appendChild(extra);

                row.classList.add(`account_${user.status}`);
                extra.classList.add(`account_${user.status}`);

                row.dataset.email = user.email;
                row.dataset.quota = user.quota;

                row.querySelector('.address').textContent = user.email;
                row.querySelector('.box-size').textContent = user.box_size;

                if (user.box_size === '?') {
                    row.querySelector('.box-size').title = 'Mailbox size is unknown';
                }

                row.querySelector('.percent').textContent = user.percent;
                row.querySelector('.quota').textContent = user.quota === '0' ? 'unlimited' : user.quota;
                extra.querySelector('.restore_info tt').textContent = user.mailbox;

                if (user.status === 'inactive') return;

                const privsContainer = row.querySelector('.privs');
                const addPrivsContainer = row.querySelector('.add-privs');

                const neededPrivs = ['admin'];

                user.privileges.forEach(priv => {
                    const span = document.createElement('span');

                    const b = document.createElement('b');
                    const nameSpan = document.createElement('span');
                    nameSpan.className = 'name';
                    nameSpan.textContent = priv;
                    b.appendChild(nameSpan);
                    span.appendChild(b);

                    span.appendChild(document.createTextNode(' ('));

                    const link = document.createElement('a');
                    link.href = '#';
                    link.title = 'Remove Privilege';
                    link.textContent = 'remove privilege';
                    link.addEventListener('click', (e) => {
                        e.preventDefault();
                        modPriv(link, 'remove');
                    });
                    span.appendChild(link);

                    span.appendChild(document.createTextNode(') | '));

                    privsContainer.appendChild(span);

                    const i = neededPrivs.indexOf(priv);
                    if (i >= 0) neededPrivs.splice(i, 1);
                });

                neededPrivs.forEach(priv => {
                    const span = document.createElement('span');

                    const link = document.createElement('a');
                    link.href = '#';
                    link.title = 'Add Privilege';
                    link.textContent = 'make ';

                    const nameSpan = document.createElement('span');
                    nameSpan.className = 'name';
                    nameSpan.textContent = priv;
                    link.appendChild(nameSpan);

                    link.addEventListener('click', (e) => {
                        e.preventDefault();
                        modPriv(link, 'add');
                    });
                    span.appendChild(link);
                    span.appendChild(document.createTextNode(' | '));

                    addPrivsContainer.appendChild(span);
                });
            });
        });
    });
}

function doAddUser() {
    const email = document.getElementById('adduserEmail').value;
    const pw = document.getElementById('adduserPassword').value;
    const privs = document.getElementById('adduserPrivs').value;
    const quota = document.getElementById('adduserQuota').value;

    api('/mail/users/add', 'POST',
        { email, password: pw, privileges: privs, quota },
        (r) => {
            showModalError('Add User', `<pre>${r}</pre>`);
            showUsers();
        },
        (err) => {
            showModalError('Add User', err);
        }
    );
    return false;
}

function usersSetPassword(elem) {
    const row = elem.closest('tr');
    const email = row.dataset.email;
    let warning = '';

    if (api_credentials && email === api_credentials.username) {
        warning = `<p class='text-danger'>Changing your own password logs you out.</p>`;
    }

    const modalContent = document.createElement('div');
    const p1 = document.createElement('p');
    p1.appendChild(document.createTextNode('Set a new password for '));
    const b = document.createElement('b');
    b.textContent = email;
    p1.appendChild(b);
    p1.appendChild(document.createTextNode('?'));
    modalContent.appendChild(p1);

    const p2 = document.createElement('p');
    const label = document.createElement('label');
    label.style.display = 'block';
    label.style.fontWeight = 'normal';
    label.textContent = 'New Password:';
    p2.appendChild(label);
    const input = document.createElement('input');
    input.type = 'password';
    input.id = 'users_set_password_pw';
    p2.appendChild(input);
    modalContent.appendChild(p2);

    const p3 = document.createElement('p');
    const small = document.createElement('small');
    small.textContent = 'Minimum eight chars, no spaces.';
    p3.appendChild(small);
    modalContent.appendChild(p3);

    if (warning) {
        const warningP = document.createElement('p');
        warningP.className = 'text-danger';
        warningP.textContent = 'Changing your own password logs you out.';
        modalContent.appendChild(warningP);
    }

    showModalConfirm(
        'Set Password',
        modalContent,
        'Set Password',
        () => {
            const newpw = document.getElementById('users_set_password_pw').value;
            api(
                '/mail/users/password',
                'POST',
                { email, password: newpw },
                (r) => showModalError('Set Password', `<pre>${r}</pre>`),
                (err) => showModalError('Set Password', err)
            );
        }
    );
}

function usersSetQuota(elem) {
    const row = elem.closest('tr');
    const email = row.dataset.email;
    const quota = row.dataset.quota;

    const modalContent = document.createElement('div');
    const p1 = document.createElement('p');
    p1.appendChild(document.createTextNode('Set quota for '));
    const b = document.createElement('b');
    b.textContent = email;
    p1.appendChild(b);
    p1.appendChild(document.createTextNode('?'));
    modalContent.appendChild(p1);

    const p2 = document.createElement('p');
    const label = document.createElement('label');
    label.style.display = 'block';
    label.style.fontWeight = 'normal';
    label.textContent = 'Quota:';
    p2.appendChild(label);
    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'users_set_quota';
    input.value = quota;
    p2.appendChild(input);
    modalContent.appendChild(p2);

    const p3 = document.createElement('p');
    const small = document.createElement('small');
    small.textContent = 'No spaces, commas; G/M suffix allowed. 0 = unlimited.';
    p3.appendChild(small);
    modalContent.appendChild(p3);

    showModalConfirm(
        'Set Quota',
        modalContent,
        'Set Quota',
        () => {
            const newQuota = document.getElementById('users_set_quota').value;
            api(
                '/mail/users/quota',
                'POST',
                { email, quota: newQuota },
                () => showUsers(),
                (err) => showModalError('Set Quota', err)
            );
        }
    );
}

function usersRemove(elem) {
    const row = elem.closest('tr');
    const email = row.dataset.email;

    if (api_credentials && email === api_credentials.username) {
        showModalError('Archive User', 'You cannot archive yourself.');
        return;
    }

    const modalContent = document.createElement('div');
    const p1 = document.createElement('p');
    p1.appendChild(document.createTextNode('Archive '));
    const b = document.createElement('b');
    b.textContent = email;
    p1.appendChild(b);
    p1.appendChild(document.createTextNode('?'));
    modalContent.appendChild(p1);

    const p2 = document.createElement('p');
    p2.textContent = 'Mailboxes stay on disk. The user loses all login access.';
    modalContent.appendChild(p2);

    showModalConfirm(
        'Archive User',
        modalContent,
        'Archive',
        () => {
            api(
                '/mail/users/remove',
                'POST',
                { email },
                (r) => {
                    showModalError('Remove User', `<pre>${r}</pre>`);
                    showUsers();
                },
                (err) => showModalError('Remove User', err)
            );
        }
    );
}

function modPriv(elem, action) {
    const row = elem.closest('tr');
    const email = row.dataset.email;
    const priv = elem.closest('td').querySelector('.name').textContent;

    if (priv === 'admin' && action === 'remove' &&
        api_credentials && email === api_credentials.username) {
        showModalError('Modify Privileges', 'You cannot remove admin from yourself.');
        return;
    }

    const label = action.charAt(0).toUpperCase() + action.substring(1);

    const modalContent = document.createElement('div');
    const p = document.createElement('p');
    p.appendChild(document.createTextNode(`${action} privilege `));
    const b1 = document.createElement('b');
    b1.textContent = priv;
    p.appendChild(b1);
    p.appendChild(document.createTextNode(' for '));
    const b2 = document.createElement('b');
    b2.textContent = email;
    p.appendChild(b2);
    p.appendChild(document.createTextNode('?'));
    modalContent.appendChild(p);

    showModalConfirm(
        'Modify Privileges',
        modalContent,
        label,
        () => {
            api(`/mail/users/privileges/${action}`, 'POST',
                { email, privilege: priv },
                () => showUsers()
            );
        }
    );
}

function generateRandomPassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    let pw = '';
    // Use cryptographically secure random number generator
    const randomValues = new Uint32Array(12);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < 12; i++) {
        pw += chars[randomValues[i] % chars.length];
    }
    showModalError('Random Password',
        `<p>Here, try this:</p><p><code style="font-size:110%">${pw}</code></p>`
    );
    return false;
}

const handleAddUserSubmit = (e) => {
    e.preventDefault();
    doAddUser();
};

const handleGeneratePassword = (e) => {
    e.preventDefault();
    generateRandomPassword();
};

const handleUserTableClick = (e) => {
    const action = e.target.dataset.action;
    if (!action) return;

    e.preventDefault();
    const elem = e.target;

    if (action === 'set-password') usersSetPassword(elem);
    if (action === 'set-quota') usersSetQuota(elem);
    if (action === 'remove-user') usersRemove(elem);
};

export function initUserManagement() {
    // Load table immediately
    showUsers();

    // Add user form submission
    const addForm = document.getElementById('adduser_form');
    if (addForm) {
        addForm.removeEventListener('submit', handleAddUserSubmit);
        addForm.addEventListener('submit', handleAddUserSubmit);
    }

    // Generate random password link
    const generatePwLink = document.getElementById('generate-random-password');
    if (generatePwLink) {
        generatePwLink.removeEventListener('click', handleGeneratePassword);
        generatePwLink.addEventListener('click', handleGeneratePassword);
    }

    // Delegate button clicks for password, quota, remove, etc.
    const table = document.getElementById('user_table');
    if (table) {
        table.removeEventListener('click', handleUserTableClick);
        table.addEventListener('click', handleUserTableClick);
    }
}
