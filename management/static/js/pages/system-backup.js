import { api } from '../core/api.js';
import {showModalError} from "../core/ui.js";

// ---- Helper Functions ----
function toggleForm() {
    const targetType = document.getElementById('backup-target-type').value;

    // Hide all backup sections
    document.querySelectorAll('.backup-target-local, .backup-target-rsync, .backup-target-s3, .backup-target-b2')
        .forEach(el => el.style.display = 'none');

    // Show selected section
    const section = document.querySelector(`.backup-target-${targetType}`);
    if (section) section.style.display = '';

    initInputs(targetType);
}

function niceSize(bytes) {
    const powers = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    let i = 0;
    while (bytes >= 1000 && i < powers.length - 1) {
        bytes /= 1024;
        i++;
    }
    bytes = bytes >= 100 ? Math.round(bytes) : Math.round(bytes * 10) / 10;
    return `${bytes} ${powers[i]}`;
}

function split1Rest(str, separator) {
    const idx = str.indexOf(separator);
    return idx >= 0 ? [str.substring(0, idx), str.substring(idx + separator.length)] : [undefined, str];
}

function urlSplit(url) {
    const [scheme, schemeRest] = split1Rest(url, '://');
    const [user, userRest] = split1Rest(schemeRest, '@');
    const [host, path] = split1Rest(userRest, '/');
    return { scheme, user, host, path };
}

// ---- Backup Display Functions ----
export function showSystemBackup() {
    showCustomBackup();

    const tbody = document.querySelector('#backup-status tbody');
    tbody.innerHTML = `<tr><td colspan="2" class="text-muted">Loading...</td></tr>`;

    api('/system/backup/status', 'GET', {}, (r) => {
        tbody.innerHTML = '';
        let totalDiskSize = 0;

        if (!r.backups) {
            tbody.innerHTML = `<tr><td colspan="3">Backups are turned off.</td></tr>`;
            return;
        }
        if (r.backups.length === 0) {
            tbody.innerHTML = `<tr><td colspan="3">No backups have been made yet.</td></tr>`;
        }

        r.backups.forEach(b => {
            const tr = document.createElement('tr');
            if (b.full) tr.classList.add('full-backup');

            // Date column
            const td1 = document.createElement('td');
            td1.textContent = b.date_str;
            tr.appendChild(td1);

            // Date delta column
            const td2 = document.createElement('td');
            td2.textContent = `${b.date_delta} ago`;
            tr.appendChild(td2);

            // Type column
            const td3 = document.createElement('td');
            td3.textContent = b.full ? 'full' : 'increment';
            tr.appendChild(td3);

            // Size column
            const td4 = document.createElement('td');
            td4.style.textAlign = 'right';
            td4.textContent = niceSize(b.size);
            tr.appendChild(td4);

            // Deleted in column
            const td5 = document.createElement('td');
            if (b.deleted_in) {
                td5.textContent = b.deleted_in;
            } else {
                const span = document.createElement('span');
                span.className = 'text-muted';
                span.textContent = 'unknown';
                td5.appendChild(span);
            }
            tr.appendChild(td5);

            tbody.appendChild(tr);
            totalDiskSize += b.size;
        });

        totalDiskSize += r.unmatched_file_size || 0;
        document.getElementById('backup-total-size').textContent = niceSize(totalDiskSize);
    });
}

function showCustomBackup() {
    document.querySelectorAll('.backup-target-local, .backup-target-rsync, .backup-target-s3, .backup-target-b2')
        .forEach(el => el.style.display = 'none');

    api('/system/backup/config', 'GET', {}, (r) => {
        document.getElementById('backup-target-user').value = r.target_user || '';
        document.getElementById('backup-target-pass').value = r.target_pass || '';
        document.getElementById('min-age').value = r.min_age_in_days || '';
        document.querySelectorAll('.backup-location').forEach(el => el.textContent = r.file_target_directory || '');
        document.querySelectorAll('.backup-encpassword-file').forEach(el => el.textContent = r.enc_pw_file || '');
        document.getElementById('ssh-pub-key').value = r.ssh_pub_key || '';

        let type = 'off';
        if (r.target === `file://${r.file_target_directory}`) type = 'local';
        else if (r.target === 'off') type = 'off';
        else if (r.target.startsWith('rsync://')) {
            type = 'rsync';
            const spec = urlSplit(r.target);
            document.getElementById('backup-target-rsync-user').value = spec.user || '';
            document.getElementById('backup-target-rsync-host').value = spec.host || '';
            document.getElementById('backup-target-rsync-path').value = spec.path || '';
        } else if (r.target.startsWith('s3://')) {
            type = 's3';
            const spec = urlSplit(r.target);
            document.getElementById('backup-target-s3-host-select').value = spec.host || '';
            document.getElementById('backup-target-s3-host').value = spec.host || '';
            document.getElementById('backup-target-s3-region-name').value = spec.user || '';
            document.getElementById('backup-target-s3-path').value = spec.path || '';
        } else if (r.target.startsWith('b2://')) {
            type = 'b2';
            const targetPath = r.target.substring(5);
            const b2AppKeyID = targetPath.split(':')[0];
            const b2AppKey = targetPath.split(':')[1].split('@')[0];
            const b2Bucket = targetPath.split('@')[1];
            document.getElementById('backup-target-b2-user').value = b2AppKeyID;
            document.getElementById('backup-target-b2-pass').value = decodeURIComponent(b2AppKey);
            document.getElementById('backup-target-b2-bucket').value = b2Bucket;
        }

        document.getElementById('backup-target-type').value = type;
        toggleForm();
    });
}

// ---- Backup Configuration Save ----
function setCustomBackup() {
    const targetType = document.getElementById('backup-target-type').value;
    let targetUser = document.getElementById('backup-target-user').value;
    let targetPass = document.getElementById('backup-target-pass').value;

    let target;
    if (targetType === 'local' || targetType === 'off') {
        target = targetType;
    } else if (targetType === 's3') {
        const region = document.getElementById('backup-target-s3-region-name').value;
        target = `s3://${region ? region + '@' : ''}${document.getElementById('backup-target-s3-host').value}/${document.getElementById('backup-target-s3-path').value}`;
    } else if (targetType === 'rsync') {
        target = `rsync://${document.getElementById('backup-target-rsync-user').value}@${document.getElementById('backup-target-rsync-host').value}/${document.getElementById('backup-target-rsync-path').value}`;
        targetUser = '';
    } else if (targetType === 'b2') {
        target = `b2://${document.getElementById('backup-target-b2-user').value}:${encodeURIComponent(document.getElementById('backup-target-b2-pass').value)}@${document.getElementById('backup-target-b2-bucket').value}`;
        targetUser = '';
        targetPass = '';
    }

    const minAge = document.getElementById('min-age').value;

    api('/system/backup/config', 'POST', {
        target, target_user: targetUser, target_pass: targetPass, min_age: minAge
    }, (r) => {
        showModalError("Backup configuration", r, () => { if (r === 'OK') showSystemBackup(); });
    }, (err) => {
        showModalError("Backup configuration", err);
    });

    return false;
}

// ---- Initialization Helpers ----
function initInputs(targetType) {
    if (targetType === 's3') {
        const select = document.getElementById('backup-target-s3-host-select');

        // Remove any existing listener first
        const newSelect = select.cloneNode(true);
        select.parentNode.replaceChild(newSelect, select);

        newSelect.addEventListener('change', () => {
            document.getElementById('backup-target-s3-host').value = newSelect.value !== 'other' ? newSelect.value : '';
        });
        newSelect.dispatchEvent(new Event('change'));
    }
}

// ---- Clipboard ----
function copyPubKeyToClipboard() {
    const sshKey = document.getElementById('ssh-pub-key').value;
    navigator.clipboard.writeText(sshKey);
}

const handleBackupSubmit = (e) => {
    e.preventDefault();
    setCustomBackup();
};

export function onBackupInit() {
    // Copy button setup
    const copyBtnDiv = document.getElementById('copy_pub_key_div');
    if (!(navigator && navigator.clipboard && navigator.clipboard.writeText)) {
        copyBtnDiv.hidden = true;
    } else {
        const copyBtn = document.getElementById('copy-pub-key-btn');
        if (copyBtn) {
            copyBtn.removeEventListener('click', copyPubKeyToClipboard);
            copyBtn.addEventListener('click', copyPubKeyToClipboard);
        }
    }

    // Backup target type change
    const targetTypeSelect = document.getElementById('backup-target-type');
    if (targetTypeSelect) {
        targetTypeSelect.removeEventListener('change', toggleForm);
        targetTypeSelect.addEventListener('change', toggleForm);
    }

    // Form submission
    const backupForm = document.getElementById('backup-config-form');
    if (backupForm) {
        backupForm.removeEventListener('submit', handleBackupSubmit);
        backupForm.addEventListener('submit', handleBackupSubmit);
    }

    // Call API to initialize backup page
    showSystemBackup();
}