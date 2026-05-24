import { api } from '../core/api.js';
import { showModalConfirm, showModalError } from '../core/ui.js';

let current_privacy_setting = null;

/**
 * Create a status row element
 * @type {(item: any, count_by_status: any, ok_symbol: string, error_symbol: string, warning_symbol: string) => HTMLTableRowElement}
 */
function createStatusRow(item, count_by_status, ok_symbol, error_symbol, warning_symbol) {
    const tr = document.createElement('tr');
    const statusTd = document.createElement('td');
    statusTd.className = 'status';
    const messageTd = document.createElement('td');
    messageTd.className = 'message';

    const p = document.createElement('p');
    p.style.margin = 0;
    p.textContent = item.text;
    messageTd.appendChild(p);

    const extraDiv = document.createElement('div');
    extraDiv.className = 'extra';
    messageTd.appendChild(extraDiv);

    const showMore = document.createElement('a');
    showMore.className = 'showhide';
    showMore.textContent = "show more";
    showMore.href = "#";
    showMore.addEventListener('click', (e) => {
        e.preventDefault();
        showMore.style.display = 'none';
        extraDiv.style.display = 'block';
    });
    messageTd.appendChild(showMore);

    if(item.type === 'ok') {
        statusTd.textContent = ok_symbol;
        count_by_status.ok++;
        tr.classList.add('bg-row-success');
        statusTd.classList.add('text-success');
        messageTd.classList.add('text-success');
    }
    if(item.type === 'error') {
        statusTd.textContent = error_symbol;
        count_by_status.error++;
        tr.classList.add('bg-row-danger');
        statusTd.classList.add('text-danger');
        messageTd.classList.add('text-danger');
    }
    if(item.type === 'warning') {
        statusTd.textContent = warning_symbol;
        count_by_status.warning++;
        tr.classList.add('bg-row-warning');
        statusTd.classList.add('text-warning');
        messageTd.classList.add('text-warning');
    }

    // extras - filter out empty text and render content
    const hasExtras = item.extra && item.extra.length > 0 && item.extra.some(e => e.text && e.text.trim());
    if(hasExtras) {
        item.extra.forEach(extraItem => {
            // Skip empty text items
            if (!extraItem.text || !extraItem.text.trim()) return;

            const div = document.createElement('div');
            div.textContent = extraItem.text;
            if(extraItem.monospace) div.classList.add('pre');
            extraDiv.appendChild(div);
        });
        // Only show the "show more" link if there's actual content
        showMore.style.display = 'inline';
    }

    tr.appendChild(statusTd);
    tr.appendChild(messageTd);
    return tr;
}

export function show_system_status() {
    const summary = document.getElementById('system-checks-summary');
    summary.textContent = "";

    const container = document.getElementById('system-checks-container');
    container.innerHTML = "<div class='text-muted'>Loading...</div>";

    // Setup event listeners
    setupEventListeners();

    // Privacy
    api("/system/privacy", "GET", {}, (r) => {
        current_privacy_setting = r;
        const privacyDiv = document.getElementById('system-privacy-setting');
        privacyDiv.style.display = 'block';

        const toggleText = document.getElementById('privacy-toggle-text');
        const helpText = document.getElementById('privacy-help-text');

        if (r) {
            toggleText.textContent = 'Disable Version Check';
            helpText.textContent = 'Currently enabled - Status checks will phone-home to check for new Mail-in-a-Box releases';
        } else {
            toggleText.textContent = 'Enable Version Check';
            helpText.textContent = 'Currently disabled - Enable to automatically check for new Mail-in-a-Box releases';
        }
    });

    // Reboot
    api("/system/reboot", "GET", {}, (r) => {
        const rebootDiv = document.getElementById('system-reboot-required');
        rebootDiv.style.display = 'block';
        const rebootRequired = document.getElementById('reboot-needed');
        const rebootNotNeeded = document.getElementById('reboot-not-needed');

        if (r) {
            rebootDiv.classList = 'info-card alert-warning'
            rebootRequired.style.display = 'block';
            rebootNotNeeded.style.display = 'none';
        } else {
            rebootDiv.classList = 'info-card'
            rebootRequired.style.display = 'none';
            rebootNotNeeded.style.display = 'flex';
        }
    });

    // Status
    api("/system/status", "POST", {}, (r) => {
        const container = document.getElementById('system-checks-container');
        container.innerHTML = "";
        const ok_symbol = "✓";
        const error_symbol = "✖";
        const warning_symbol = "?";
        const count_by_status = { ok: 0, error: 0, warning: 0 };

        // Group items by heading
        const sections = [];
        let currentSection = null;

        r.forEach((item) => {
            if (item.type === 'heading') {
                // Start a new section
                currentSection = {
                    heading: item.text,
                    items: []
                };
                sections.push(currentSection);
            } else if (currentSection) {
                // Add item to current section
                currentSection.items.push(item);
            } else {
                // No heading yet, create a default section
                currentSection = {
                    heading: 'General',
                    items: [item]
                };
                sections.push(currentSection);
            }
        });

        // Render each section
        sections.forEach((section) => {
            if (section.items.length === 0) return;

            // Create section container
            const sectionDiv = document.createElement('div');
            sectionDiv.className = 'status-section';

            // Create section header
            const header = document.createElement('div');
            header.className = 'status-section-header';
            header.textContent = section.heading;
            sectionDiv.appendChild(header);

            // Create table container
            const tableContainer = document.createElement('div');
            tableContainer.className = 'table-container';

            // Create table
            const table = document.createElement('table');
            table.className = 'status-table';
            const tbody = document.createElement('tbody');

            // Render items in this section
            section.items.forEach((item) => {
                const tr = createStatusRow(item, count_by_status, ok_symbol, error_symbol, warning_symbol);
                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            tableContainer.appendChild(table);
            sectionDiv.appendChild(tableContainer);
            container.appendChild(sectionDiv);
        });

        // Summary
        summary.textContent = "Summary: ";
        if(count_by_status.error + count_by_status.warning === 0) {
            const span = document.createElement('span');
            span.className = 'text-success';
            span.style.fontWeight = '600';
            span.textContent = `All ${count_by_status.ok} ${ok_symbol} OK`;
            summary.appendChild(span);
        } else {
            const okSpan = document.createElement('span');
            okSpan.className = 'text-success';
            okSpan.style.fontWeight = '600';
            okSpan.textContent = `${count_by_status.ok} ${ok_symbol} OK, `;
            const errSpan = document.createElement('span');
            errSpan.className = 'text-danger';
            errSpan.style.fontWeight = '600';
            errSpan.textContent = `${count_by_status.error} ${error_symbol} Error, `;
            const warnSpan = document.createElement('span');
            warnSpan.className = 'text-warning';
            warnSpan.style.fontWeight = '600';
            warnSpan.textContent = `${count_by_status.warning} ${warning_symbol} Warning`;
            summary.appendChild(okSpan);
            summary.appendChild(errSpan);
            summary.appendChild(warnSpan);
        }
    });
}

function enable_privacy(status) {
    api("/system/privacy", "POST", { value: status ? "private" : "off" }, () => {
        show_system_status();
    });
    return false;
}

function confirm_reboot() {
    showModalConfirm(
        "Reboot",
        document.createElement('p').appendChild(document.createTextNode(`This will reboot your Mail-in-a-Box instance.`)),
        "Reboot Now",
        () => {
            api("/system/reboot", "POST", {}, (r) => {
                let msg = "<p>Please reload this page after a minute or so.</p>";
                if(r) msg = `<p>The reboot command said:</p><pre>${r}</pre>`;
                showModalError("Reboot", msg);
            });
        }
    );
}

const handlePrivacyToggle = (e) => {
    e.preventDefault();
    enable_privacy(!current_privacy_setting);
};

function setupEventListeners() {
    // Reboot button
    const rebootBtn = document.getElementById('reboot-box-btn');
    if (rebootBtn) {
        rebootBtn.removeEventListener('click', confirm_reboot);
        rebootBtn.addEventListener('click', confirm_reboot);
    }

    // Privacy toggle
    const privacyToggle = document.getElementById('privacy-toggle');
    if (privacyToggle) {
        privacyToggle.removeEventListener('click', handlePrivacyToggle);
        privacyToggle.addEventListener('click', handlePrivacyToggle);
    }
}
