import { api } from '../core/api.js';
import { showModalError } from '../core/ui.js';

let customDnsData = [];
let customDnsDataSortOrder = 'qname';

const handleCustomDnsSubmit = (e) => {
    e.preventDefault();
    doSetCustomDns();
};

const handleSecondaryDnsSubmit = (e) => {
    e.preventDefault();
    doSetSecondaryDns();
};

const handleSortClick = (e) => {
    e.preventDefault();
    customDnsDataSortOrder = e.target.dataset.sort;
    showCurrentCustomDnsUpdateAfterSort();
};

const handleTableClick = (e) => {
    if (e.target.classList.contains('delete-dns-record')) {
        e.preventDefault();
        deleteCustomDnsRecord(e.target);
    }
};

export function initCustomDns() {
    // Load secondary nameserver
    api("/dns/secondary-nameserver", "GET", {}, (data) => {
        document.getElementById('secondarydnsHostname').value = data.hostnames.join(' ');
        const clearInstructions = document.getElementById('secondarydns-clear-instructions');
        clearInstructions.style.display = data.hostnames.length > 0 ? 'block' : 'none';
    });

    // Load DNS zones
    api("/dns/zones", "GET", {}, (data) => {
        const zoneSelect = document.getElementById('customdnsZone');
        zoneSelect.innerHTML = '';
        data.forEach(zone => {
            const option = document.createElement('option');
            option.textContent = zone;
            zoneSelect.appendChild(option);
        });
    });

    showCurrentCustomDns();
    showCustomdnsRtypeHint();

    // Type select change handler
    const typeSelect = document.getElementById('customdnsType');
    if (typeSelect) {
        typeSelect.removeEventListener('change', showCustomdnsRtypeHint);
        typeSelect.addEventListener('change', showCustomdnsRtypeHint);
    }

    // Custom DNS form
    const customdnsForm = document.getElementById('customdns-form');
    if (customdnsForm) {
        customdnsForm.removeEventListener('submit', handleCustomDnsSubmit);
        customdnsForm.addEventListener('submit', handleCustomDnsSubmit);
    }

    // Secondary DNS form
    const secondarydnsForm = document.getElementById('secondarydns-form');
    if (secondarydnsForm) {
        secondarydnsForm.removeEventListener('submit', handleSecondaryDnsSubmit);
        secondarydnsForm.addEventListener('submit', handleSecondaryDnsSubmit);
    }

    // Sort links
    document.querySelectorAll('[data-sort]').forEach(link => {
        link.removeEventListener('click', handleSortClick);
        link.addEventListener('click', handleSortClick);
    });

    // Delete links delegation
    const table = document.getElementById('custom-dns-current');
    if (table) {
        table.removeEventListener('click', handleTableClick);
        table.addEventListener('click', handleTableClick);
    }
}

function showCurrentCustomDns() {
    api("/dns/custom", "GET", {}, (data) => {
        const table = document.getElementById('custom-dns-current');
        if (data.length > 0) {
            table.style.display = '';
        } else {
            table.style.display = 'none';
        }
        customDnsData = data;
        showCurrentCustomDnsUpdateAfterSort();
    });
}

function showCurrentCustomDnsUpdateAfterSort() {
    const data = customDnsData;
    const sortKey = customDnsDataSortOrder || "qname";

    data.sort((a, b) => a["sort-order"][sortKey] - b["sort-order"][sortKey]);

    const tbody = document.querySelector('#custom-dns-current tbody');
    tbody.innerHTML = '';
    let lastZone = null;

    data.forEach(record => {
        if (sortKey === "qname" && record.zone !== lastZone) {
            const row = document.createElement('tr');
            const th = document.createElement('th');
            th.setAttribute('colspan', '4');
            th.setAttribute('role', 'heading');
            th.setAttribute('aria-level', '4');
            th.style.backgroundColor = '#EEE';
            th.textContent = record.zone;
            row.appendChild(th);
            tbody.appendChild(row);
            lastZone = record.zone;
        }

        const tr = document.createElement('tr');
        tr.dataset.qname = record.qname;
        tr.dataset.rtype = record.rtype;
        tr.dataset.value = record.value;

        const qnameTd = document.createElement('td');
        qnameTd.className = 'long';
        qnameTd.textContent = record.qname;
        tr.appendChild(qnameTd);

        const rtypeTd = document.createElement('td');
        rtypeTd.textContent = record.rtype;
        tr.appendChild(rtypeTd);

        const valueTd = document.createElement('td');
        valueTd.className = 'long';
        valueTd.style.maxWidth = '40em';
        valueTd.textContent = record.value;
        tr.appendChild(valueTd);

        const actionTd = document.createElement('td');
        actionTd.innerHTML = '[<a href="#" class="delete-dns-record">delete</a>]';
        tr.appendChild(actionTd);

        tbody.appendChild(tr);
    });
}

function deleteCustomDnsRecord(elem) {
    const row = elem.closest('tr');
    const qname = row.dataset.qname;
    const rtype = row.dataset.rtype;
    const value = row.dataset.value;
    doSetCustomDns(qname, rtype, value, "DELETE");
}

function doSetSecondaryDns() {
    api("/dns/secondary-nameserver", "POST", {
        hostnames: document.getElementById('secondarydnsHostname').value
    }, (data) => {
        if (data === "") return;
        const pre = document.createElement('pre');
        pre.textContent = data;
        showModalError("Secondary DNS", pre.outerHTML);
        const clearInstructions = document.getElementById('secondarydns-clear-instructions');
        clearInstructions.style.display = 'block';
    }, (err) => {
        const pre = document.createElement('pre');
        pre.textContent = err;
        showModalError("Secondary DNS", pre.outerHTML);
    });
}

function doSetCustomDns(qname, rtype, value, method) {
    if (!qname) {
        const qnameField = document.getElementById('customdnsQname').value;
        const zoneField = document.getElementById('customdnsZone').value;

        if (qnameField !== '') {
            qname = qnameField + '.' + zoneField;
        } else {
            qname = zoneField;
        }
        rtype = document.getElementById('customdnsType').value;
        value = document.getElementById('customdnsValue').value;
        method = 'POST';
    }

    api(`/dns/custom/${qname}/${rtype}`, method, value, (data) => {
        if (data === "") return;
        const pre = document.createElement('pre');
        pre.textContent = data;
        showModalError("Custom DNS", pre.outerHTML);
        showCurrentCustomDns();
    }, (err) => {
        const pre = document.createElement('pre');
        pre.textContent = err;
        showModalError("Custom DNS (Error)", pre.outerHTML);
    });
}

function showCustomdnsRtypeHint() {
    const typeSelect = document.getElementById('customdnsType');
    const selectedOption = typeSelect.options[typeSelect.selectedIndex];
    const hint = selectedOption.getAttribute('data-hint');
    document.getElementById('customdnsTypeHint').textContent = hint || '';
}
