import { api } from '../core/api.js';
import { showModalError } from '../core/ui.js';

function showExternalDns() {
    // Load zones for dropdown
    api("/dns/zones", "GET", {}, (data) => {
        const zonesSelect = document.getElementById('downloadZonefile');
        zonesSelect.innerHTML = '';
        data.forEach(zone => {
            const option = document.createElement('option');
            option.textContent = zone;
            zonesSelect.appendChild(option);
        });
    });

    // Load DNS records table
    const tbody = document.querySelector('#external_dns_settings tbody');
    tbody.innerHTML = "<tr><td colspan='2' class='text-muted'>Loading...</td></tr>";

    api("/dns/dump", "GET", {}, (zones) => {
        tbody.innerHTML = "";

        zones.forEach((zoneData, index) => {
            const zoneName = zoneData[0];
            const records = zoneData[1];

            // Create zone heading row
            const headingRow = document.createElement('tr');
            headingRow.className = index === 0 ? 'heading first' : 'heading';
            const headingTd = document.createElement('td');
            headingTd.setAttribute('colspan', '3');
            headingTd.textContent = zoneName;
            headingRow.appendChild(headingTd);
            tbody.appendChild(headingRow);

            // Create rows for each record
            records.forEach(record => {
                // Values row
                const valuesRow = document.createElement('tr');
                valuesRow.className = 'values';

                const qnameTd = document.createElement('td');
                qnameTd.className = 'qname';
                qnameTd.textContent = record.qname;
                valuesRow.appendChild(qnameTd);

                const rtypeTd = document.createElement('td');
                rtypeTd.className = 'rtype';
                rtypeTd.textContent = record.rtype;
                valuesRow.appendChild(rtypeTd);

                const valueTd = document.createElement('td');
                valueTd.className = 'value';
                valueTd.textContent = record.value;
                valuesRow.appendChild(valueTd);

                tbody.appendChild(valuesRow);

                // Explanation row
                const explanationRow = document.createElement('tr');
                explanationRow.className = 'explanation';
                const explanationTd = document.createElement('td');
                explanationTd.setAttribute('colspan', '3');
                explanationTd.textContent = record.explanation;
                explanationRow.appendChild(explanationTd);
                tbody.appendChild(explanationRow);
            });
        });
    });
}

function doDownloadZonefile() {
    const zone = document.getElementById('downloadZonefile').value;

    api(`/dns/zonefile/${zone}`, "GET", {}, (data) => {
        const pre = document.createElement('pre');
        pre.textContent = data;
        showModalError("Download Zonefile", pre.outerHTML);
    }, (err) => {
        const pre = document.createElement('pre');
        pre.textContent = err;
        showModalError("Download Zonefile (Error)", pre.outerHTML);
    });
}

const handleDownloadZonefileSubmit = (e) => {
    e.preventDefault();
    doDownloadZonefile();
};

export function initExternalDns() {
    // Load external DNS records
    showExternalDns();

    // Form submission for downloading zonefile
    const downloadForm = document.getElementById('download-zonefile-form');
    if (downloadForm) {
        downloadForm.removeEventListener('submit', handleDownloadZonefileSubmit);
        downloadForm.addEventListener('submit', handleDownloadZonefileSubmit);
    }
}
