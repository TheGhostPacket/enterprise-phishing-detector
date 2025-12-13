// ============================================
// DOM Elements
// ============================================
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const loadingOverlay = document.getElementById('loadingOverlay');
const themeToggle = document.getElementById('themeToggle');

// Email elements
const emailForm = document.getElementById('emailForm');
const emailResults = document.getElementById('emailResults');

// URL elements
const urlForm = document.getElementById('urlForm');
const quickCheckBtn = document.getElementById('quickCheckBtn');
const urlResults = document.getElementById('urlResults');
const quickResult = document.getElementById('quickResult');

// Monitor elements
const startMonitorBtn = document.getElementById('startMonitor');
const stopMonitorBtn = document.getElementById('stopMonitor');

// Store last analyzed email for feedback
let lastAnalyzedEmail = null;

// ============================================
// Tab Switching
// ============================================
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Update tab buttons
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Update tab content
        tabContents.forEach(content => {
            content.classList.remove('active');
            if (content.id === `${targetTab}-tab`) {
                content.classList.add('active');
            }
        });
    });
});

// ============================================
// Theme Toggle
// ============================================
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    themeToggle.textContent = document.body.classList.contains('light-theme') ? '🌙' : '☀️';
});

// ============================================
// Loading State
// ============================================
function showLoading(message = 'Analyzing...') {
    loadingOverlay.querySelector('p').textContent = message;
    loadingOverlay.classList.add('show');
}

function hideLoading() {
    loadingOverlay.classList.remove('show');
}

// ============================================
// Email Analysis
// ============================================
emailForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const sender = document.getElementById('sender').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const body = document.getElementById('body').value.trim();
    
    if (!sender || !subject) {
        alert('Please provide sender and subject');
        return;
    }
    
    showLoading('Analyzing email...');
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender, subject, body })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayEmailResults(data);
            lastAnalyzedEmail = { subject, body };
        } else {
            alert('Error: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to analyze email. Please try again.');
    } finally {
        hideLoading();
    }
});

function displayEmailResults(data) {
    emailResults.style.display = 'block';
    
    // Header
    const header = document.getElementById('emailResultsHeader');
    header.style.borderLeft = `5px solid ${data.risk_color}`;
    
    document.getElementById('emailRiskIcon').textContent = data.risk_icon;
    document.getElementById('emailRiskLevel').textContent = data.risk_level;
    document.getElementById('emailRiskLevel').style.color = data.risk_color;
    document.getElementById('emailScore').textContent = data.danger_score;
    document.getElementById('emailScore').style.color = data.risk_color;
    
    // Advice
    document.getElementById('emailAdvice').textContent = data.advice;
    document.getElementById('emailAdvice').style.borderColor = data.risk_color;
    
    // Findings
    const findingsList = document.getElementById('emailFindings');
    findingsList.innerHTML = '';
    
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            findingsList.appendChild(li);
        });
    } else {
        findingsList.innerHTML = '<li style="color: var(--success);">✅ No suspicious indicators found</li>';
    }
    
    // Extracted URLs
    const urlsSection = document.getElementById('emailUrlsSection');
    const urlsList = document.getElementById('emailUrls');
    
    if (data.extracted_urls && data.extracted_urls.length > 0) {
        urlsSection.style.display = 'block';
        urlsList.innerHTML = '';
        
        data.extracted_urls.forEach(url => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span class="url-text">${truncateUrl(url, 50)}</span>
                <button class="btn btn-sm btn-secondary" onclick="analyzeUrlFromEmail('${escapeHtml(url)}')">
                    Analyze
                </button>
            `;
            urlsList.appendChild(li);
        });
    } else {
        urlsSection.style.display = 'none';
    }
    
    // ML results
    document.getElementById('emailMlProb').textContent = `${data.ml_probability}% (${data.ml_confidence})`;
    
    // Scroll to results
    emailResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================
// URL Analysis
// ============================================
urlForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await analyzeUrl(false);
});

quickCheckBtn.addEventListener('click', async () => {
    await analyzeUrl(true);
});

async function analyzeUrl(quickCheck = false) {
    const url = document.getElementById('urlInput').value.trim();
    
    if (!url) {
        alert('Please enter a URL to analyze');
        return;
    }
    
    if (quickCheck) {
        showLoading('Quick checking...');
        quickResult.style.display = 'block';
        urlResults.style.display = 'none';
        
        try {
            const response = await fetch('/quick-url-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (data.success) {
                displayQuickResult(data);
            } else {
                alert('Error: ' + data.error);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Failed to check URL. Please try again.');
        } finally {
            hideLoading();
        }
    } else {
        showLoading('Performing deep analysis...');
        quickResult.style.display = 'none';
        
        try {
            const response = await fetch('/analyze-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (data.success) {
                displayUrlResults(data);
            } else {
                alert('Error: ' + data.error);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Failed to analyze URL. Please try again.');
        } finally {
            hideLoading();
        }
    }
}

function displayQuickResult(data) {
    const verdict = document.getElementById('quickVerdict');
    const details = document.getElementById('quickDetails');
    
    verdict.textContent = data.verdict;
    verdict.style.color = data.color;
    
    if (data.findings && data.findings.length > 0) {
        details.innerHTML = data.findings.map(f => `⚠️ ${f}`).join('<br>');
    } else {
        details.innerHTML = '✅ No immediate threats detected';
    }
    
    details.innerHTML += `<br><small style="color: var(--text-muted);">${data.note}</small>`;
}

function displayUrlResults(data) {
    urlResults.style.display = 'block';
    
    // Header
    const header = document.getElementById('urlResultsHeader');
    header.style.borderLeft = `5px solid ${data.risk_color}`;
    
    document.getElementById('urlRiskIcon').textContent = data.risk_icon;
    document.getElementById('urlRiskLevel').textContent = data.risk_level;
    document.getElementById('urlRiskLevel').style.color = data.risk_color;
    document.getElementById('urlScore').textContent = data.danger_score;
    document.getElementById('urlScore').style.color = data.risk_color;
    
    // Summary
    document.getElementById('urlSummary').textContent = data.summary;
    document.getElementById('urlSummary').style.borderColor = data.risk_color;
    
    // Domain Info
    displayDomainInfo(data.domain_info);
    
    // SSL Info
    displaySslInfo(data.ssl_info);
    
    // Redirect Info
    displayRedirectInfo(data.redirect_info);
    
    // DNS Info
    displayDnsInfo(data.dns_info);
    
    // Content Info
    displayContentInfo(data.content_info);
    
    // All Risk Factors
    const findingsList = document.getElementById('urlFindings');
    findingsList.innerHTML = '';
    
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            findingsList.appendChild(li);
        });
    } else {
        findingsList.innerHTML = '<li style="color: var(--success);">✅ No risk factors identified</li>';
    }
    
    // Setup collapsible sections
    setupCollapsibles();
    
    // Scroll to results
    urlResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function displayDomainInfo(info) {
    const container = document.getElementById('domainInfo');
    
    if (!info || !info.success) {
        container.innerHTML = '<p style="color: var(--text-muted);">Domain information unavailable</p>';
        return;
    }
    
    container.innerHTML = `
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Domain</div>
                <div class="info-value">${info.domain || 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Registrar</div>
                <div class="info-value">${info.registrar || 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Created</div>
                <div class="info-value">${info.creation_date || 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Domain Age</div>
                <div class="info-value">${info.domain_age_days ? info.domain_age_days + ' days' : 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Expires</div>
                <div class="info-value">${info.expiration_date || 'N/A'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Country</div>
                <div class="info-value">${info.registrant_country || 'N/A'}</div>
            </div>
        </div>
        ${info.name_servers && info.name_servers.length > 0 ? `
            <div style="margin-top: 12px;">
                <div class="info-label">Name Servers</div>
                <div class="info-value">${info.name_servers.join(', ')}</div>
            </div>
        ` : ''}
    `;
}

function displaySslInfo(info) {
    const container = document.getElementById('sslInfo');
    
    if (!info) {
        container.innerHTML = '<p style="color: var(--text-muted);">SSL information unavailable</p>';
        return;
    }
    
    const hasSSL = info.has_ssl;
    const statusIcon = hasSSL ? '✅' : '❌';
    const statusText = hasSSL ? 'Valid SSL Certificate' : 'No Valid SSL Certificate';
    
    container.innerHTML = `
        <div style="margin-bottom: 15px;">
            <span style="font-size: 1.2rem;">${statusIcon}</span>
            <strong>${statusText}</strong>
        </div>
        ${hasSSL ? `
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Issuer</div>
                    <div class="info-value">${info.issuer || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Organization</div>
                    <div class="info-value">${info.issuer_org || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Valid From</div>
                    <div class="info-value">${info.valid_from || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Valid Until</div>
                    <div class="info-value">${info.valid_until || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Days Until Expiry</div>
                    <div class="info-value" style="color: ${info.days_until_expiry < 30 ? 'var(--danger)' : 'var(--success)'}">
                        ${info.days_until_expiry || 'N/A'}
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Subject</div>
                    <div class="info-value">${info.subject || 'N/A'}</div>
                </div>
            </div>
        ` : `
            <p style="color: var(--danger);">⚠️ This site does not have a valid SSL certificate, which is a security concern.</p>
        `}
    `;
}

function displayRedirectInfo(info) {
    const container = document.getElementById('redirectInfo');
    
    if (!info || !info.success) {
        container.innerHTML = '<p style="color: var(--text-muted);">Redirect information unavailable</p>';
        return;
    }
    
    const redirectCount = info.redirect_count || 0;
    
    container.innerHTML = `
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Redirect Count</div>
                <div class="info-value" style="color: ${redirectCount >= 3 ? 'var(--warning)' : 'var(--success)'}">
                    ${redirectCount}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Uses Shortener</div>
                <div class="info-value" style="color: ${info.uses_shortener ? 'var(--danger)' : 'var(--success)'}">
                    ${info.uses_shortener ? 'Yes ⚠️' : 'No'}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Crosses Domains</div>
                <div class="info-value" style="color: ${info.crosses_domains ? 'var(--warning)' : 'var(--success)'}">
                    ${info.crosses_domains ? 'Yes ⚠️' : 'No'}
                </div>
            </div>
        </div>
        ${info.chain && info.chain.length > 1 ? `
            <div style="margin-top: 15px;">
                <div class="info-label">Redirect Chain</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; margin-top: 8px;">
                    ${info.chain.map((item, i) => `
                        <div style="padding: 8px; background: var(--bg-secondary); border-radius: 4px; margin-bottom: 4px;">
                            ${i + 1}. ${truncateUrl(item.url, 60)}
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
        <div style="margin-top: 15px;">
            <div class="info-label">Final URL</div>
            <div class="info-value" style="word-break: break-all;">${info.final_url || 'N/A'}</div>
        </div>
    `;
}

function displayDnsInfo(info) {
    const container = document.getElementById('dnsInfo');
    
    if (!info || !info.success) {
        container.innerHTML = '<p style="color: var(--text-muted);">DNS information unavailable</p>';
        return;
    }
    
    container.innerHTML = `
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">A Records</div>
                <div class="info-value">${info.a_records && info.a_records.length > 0 ? info.a_records.join(', ') : 'None'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">MX Records</div>
                <div class="info-value">${info.mx_records && info.mx_records.length > 0 ? info.mx_records.join(', ') : 'None'}</div>
            </div>
            <div class="info-item">
                <div class="info-label">NS Records</div>
                <div class="info-value">${info.ns_records && info.ns_records.length > 0 ? info.ns_records.join(', ') : 'None'}</div>
            </div>
        </div>
        ${info.txt_records && info.txt_records.length > 0 ? `
            <div style="margin-top: 15px;">
                <div class="info-label">TXT Records</div>
                <div style="font-size: 0.8rem; margin-top: 8px;">
                    ${info.txt_records.map(txt => `
                        <div style="padding: 8px; background: var(--bg-secondary); border-radius: 4px; margin-bottom: 4px; word-break: break-all;">
                            ${escapeHtml(txt.substring(0, 100))}${txt.length > 100 ? '...' : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
    `;
}

function displayContentInfo(info) {
    const container = document.getElementById('contentInfo');
    
    if (!info || !info.success) {
        container.innerHTML = '<p style="color: var(--text-muted);">Content analysis unavailable (site may be unreachable)</p>';
        return;
    }
    
    container.innerHTML = `
        ${info.page_title ? `
            <div style="margin-bottom: 15px;">
                <div class="info-label">Page Title</div>
                <div class="info-value">${escapeHtml(info.page_title)}</div>
            </div>
        ` : ''}
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Login Form</div>
                <div class="info-value" style="color: ${info.has_login_form ? 'var(--warning)' : 'var(--success)'}">
                    ${info.has_login_form ? 'Yes ⚠️' : 'No'}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Password Field</div>
                <div class="info-value" style="color: ${info.has_password_field ? 'var(--warning)' : 'var(--success)'}">
                    ${info.has_password_field ? 'Yes ⚠️' : 'No'}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Requests Sensitive Info</div>
                <div class="info-value" style="color: ${info.requests_sensitive_info ? 'var(--danger)' : 'var(--success)'}">
                    ${info.requests_sensitive_info ? 'Yes 🚨' : 'No'}
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">External Form Action</div>
                <div class="info-value" style="color: ${info.external_form_action ? 'var(--danger)' : 'var(--success)'}">
                    ${info.external_form_action ? 'Yes 🚨' : 'No'}
                </div>
            </div>
        </div>
        ${info.suspicious_elements && info.suspicious_elements.length > 0 ? `
            <div style="margin-top: 15px;">
                <div class="info-label">Suspicious Elements</div>
                <ul style="margin-top: 8px; padding-left: 20px;">
                    ${info.suspicious_elements.map(el => `<li>${escapeHtml(el)}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
    `;
}

// ============================================
// Analyze URL from Email
// ============================================
function analyzeUrlFromEmail(url) {
    // Switch to URL tab
    document.querySelector('[data-tab="url"]').click();
    
    // Fill in the URL
    document.getElementById('urlInput').value = url;
    
    // Trigger analysis
    setTimeout(() => {
        analyzeUrl(false);
    }, 300);
}

// ============================================
// Collapsible Sections
// ============================================
function setupCollapsibles() {
    document.querySelectorAll('.collapsible .section-toggle').forEach(toggle => {
        // Remove existing listeners
        toggle.replaceWith(toggle.cloneNode(true));
    });
    
    document.querySelectorAll('.collapsible .section-toggle').forEach(toggle => {
        toggle.addEventListener('click', function() {
            this.parentElement.classList.toggle('open');
        });
    });
}

// ============================================
// Email Monitoring
// ============================================
let monitoringInterval = null;

startMonitorBtn.addEventListener('click', async () => {
    try {
        const response = await fetch('/start-monitoring', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: {} })
        });
        
        const data = await response.json();
        
        if (data.success) {
            startMonitorBtn.disabled = true;
            stopMonitorBtn.disabled = false;
            
            document.querySelector('.status-indicator').classList.add('online');
            document.querySelector('.monitor-status span').innerHTML = 'Monitoring: <strong>Active</strong>';
            
            // Start polling for status
            monitoringInterval = setInterval(updateMonitoringStatus, 5000);
        }
    } catch (error) {
        console.error('Error starting monitor:', error);
        alert('Failed to start monitoring');
    }
});

stopMonitorBtn.addEventListener('click', async () => {
    try {
        const response = await fetch('/stop-monitoring', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            startMonitorBtn.disabled = false;
            stopMonitorBtn.disabled = true;
            
            document.querySelector('.status-indicator').classList.remove('online');
            document.querySelector('.monitor-status span').innerHTML = 'Monitoring: <strong>Inactive</strong>';
            
            if (monitoringInterval) {
                clearInterval(monitoringInterval);
                monitoringInterval = null;
            }
        }
    } catch (error) {
        console.error('Error stopping monitor:', error);
    }
});

async function updateMonitoringStatus() {
    try {
        const response = await fetch('/monitoring-status');
        const data = await response.json();
        
        if (data.success && data.status) {
            document.getElementById('emailsProcessed').textContent = data.status.emails_processed;
            document.getElementById('alertsCount').textContent = data.status.alerts_count;
            
            const alertsList = document.getElementById('alertsList');
            alertsList.innerHTML = '';
            
            if (data.status.recent_alerts && data.status.recent_alerts.length > 0) {
                data.status.recent_alerts.forEach(alert => {
                    const li = document.createElement('li');
                    li.textContent = alert;
                    alertsList.appendChild(li);
                });
            }
        }
    } catch (error) {
        console.error('Error fetching status:', error);
    }
}

// ============================================
// Feedback
// ============================================
async function submitFeedback(isPhishing) {
    if (!lastAnalyzedEmail) {
        alert('No email to provide feedback for');
        return;
    }
    
    try {
        const response = await fetch('/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                subject: lastAnalyzedEmail.subject,
                body: lastAnalyzedEmail.body,
                is_phishing: isPhishing
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Thank you for your feedback! The ML model has been updated.');
        }
    } catch (error) {
        console.error('Error submitting feedback:', error);
    }
}

// ============================================
// Utility Functions
// ============================================
function truncateUrl(url, maxLength) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// Initialize
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Setup collapsibles on page load
    setupCollapsibles();
    
    console.log('🛡️ Phishing Intelligence Platform loaded');
});
