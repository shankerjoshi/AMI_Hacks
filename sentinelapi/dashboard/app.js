const specText = document.getElementById('specText');
const baseUrl = document.getElementById('baseUrl');
const button = document.getElementById('runScan');
const summary = document.getElementById('summary');
const findingList = document.getElementById('findingList');

const SAMPLE_SPEC = `openapi: 3.0.0
info:
  title: SentinelAPI Demo Sandbox
  version: '1.0.0'
servers:
  - url: http://demo-api:8001
paths:
  /orders/{id}:
    get:
      operationId: getOrder
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: integer
  /profile/{id}:
    get:
      operationId: getProfile
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: integer
  /me:
    get:
      operationId: getCurrentUser
      responses:
        '200':
          description: Current user profile
`;

specText.value = SAMPLE_SPEC;
baseUrl.value = window.location.hostname === 'localhost'
  ? 'http://demo-api:8001'
  : `${window.location.protocol}//${window.location.hostname}:8001`;

button.addEventListener('click', async () => {
  summary.textContent = 'Running scanner...';
  findingList.innerHTML = '';

  try {
    const response = await fetch('http://localhost:8000/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        spec_text: specText.value,
        spec_format: 'yaml',
        base_url: baseUrl.value,
        allowlist: ['localhost', '127.0.0.1', 'demo-api'],
        auth_profiles: [
          { name: 'alice', token: 'alice-token', header: 'Authorization', prefix: 'Bearer' },
          { name: 'bob', token: 'bob-token', header: 'Authorization', prefix: 'Bearer' }
        ],
        timeout_seconds: 10,
        request_budget: 25,
        concurrency: 2
      })
    });

    const data = await response.json();
    const findings = data.findings || [];

    if (!findings.length) {
      summary.textContent = `Scan completed: ${data.endpoints_discovered ?? 0} endpoints discovered, 0 findings.`;
      return;
    }

    summary.innerHTML = `<strong>${data.endpoints_discovered ?? 0}</strong> endpoints discovered, <strong>${findings.length}</strong> findings.`;

    findingList.innerHTML = findings
      .map((finding) => `
        <li class="finding-item">
          <span class="severity ${finding.severity}">${finding.severity}</span>
          <strong>${finding.type}</strong><br />
          ${finding.endpoint.path}
        </li>
      `)
      .join('');
  } catch (error) {
    summary.textContent = 'Scan failed: ' + error.message;
  }
});
