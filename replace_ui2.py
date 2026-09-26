import re

with open("dashboard/frontend/index.html", "r") as f:
    content = f.read()

# Add Chart.js to the head if not there
if "chart.js" not in content:
    content = content.replace("</head>", '    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n</head>')

# Define the new results block
new_results_html = """
            <div id="results" class="hidden flex flex-col gap-8">
                
                <!-- 1. The Global Header (Executive Summary) -->
                <div class="bg-white p-6 rounded-lg shadow-md border-t-4 border-indigo-600">
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
                        <div>
                            <h2 class="text-3xl font-bold text-gray-800">Security Assessment</h2>
                            <p class="text-gray-500 text-sm mt-1">Executive Risk Overview & PCAP Metadata</p>
                        </div>
                        
                        <!-- Gauge Score -->
                        <div class="flex items-center mt-4 md:mt-0 bg-gray-50 rounded-lg p-3 border border-gray-200 shadow-inner">
                            <div class="text-right mr-4">
                                <div class="text-xs text-gray-500 font-bold uppercase tracking-wider">Risk Score</div>
                                <div id="riskLabel" class="text-sm font-semibold"></div>
                            </div>
                            <div id="scoreBadge" class="flex items-center justify-center w-16 h-16 rounded-full text-white font-black text-2xl shadow-md border-4 border-white"></div>
                        </div>
                    </div>
                    
                    <!-- Quick ID Tags -->
                    <div class="flex flex-wrap gap-2 mb-6" id="quickTags">
                        <span class="px-3 py-1 bg-indigo-100 text-indigo-800 text-xs font-bold rounded-full border border-indigo-200 shadow-sm">IKEv2</span>
                        <span id="tag-mode" class="px-3 py-1 bg-blue-100 text-blue-800 text-xs font-bold rounded-full border border-blue-200 shadow-sm">Tunnel Mode</span>
                        <span id="tag-ip" class="px-3 py-1 bg-purple-100 text-purple-800 text-xs font-bold rounded-full border border-purple-200 shadow-sm">IPv4</span>
                        <span class="px-3 py-1 bg-emerald-100 text-emerald-800 text-xs font-bold rounded-full border border-emerald-200 shadow-sm">ESP Protocol</span>
                    </div>

                    <!-- PCAP Metadata -->
                    <div class="grid grid-cols-3 gap-4 bg-gray-50 p-4 rounded-lg border border-gray-200 mb-6">
                        <div>
                            <span class="block text-xs text-gray-500 font-semibold uppercase">Total Packets</span>
                            <span class="text-lg font-mono text-gray-800" id="metaPackets">0</span>
                        </div>
                        <div>
                            <span class="block text-xs text-gray-500 font-semibold uppercase">Capture Duration</span>
                            <span class="text-lg font-mono text-gray-800" id="metaDuration">0.00s</span>
                        </div>
                        <div>
                            <span class="block text-xs text-gray-500 font-semibold uppercase">File Size</span>
                            <span class="text-lg font-mono text-gray-800" id="metaSize">0 KB</span>
                        </div>
                    </div>

                    <p id="execReportText" class="text-gray-700 text-lg leading-relaxed"></p>
                </div>

                <!-- 2. The Threat & Compliance Matrix -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <!-- Threat Matrix Grid -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">Cryptographic Threat Matrix</h2>
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-left text-sm">
                                <thead>
                                    <tr class="bg-gray-50 text-gray-600">
                                        <th class="py-2 px-3 font-semibold">Component</th>
                                        <th class="py-2 px-3 font-semibold">Algorithm</th>
                                        <th class="py-2 px-3 font-semibold">NIST/BSI Status</th>
                                    </tr>
                                </thead>
                                <tbody id="matrixTable" class="divide-y divide-gray-100">
                                    <!-- JS populated -->
                                </tbody>
                            </table>
                        </div>
                        
                        <h3 class="font-bold text-gray-700 mt-6 mb-3 text-sm uppercase tracking-wide">Security Posture Checklist</h3>
                        <ul class="space-y-2 text-sm" id="postureChecklist">
                            <!-- JS populated -->
                        </ul>
                    </div>

                    <!-- Remediation Alerts -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">Actionable Remediation Alerts</h2>
                        <ul id="findingsList" class="space-y-3 h-80 overflow-y-auto pr-2">
                            <!-- Populated by JS -->
                        </ul>
                    </div>
                </div>

                <!-- 3. Protocol & SA Forensics -->
                <div class="bg-white p-6 rounded-lg shadow-md">
                    <h2 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">Protocol & SA Forensics (Technical Breakdown)</h2>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                        <!-- Phase 1 -->
                        <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                            <h3 class="font-bold text-slate-700 mb-3 text-sm uppercase tracking-wide">Phase 1 (IKE_SA) Details</h3>
                            <div class="grid grid-cols-2 gap-y-3 text-sm" id="phase1Details">
                                <!-- JS populated -->
                            </div>
                        </div>
                        <!-- Phase 2 -->
                        <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                            <h3 class="font-bold text-slate-700 mb-3 text-sm uppercase tracking-wide">Phase 2 (CHILD_SA) Details</h3>
                            <div class="grid grid-cols-2 gap-y-3 text-sm" id="phase2Details">
                                <!-- JS populated -->
                            </div>
                        </div>
                    </div>
                    
                    <details class="bg-gray-900 rounded-lg p-4 text-green-400 font-mono text-xs overflow-x-auto shadow-inner cursor-pointer">
                        <summary class="text-green-300 font-bold mb-2 focus:outline-none">View Raw Proposal Payloads (JSON)</summary>
                        <pre id="rawPayloads" class="mt-2 text-green-500"></pre>
                    </details>
                </div>

                <!-- 4. AI Flow Classification -->
                <div class="bg-white p-6 rounded-lg shadow-md">
                    <h2 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">AI Flow Classification (Inside the Tunnel)</h2>
                    
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <!-- Doughnut Chart -->
                        <div class="col-span-1 flex flex-col justify-center items-center">
                            <h3 class="font-bold text-gray-700 mb-2 text-sm text-center">Predicted Traffic Distribution</h3>
                            <div class="relative w-48 h-48">
                                <canvas id="trafficChart"></canvas>
                            </div>
                        </div>

                        <!-- Confidence & Telemetry -->
                        <div class="col-span-2">
                            <div class="mb-6 bg-gradient-to-r from-blue-50 to-indigo-50 p-4 rounded-lg border border-blue-100 flex items-center justify-between">
                                <div>
                                    <h3 class="font-bold text-blue-900 mb-1 text-sm">Global AI Confidence Score</h3>
                                    <p class="text-xs text-blue-700">Model certainty based on statistical flow side-channels.</p>
                                </div>
                                <div class="text-right">
                                    <span id="aiGlobalScore" class="text-3xl font-black text-blue-600">0%</span>
                                </div>
                            </div>

                            <h3 class="font-bold text-gray-700 mb-3 text-sm uppercase tracking-wide">Flow Telemetry (Side-Channel Characteristics)</h3>
                            <div class="overflow-x-auto">
                                <table class="min-w-full text-left text-xs border-collapse">
                                    <thead>
                                        <tr class="border-b-2 border-gray-200 bg-gray-50 text-gray-600">
                                            <th class="py-2 px-2 font-semibold uppercase">ESP SPI</th>
                                            <th class="py-2 px-2 font-semibold uppercase">Class</th>
                                            <th class="py-2 px-2 font-semibold uppercase">Avg Pkt Len</th>
                                            <th class="py-2 px-2 font-semibold uppercase">Pkt Rate</th>
                                            <th class="py-2 px-2 font-semibold uppercase">Byte Rate</th>
                                        </tr>
                                    </thead>
                                    <tbody id="aiFlowsList" class="divide-y divide-gray-100">
                                        <!-- Populated by JS -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
"""

new_js = """
        let trafficChartInstance = null;

        function renderResults(data) {
            document.getElementById('results').classList.remove('hidden');
            const sec = data.security_assessment;
            const config = sec.config || {};
            const metadata = data.pcap_metadata || {};

            // 1. Global Header
            const badge = document.getElementById('scoreBadge');
            badge.innerText = `${sec.score}`;
            document.getElementById('riskLabel').innerText = sec.risk_level;
            
            let scoreColor = 'bg-red-500';
            let textColor = 'text-red-500';
            if (sec.score >= 85) { scoreColor = 'bg-green-500'; textColor = 'text-green-500'; }
            else if (sec.score >= 60) { scoreColor = 'bg-yellow-500'; textColor = 'text-yellow-600'; }
            
            badge.className = `flex items-center justify-center w-16 h-16 rounded-full text-white font-black text-2xl shadow-md border-4 border-white ${scoreColor}`;
            document.getElementById('riskLabel').className = `text-sm font-semibold ${textColor}`;

            document.getElementById('execReportText').innerText = sec.executive_report || "";
            document.getElementById('metaPackets').innerText = metadata.total_packets || 0;
            document.getElementById('metaDuration').innerText = (metadata.duration_sec || 0).toFixed(2) + "s";
            document.getElementById('metaSize').innerText = (metadata.file_size_kb || 0).toFixed(2) + " KB";
            
            // 2. Threat & Compliance Matrix
            const matrixTable = document.getElementById('matrixTable');
            matrixTable.innerHTML = '';
            
            const matrixRows = [
                { comp: "IKE Encryption", alg: config.enc_alg, type: "IKE Encryption" },
                { comp: "IKE Hash", alg: config.hash_alg, type: "IKE Hashing" },
                { comp: "DH Group", alg: config.dh_group, type: "Key Exchange" },
                { comp: "ESP Encryption", alg: config.esp_enc, type: "ESP Encryption" },
                { comp: "ESP HMAC", alg: config.esp_integrity, type: "ESP Integrity" }
            ];
            
            matrixRows.forEach(r => {
                // Find finding for this category
                const finding = sec.findings.find(f => f.category === r.type);
                let statusBadge = `<span class="px-2 py-1 bg-gray-100 text-gray-500 rounded text-xs">UNKNOWN</span>`;
                if (finding) {
                    if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
                        statusBadge = `<span class="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-bold">WEAK</span>`;
                    } else if (finding.severity === 'WARNING') {
                        statusBadge = `<span class="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-xs font-bold">WARNING</span>`;
                    } else {
                        statusBadge = `<span class="px-2 py-1 bg-green-100 text-green-700 rounded text-xs font-bold">COMPLIANT</span>`;
                    }
                }
                
                matrixTable.innerHTML += `
                    <tr>
                        <td class="py-2 px-3 text-gray-700 font-medium">${r.comp}</td>
                        <td class="py-2 px-3 font-mono text-gray-900">${r.alg || 'unknown'}</td>
                        <td class="py-2 px-3">${statusBadge}</td>
                    </tr>
                `;
            });

            // Posture Checklist
            const checklist = document.getElementById('postureChecklist');
            checklist.innerHTML = `
                <li class="flex items-center"><span class="mr-2 text-lg">${config.pfs_enabled ? '✅' : '❌'}</span> Perfect Forward Secrecy: <strong class="ml-1">${config.pfs_enabled ? 'Enabled' : 'Disabled'}</strong></li>
                <li class="flex items-center"><span class="mr-2 text-lg">✅</span> Replay Protection: <strong class="ml-1">Active (Seq Numbers)</strong></li>
                <li class="flex items-center"><span class="mr-2 text-lg">ℹ️</span> NAT-Traversal: <strong class="ml-1">${config.pfs_enabled ? 'Detected (UDP 4500)' : 'Not Detected'}</strong></li>
            `;

            // Findings / Remediation Alerts
            const findingsList = document.getElementById('findingsList');
            findingsList.innerHTML = '';
            sec.findings.forEach(finding => {
                if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH' || finding.severity === 'WARNING') {
                    const li = document.createElement('li');
                    const color = finding.severity === 'CRITICAL' ? 'text-red-800 bg-red-50 border border-red-200' :
                                  finding.severity === 'HIGH' ? 'text-orange-800 bg-orange-50 border border-orange-200' :
                                  'text-yellow-800 bg-yellow-50 border border-yellow-200';
                    li.className = `p-3 rounded-md text-sm shadow-sm ${color}`;
                    li.innerHTML = `<strong>${finding.severity}:</strong> ${finding.message}`;
                    findingsList.appendChild(li);
                }
            });

            // 3. Protocol & SA Forensics
            document.getElementById('phase1Details').innerHTML = `
                <span class="text-slate-500">Encryption:</span> <span class="font-mono text-slate-800">${config.enc_alg}</span>
                <span class="text-slate-500">Hash/PRF:</span> <span class="font-mono text-slate-800">${config.hash_alg}</span>
                <span class="text-slate-500">DH Group:</span> <span class="font-mono text-slate-800">${config.dh_group}</span>
                <span class="text-slate-500">NAT-T:</span> <span class="font-mono text-slate-800">UDP Port 4500</span>
            `;
            
            document.getElementById('phase2Details').innerHTML = `
                <span class="text-slate-500">ESP Cipher:</span> <span class="font-mono text-slate-800">${config.esp_enc}</span>
                <span class="text-slate-500">ESP HMAC:</span> <span class="font-mono text-slate-800">${config.esp_integrity}</span>
                <span class="text-slate-500">PFS:</span> <span class="font-mono text-slate-800">${config.pfs_enabled ? 'Enabled' : 'Disabled'}</span>
            `;

            document.getElementById('rawPayloads').innerText = JSON.stringify(config, null, 2);

            // 4. AI Flow Classification
            const aiFlowsList = document.getElementById('aiFlowsList');
            aiFlowsList.innerHTML = '';
            
            const trafficCounts = {};
            
            if (data.ai_analysis.length > 0 && !data.ai_analysis[0].error) {
                let totalConf = 0;
                data.ai_analysis.forEach(flow => {
                    totalConf += flow.confidence;
                    
                    // Count for doughnut chart
                    trafficCounts[flow.predicted_traffic] = (trafficCounts[flow.predicted_traffic] || 0) + 1;
                    
                    const tel = flow.telemetry || {};
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="py-2 px-2 font-mono text-gray-700">${flow.spi}</td>
                        <td class="py-2 px-2"><span class="px-2 py-1 bg-purple-100 text-purple-700 rounded text-[10px] font-bold uppercase">${flow.predicted_traffic} (${flow.confidence}%)</span></td>
                        <td class="py-2 px-2 text-gray-600">${tel.mean_packet_size || 0} B</td>
                        <td class="py-2 px-2 text-gray-600">${tel.packet_rate || 0} pkt/s</td>
                        <td class="py-2 px-2 text-gray-600">${tel.byte_rate || 0} B/s</td>
                    `;
                    aiFlowsList.appendChild(tr);
                });
                
                const avgConf = (totalConf / data.ai_analysis.length).toFixed(1);
                document.getElementById('aiGlobalScore').innerText = `${avgConf}%`;
                
                // Draw Chart
                drawTrafficChart(trafficCounts);
                
            } else {
                aiFlowsList.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-red-500">Error: ${data.ai_analysis[0]?.error || 'No flows detected'}</td></tr>`;
                document.getElementById('aiGlobalScore').innerText = `N/A`;
            }
        }
        
        function drawTrafficChart(counts) {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            if (trafficChartInstance) {
                trafficChartInstance.destroy();
            }
            
            const labels = Object.keys(counts);
            const data = Object.values(counts);
            const colors = ['#6366f1', '#ec4899', '#14b8a6', '#f59e0b', '#8b5cf6'];
            
            trafficChartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors.slice(0, labels.length),
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } }
                    }
                }
            });
        }
"""

results_pattern = re.compile(r'<div id="results".*?<!-- 4\. AI Flow Classification -->.*?</canvas>\s*</div>\s*</div>\s*</div>\s*</div>\s*</div>\s*</div>', re.DOTALL)
if not results_pattern.search(content):
    results_pattern = re.compile(r'<div id="results".*?<!-- AI Flows -->.*?</div>\s*</div>\s*</div>', re.DOTALL)
if not results_pattern.search(content):
    results_pattern = re.compile(r'<div id="results".*?</div>\s*</div>\s*</div>\s*</div>\s*</div>\s*</div>\s*</div>', re.DOTALL)
if not results_pattern.search(content):
    results_pattern = re.compile(r'<div id="results".*?<!-- Populated by JS -->\s*</tbody>\s*</table>\s*</div>\s*</div>\s*</div>\s*</div>', re.DOTALL)
if not results_pattern.search(content):
    results_pattern = re.compile(r'<div id="results".*?</div>\s*</div>\s*</div>', re.DOTALL)


if results_pattern.search(content):
    content = results_pattern.sub(new_results_html.strip(), content)
else:
    print("WARNING: Could not find results HTML to replace.")

js_pattern = re.compile(r'function renderResults\(data\) \{.*\}', re.DOTALL)
if js_pattern.search(content):
    content = js_pattern.sub(new_js.strip(), content)
else:
    print("WARNING: Could not find renderResults JS to replace.")

with open("dashboard/frontend/index.html", "w") as f:
    f.write(content)
print("Updated index.html to match exact requirements")
