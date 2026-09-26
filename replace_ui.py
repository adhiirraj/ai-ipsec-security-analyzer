import re

with open("dashboard/frontend/index.html", "r") as f:
    content = f.read()

new_results_html = """
            <div id="results" class="hidden flex flex-col gap-8">
                
                <!-- Top Row: Exec Summary & AI -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <!-- Executive Summary -->
                    <div class="col-span-2 bg-white p-6 rounded-lg shadow-md border-t-4 border-blue-600">
                        <div class="flex justify-between items-center mb-4">
                            <h2 class="text-2xl font-semibold">Executive Security Report</h2>
                            <div id="scoreBadge" class="px-4 py-1 rounded-full text-white font-bold text-lg"></div>
                        </div>
                        <div id="complianceBadge" class="inline-block mb-4 px-3 py-1 bg-gray-100 text-gray-700 rounded-md text-xs font-bold uppercase tracking-wide"></div>
                        <p id="execReportText" class="text-gray-700 text-lg leading-relaxed"></p>
                    </div>

                    <!-- AI Confidence -->
                    <div class="bg-white p-6 rounded-lg shadow-md flex flex-col justify-center items-center bg-gradient-to-br from-indigo-50 to-purple-50">
                        <h2 class="text-lg font-semibold text-indigo-900 mb-2">Overall AI Confidence</h2>
                        <div class="relative w-32 h-32 flex justify-center items-center rounded-full border-8 border-indigo-200">
                            <span id="aiGlobalScore" class="text-3xl font-black text-indigo-700">0%</span>
                        </div>
                        <p class="text-sm text-indigo-600 mt-4 text-center">Prediction Certainty across all ESP flows</p>
                    </div>
                </div>

                <!-- Middle Row: Threat Matrix & Findings -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    
                    <!-- Threat Matrix -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">Threat Matrix</h2>
                        <div class="grid grid-cols-2 gap-3" id="threatMatrixGrid">
                            <!-- Populated by JS -->
                        </div>
                    </div>

                    <!-- Detailed Findings -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">Vulnerability Findings</h2>
                        <ul id="findingsList" class="space-y-3 h-64 overflow-y-auto pr-2">
                            <!-- Populated by JS -->
                        </ul>
                    </div>
                </div>

                <!-- Bottom Row: Technical & AI Flows -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <!-- Technical Report -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">Technical Report & Wire Parameters</h2>
                        <p id="techReportText" class="text-sm text-gray-600 mb-6 italic border-l-2 border-gray-300 pl-3"></p>
                        
                        <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
                            <h3 class="font-bold text-gray-700 mb-3 text-sm uppercase tracking-wide">Extracted Payload Config</h3>
                            <div class="grid grid-cols-2 gap-4 text-sm" id="wireParamsList">
                                <!-- Populated by JS -->
                            </div>
                        </div>
                    </div>

                    <!-- AI Flows -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">AI Traffic Inference (ESP Payload)</h2>
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-left border-collapse">
                                <thead>
                                    <tr class="border-b-2 border-gray-200">
                                        <th class="py-2 px-4 text-xs font-semibold text-gray-600 uppercase tracking-wider">ESP SPI</th>
                                        <th class="py-2 px-4 text-xs font-semibold text-gray-600 uppercase tracking-wider">Inferred Class</th>
                                        <th class="py-2 px-4 text-xs font-semibold text-gray-600 uppercase tracking-wider">Confidence</th>
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
"""

new_js = """
        function renderResults(data) {
            document.getElementById('results').classList.remove('hidden');

            const sec = data.security_assessment;
            
            // Render Score & Exec Report
            const badge = document.getElementById('scoreBadge');
            badge.innerText = `${sec.score} / 100 (${sec.risk_level})`;
            badge.className = "px-4 py-1 rounded-full text-white font-bold text-lg shadow-sm " + 
                (sec.risk_level === 'LOW' ? 'bg-green-500' : 
                 sec.risk_level === 'MEDIUM' ? 'bg-yellow-500' : 
                 sec.risk_level === 'HIGH' ? 'bg-orange-500' : 'bg-red-600');
                 
            document.getElementById('execReportText').innerText = sec.executive_report || "No executive report available.";
            document.getElementById('complianceBadge').innerText = sec.compliance || "Compliance Unknown";
            document.getElementById('techReportText').innerText = sec.technical_report || "";

            // Render Threat Matrix
            const threatMatrixGrid = document.getElementById('threatMatrixGrid');
            threatMatrixGrid.innerHTML = '';
            
            // Standard threats IPsec protects against
            const allThreats = ["MITM", "Bit-Flipping", "Replay", "Collision Attacks", "Brute Force", "Data Exfiltration", "Downgrade", "Retrospective Decryption (Harvest Now, Decrypt Later)", "Message Forgery", "Traffic Analysis (Metadata Extraction)"];
            
            const activeThreats = sec.threat_matrix || [];
            
            allThreats.forEach(t => {
                const isVuln = activeThreats.includes(t);
                const color = isVuln ? "bg-red-100 border-red-300 text-red-800" : "bg-green-50 border-green-200 text-green-700";
                const icon = isVuln ? "⚠️" : "🛡️";
                threatMatrixGrid.innerHTML += `
                    <div class="border p-2 rounded-md flex items-center text-xs font-medium ${color}">
                        <span class="mr-2">${icon}</span> ${t}
                    </div>
                `;
            });

            // Render Findings
            const findingsList = document.getElementById('findingsList');
            findingsList.innerHTML = '';
            sec.findings.forEach(finding => {
                const li = document.createElement('li');
                const color = finding.severity === 'CRITICAL' ? 'text-red-700 bg-red-100' :
                              finding.severity === 'HIGH' ? 'text-orange-700 bg-orange-100' :
                              finding.severity === 'WARNING' ? 'text-yellow-700 bg-yellow-100' : 
                              finding.severity === 'STRONG' ? 'text-green-700 bg-green-100' : 'text-blue-700 bg-blue-100';
                li.className = `p-3 rounded-md text-sm ${color}`;
                li.innerHTML = `<strong>[${finding.category}]</strong> ${finding.message}`;
                findingsList.appendChild(li);
            });

            // Render Wire Parameters
            const wireParamsList = document.getElementById('wireParamsList');
            wireParamsList.innerHTML = '';
            const config = data.security_assessment.config || {};
            
            const params = [
                { label: 'Phase 1 Encryption', val: config.enc_alg },
                { label: 'Phase 1 Hash', val: config.hash_alg },
                { label: 'Phase 1 DH Group', val: config.dh_group },
                { label: 'Phase 2 Encryption', val: config.esp_enc },
                { label: 'Phase 2 HMAC', val: config.esp_integrity },
                { label: 'Perfect Forward Secrecy', val: config.pfs_enabled ? "Enabled" : "Disabled" }
            ];
            
            params.forEach(p => {
                if (p.val && p.val !== "unknown") {
                    wireParamsList.innerHTML += `
                        <div>
                            <span class="block text-xs text-gray-500">${p.label}</span>
                            <strong class="text-gray-800 font-mono">${p.val}</strong>
                        </div>
                    `;
                }
            });

            // Render AI Flows & Calculate Global Confidence
            const aiFlowsList = document.getElementById('aiFlowsList');
            aiFlowsList.innerHTML = '';
            
            if (data.ai_analysis.length > 0 && !data.ai_analysis[0].error) {
                let totalConf = 0;
                data.ai_analysis.forEach(flow => {
                    totalConf += flow.confidence;
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="py-3 px-4 font-mono text-xs text-gray-600">${flow.spi}</td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-1 bg-purple-100 text-purple-700 rounded text-xs font-bold uppercase">${flow.predicted_traffic}</span>
                        </td>
                        <td class="py-3 px-4">
                            <div class="w-full bg-gray-200 rounded-full h-2 mt-1">
                                <div class="bg-blue-600 h-2 rounded-full" style="width: ${flow.confidence}%"></div>
                            </div>
                            <span class="text-xs text-gray-500">${flow.confidence}%</span>
                        </td>
                    `;
                    aiFlowsList.appendChild(tr);
                });
                
                const avgConf = (totalConf / data.ai_analysis.length).toFixed(1);
                const circleColor = avgConf > 80 ? 'border-green-400 text-green-600' : 
                                   avgConf > 60 ? 'border-yellow-400 text-yellow-600' : 'border-red-400 text-red-600';
                
                const aiCircle = document.getElementById('aiGlobalScore').parentElement;
                aiCircle.className = `relative w-32 h-32 flex justify-center items-center rounded-full border-8 ${circleColor}`;
                document.getElementById('aiGlobalScore').innerText = `${avgConf}%`;
                document.getElementById('aiGlobalScore').className = `text-3xl font-black ${circleColor.split(' ')[1]}`;
                
            } else {
                aiFlowsList.innerHTML = `<tr><td colspan="3" class="py-4 text-center text-red-500">Error: ${data.ai_analysis[0]?.error || 'No flows detected'}</td></tr>`;
                document.getElementById('aiGlobalScore').innerText = `N/A`;
            }
        }
"""

# Replace the HTML block
results_pattern = re.compile(r'<div id="results" class="hidden.*?<!-- AI Flows -->.*?</div>\s*</div>\s*</div>', re.DOTALL)
if not results_pattern.search(content):
    # Try a different regex if it fails
    results_pattern = re.compile(r'<div id="results".*?<!-- Populated by JS -->\s*</tbody>\s*</table>\s*</div>\s*</div>\s*</div>', re.DOTALL)
    
if results_pattern.search(content):
    content = results_pattern.sub(new_results_html.strip(), content)
else:
    print("WARNING: Could not find results HTML to replace.")

# Replace the JS function
js_pattern = re.compile(r'function renderResults\(data\) \{.*\}', re.DOTALL)
if js_pattern.search(content):
    content = js_pattern.sub(new_js.strip(), content)
else:
    print("WARNING: Could not find renderResults JS to replace.")

with open("dashboard/frontend/index.html", "w") as f:
    f.write(content)
print("Updated index.html")
