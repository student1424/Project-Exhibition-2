document.addEventListener("DOMContentLoaded", () => {
  // --- DOM ELEMENTS ---
  const textInput = document.getElementById("text-input");
  const analyzeTextBtn = document.getElementById("analyze-text-btn");
  const emlInput = document.getElementById("enhanced-eml-input"); 
  const analyzeEmlBtn = document.getElementById("analyze-enhanced-btn");
  const attachmentInput = document.getElementById("attachment-input");
  const analyzeAttachmentBtn = document.getElementById("analyze-attachment-btn");
  
  // New elements for Enhanced Analysis
  const enhancedEmlInput = document.getElementById("enhanced-eml-input");
  const analyzeEnhancedBtn = document.getElementById("analyze-enhanced-btn");

  const predictionBadge = document.getElementById("prediction-badge");
  const historyList = document.getElementById("history-list");
  const quarantineList = document.getElementById("quarantine-list");
  const predictionChartCanvas = document.getElementById("prediction-chart");
  
  let predictionChart;

  // --- API FUNCTIONS ---
  const fetchData = async (endpoint, options = {}) => {
    try {
      const response = await fetch(endpoint, options);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error(`Fetch error for ${endpoint}:`, error);
      return null;
    }
  };

  const analyzeFile = (endpoint, file) => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    
    fetchData(endpoint, { method: "POST", body: formData }).then((data) => {
      if (!data) return;
      
      // Route results based on which endpoint was called
      if (endpoint === "/analyze/email") {
        displayEmailAnalysisResults(data);
      } else if (endpoint.includes("attachment")) {
        updatePredictionUI({ label: data.status, probabilities: null });
      } else {
        updatePredictionUI(data);
      }
    });
  };

  // --- UI UPDATE FUNCTIONS ---
  const updatePredictionUI = (data) => {
    if (!data) return;
    const { label, probabilities } = data;

    predictionBadge.textContent = label;
    predictionBadge.className = "badge"; 
    predictionBadge.classList.add(label.toLowerCase().replace('_', '-'));

    updatePieChart(probabilities);
    refreshData();
  };

  const updatePieChart = (probabilities) => {
    if (predictionChart) predictionChart.destroy();
    if (!probabilities) {
      predictionChartCanvas.style.display = "none";
      return;
    }
    predictionChartCanvas.style.display = "block";

    predictionChart = new Chart(predictionChartCanvas, {
      type: "pie",
      data: {
        labels: ["Safe", "Malicious"],
        datasets: [{
          data: [probabilities.safe, probabilities.malicious],
          backgroundColor: ["#16a34a", "#dc2626"],
          borderWidth: 0,
        }],
      },
      options: { plugins: { legend: { display: false } } },
    });
  };

  // --- ENHANCED ANALYSIS UI ---
  const displayEmailAnalysisResults = (data) => {
    // 1. Update the main badge with the final verdict
    updatePredictionUI({ 
      label: data.final_verdict, 
      probabilities: data.ml_prediction.probabilities || null 
    });

    // 2. Render behavioral details
    displayBehavioralAnalysis(data.behavioral_analysis);
  };

  const displayBehavioralAnalysis = (analysis) => {
    let behavioralDiv = document.getElementById('behavioral-analysis');
    if (!analysis) return;
    if (!behavioralDiv) {
      behavioralDiv = document.createElement('div');
      behavioralDiv.id = 'behavioral-analysis';
      behavioralDiv.className = 'card';
      document.querySelector('.results-column').prepend(behavioralDiv);
    }

    const trustLevel = analysis.trust_score > 70 ? 'high' : (analysis.trust_score > 40 ? 'medium' : 'low');
    
    behavioralDiv.innerHTML = `
      <h3>Sender Reputation</h3>
      <div class="reputation-details">
        <p><strong>Domain:</strong> ${analysis.domain}</p>
        <p><strong>Trust Score:</strong> <span class="score-${trustLevel}">${analysis.trust_score}/100</span></p>
        <p><strong>Risk:</strong> <span class="badge ${analysis.risk_level.toLowerCase()}">${analysis.risk_level}</span></p>
        <hr>
        <div class="technical-checks">
          <ul>
            <li>SPF Valid: ${analysis.spf_valid ? '✅' : '❌'}</li>
            <li>MX Records: ${analysis.mx_valid ? '✅' : '❌'}</li>
            <li>VT Score: ${analysis.virustotal_score}/100</li>
          </ul>
        </div>
      </div>
    `;
  };

  const refreshData = () => {
    fetchData("/scans").then(data => populateList(historyList, data, renderHistoryItem));
    fetchData("/quarantine").then(data => populateList(quarantineList, data, renderQuarantineItem));
  };

  const populateList = (listElement, items, renderFunc) => {
    listElement.innerHTML = items?.length ? "" : "<li>No items found.</li>";
    items?.forEach(item => {
      const li = document.createElement("li");
      li.innerHTML = renderFunc(item);
      listElement.appendChild(li);
    });
  };

  const renderHistoryItem = (item) => `
    <span>${item.timestamp} - ${item.type}</span>
    <span class="result-badge badge ${(item.result || item.ml_result || 'unknown').toLowerCase()}">
      ${item.result || item.ml_result}
    </span>
  `;

  const renderQuarantineItem = (item) => `
    <span><strong>${item.content}</strong></span>
    <span class="reason">${item.reason}</span>
  `;

  // --- EVENT LISTENERS ---
  analyzeTextBtn.addEventListener("click", () => {
    const text = textInput.value;
    if (!text) return;
    fetchData("/analyze_text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    }).then(updatePredictionUI);
  });

  analyzeEmlBtn.addEventListener("click", () => analyzeFile("/analyze_eml", emlInput.files[0]));
  analyzeAttachmentBtn.addEventListener("click", () => analyzeFile("/analyze_attachment", attachmentInput.files[0]));
  analyzeEnhancedBtn.addEventListener("click", () => analyzeFile("/analyze/email", enhancedEmlInput.files[0]));

  // --- INITIALIZATION ---
  refreshData();
});