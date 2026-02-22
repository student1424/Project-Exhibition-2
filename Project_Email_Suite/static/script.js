document.addEventListener("DOMContentLoaded", () => {
  // --- DOM ELEMENTS ---
  const textInput = document.getElementById("text-input");
  const analyzeTextBtn = document.getElementById("analyze-text-btn");
  const emlInput = document.getElementById("eml-input");
  const analyzeEmlBtn = document.getElementById("analyze-eml-btn");
  const attachmentInput = document.getElementById("attachment-input");
  const analyzeAttachmentBtn = document.getElementById(
    "analyze-attachment-btn"
  );

  const predictionBadge = document.getElementById("prediction-badge");
  const historyList = document.getElementById("history-list");
  const quarantineList = document.getElementById("quarantine-list");
  const predictionChartCanvas = document.getElementById("prediction-chart");

  let predictionChart;

  // --- MOCK API RESPONSES FOR TESTING ---
  const MOCK_DATA = {
    scanResult: {
      label: "Safe",
      probabilities: { safe: 0.92, malicious: 0.08 },
    },
    history: [
      {
        timestamp: "2025-01-15 10:30:00",
        type: "Email",
        filename: "welcome.eml",
        result: "Safe",
      },
      {
        timestamp: "2025-01-15 10:28:15",
        type: "Attachment",
        filename: "invoice.pdf",
        result: "Safe",
      },
    ],
    quarantine: [
      {
        type: "Attachment",
        content: "setup.exe",
        reason: "Potential malware detected.",
      },
    ],
  };

  // --- API FUNCTIONS ---
  const fetchData = async (endpoint, options = {}) => {
    try {
      const response = await fetch(endpoint, options);
      if (!response.ok)
        throw new Error(`HTTP error! status: ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error(`Fetch error for ${endpoint}:`, error);
      // In a real app, you'd show an error to the user
      return null;
    }
  };

  const analyzeText = () => {
    const text = textInput.value;
    if (!text) return;
    fetchData("/analyze_text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    }).then(updatePredictionUI);
  };

  const analyzeFile = (endpoint, file) => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    fetchData(endpoint, { method: "POST", body: formData }).then((data) => {
      if (endpoint.includes("attachment")) {
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
    predictionBadge.className = "badge"; // Reset classes
    predictionBadge.classList.add(label.toLowerCase());

    updatePieChart(probabilities);
    refreshData(); // Refresh history and quarantine after each scan
  };

  const updatePieChart = (probabilities) => {
    if (predictionChart) predictionChart.destroy();
    if (!probabilities) {
      // Hide chart if no probability data
      predictionChartCanvas.style.display = "none";
      return;
    }
    predictionChartCanvas.style.display = "block";

    predictionChart = new Chart(predictionChartCanvas, {
      type: "pie",
      data: {
        labels: ["Safe", "Malicious"],
        datasets: [
          {
            data: [probabilities.safe, probabilities.malicious],
            backgroundColor: ["#16a34a", "#dc2626"],
            borderWidth: 0,
          },
        ],
      },
      options: { plugins: { legend: { display: false } } },
    });
  };

  const populateList = (listElement, items, renderFunc) => {
    listElement.innerHTML = ""; // Clear list
    if (!items || items.length === 0) {
      listElement.innerHTML = "<li>No items found.</li>";
      return;
    }
    items.forEach((item) => {
      const li = document.createElement("li");
      li.innerHTML = renderFunc(item);
      listElement.appendChild(li);
    });
  };

  const renderHistoryItem = (item) => `
        <span>${item.timestamp} - ${item.type} (${item.filename})</span>
        <span class="result-badge badge ${item.result.toLowerCase()}">${
    item.result
  }</span>
    `;

  const renderQuarantineItem = (item) => `
        <span>${item.type}: <strong>${item.content}</strong></span>
        <span class="reason">${item.reason}</span>
    `;

  const refreshData = () => {
    fetchData("/scans").then((data) =>
      populateList(historyList, data, renderHistoryItem)
    );
    fetchData("/quarantine").then((data) =>
      populateList(quarantineList, data, renderQuarantineItem)
    );
  };

  // --- EVENT LISTENERS ---
  analyzeTextBtn.addEventListener("click", analyzeText);
  analyzeEmlBtn.addEventListener("click", () =>
    analyzeFile("/analyze_eml", emlInput.files[0])
  );
  analyzeAttachmentBtn.addEventListener("click", () =>
    analyzeFile("/analyze_attachment", attachmentInput.files[0])
  );

  // --- INITIALIZATION ---
  console.log("Initializing dashboard...");
  updatePieChart(null); // Start with no chart
  refreshData(); // Load initial history and quarantine
});
