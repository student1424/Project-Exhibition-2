# Email Security Suite Project

This project is a web-based dashboard for classifying emails and attachments as safe or malicious using a machine learning model.

---

## Prerequisites

- Python 3.8 or newer must be installed on your system.

---

## Setup and Installation Instructions

1.  **Unzip the Project:** Unzip the `Email_Security_Suite.zip` file into a folder on your PC.

2.  **Open a Terminal:** Open a command prompt or PowerShell inside the unzipped project folder (e.g., `C:\Path\To\email_suite`).

3.  **Create a Virtual Environment:** Run the following command to create an isolated Python environment.

    ```
    python -m venv venv
    ```

4.  **Activate the Environment:**

    - On Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
    - On Windows (CMD): `venv\Scripts\activate`
    - On macOS/Linux: `source venv/bin/activate`

5.  **Install Dependencies:** Once the environment is active, install all the required libraries using the requirements file.
    ```
    pip install -r requirements.txt
    ```

---

## How to Run the Application

1.  Make sure your virtual environment is still active.

2.  Run the main application script:

    ```
    python supa.py
    ```

3.  The terminal will display a URL (e.g., `http://127.0.0.1:5000`). Open this URL in your web browser to use the dashboard.

---

## How to Test the Application

A folder named `Examples` has been included in this project. It contains various text files and sample attachments that you can use to test the dashboard's functionality.

- **For the "Analyze Text" Panel:** Copy the content from any `.txt` file inside the `Examples/Text Analysis/` folder and paste it into the textarea.
- **For the "Upload Email (.eml)" Panel:** Use the "Choose File" button to upload any of the `.eml` files from the `Examples/Email Uploads/` folder.
- **For the "Upload Attachment" Panel:** Use the "Choose File" button to upload any of the files from the `Examples/Attachments/` folder to see the simulated scan results.
