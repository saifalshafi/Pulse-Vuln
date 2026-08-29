import sys
import json
import ipaddress
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QStackedWidget,
    QMessageBox, QFileDialog, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from scanner_app.core.port_scanner import PortScanner
from scanner_app.intelligence.cve_mapper import CVEMapper
from scanner_app.intelligence.risk_engine import RiskEngine
from scanner_app.reporting.pdf_report import generate_pdf


# ==========================================================
# Worker Thread (Now supports Subnet)
# ==========================================================

class ScanWorker(QThread):
    finished_signal = pyqtSignal(dict, float, str)
    progress_signal = pyqtSignal(int)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):

        results = {}
        mapper = CVEMapper()

        # Convert CIDR to list of hosts
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except:
            targets = [self.target]

        total_hosts = len(targets)
        current = 0

        for host in targets:

            current += 1
            progress = int((current / total_hosts) * 100)
            self.progress_signal.emit(progress)

            open_ports = PortScanner.scan(host)

            if not open_ports:
                continue

            cves = []
            for port, info in open_ports.items():
                version = info.get("version", "")
                if version:
                    found = mapper.search(version)
                    if found:
                        cves.extend(found)

            results[host] = {
                "ports": open_ports,
                "cves": cves
            }

        if not results:
            self.finished_signal.emit({}, 0, "LOW")
            return

        risk_score = RiskEngine.calculate(results)
        risk_level = RiskEngine.classify(risk_score)

        self.finished_signal.emit(results, risk_score, risk_level)


# ==========================================================
# GUI Main (unchanged layout, improved logic)
# ==========================================================

class PulseGUI(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PULSE - Enterprise Vulnerability Platform")
        self.resize(1200, 800)
        self.setStyleSheet("background-color: #0f1220; color: white;")

        self.last_results = None
        self.last_risk_score = 0
        self.last_risk_level = "LOW"

        self.init_ui()

    def init_ui(self):

        main_layout = QHBoxLayout(self)

        sidebar = QVBoxLayout()
        sidebar.setAlignment(Qt.AlignTop)

        self.btn_scan = QPushButton("Scan")
        self.btn_results = QPushButton("Results")
        self.btn_pdf = QPushButton("Export PDF")
        self.btn_json = QPushButton("Export JSON")

        for btn in [self.btn_scan, self.btn_results, self.btn_pdf, self.btn_json]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #141833;
                    border: 2px solid #00ffff;
                    padding: 10px;
                }
                QPushButton:hover {
                    background-color: #00ffff;
                    color: black;
                }
            """)
            sidebar.addWidget(btn)

        main_layout.addLayout(sidebar, 1)

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, 4)

        self.scan_page = QWidget()
        self.results_page = QWidget()

        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.results_page)

        self.build_scan_page()
        self.build_results_page()

        self.stack.setCurrentIndex(0)

        self.btn_scan.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_results.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_pdf.clicked.connect(self.export_pdf)
        self.btn_json.clicked.connect(self.export_json)

    # ======================================================
    # Scan Page
    # ======================================================

    def build_scan_page(self):

        layout = QVBoxLayout()

        title = QLabel("PULSE - Enterprise Vulnerability Intelligence")
        title.setAlignment(Qt.AlignCenter)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP or Subnet (e.g. 192.168.1.0/24)")

        self.start_btn = QPushButton("Start Scan")
        self.progress = QProgressBar()

        layout.addWidget(title)
        layout.addWidget(self.target_input)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.progress)

        self.scan_page.setLayout(layout)

        self.start_btn.clicked.connect(self.start_scan)

    # ======================================================
    # Results Page
    # ======================================================

    def build_results_page(self):

        layout = QVBoxLayout()

        self.port_table = QTableWidget()
        self.port_table.setColumnCount(4)
        self.port_table.setHorizontalHeaderLabels(["Host", "Port", "Service", "Version"])
        self.port_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.cve_table = QTableWidget()
        self.cve_table.setColumnCount(5)
        self.cve_table.setHorizontalHeaderLabels(
            ["Host", "CVE ID", "Severity", "Score", "Description"]
        )
        self.cve_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.severity_fig = Figure()
        self.severity_canvas = FigureCanvas(self.severity_fig)

        layout.addWidget(QLabel("Open Ports"))
        layout.addWidget(self.port_table)

        layout.addWidget(QLabel("CVEs"))
        layout.addWidget(self.cve_table)

        layout.addWidget(QLabel("Severity Distribution"))
        layout.addWidget(self.severity_canvas)

        self.results_page.setLayout(layout)

    # ======================================================
    # Start Scan
    # ======================================================

    def start_scan(self):

        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target.")
            return

        self.progress.setValue(0)
        self.start_btn.setEnabled(False)

        self.worker = ScanWorker(target)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    # ======================================================
    # Scan Finished
    # ======================================================

    def scan_finished(self, results, risk_score, risk_level):

        self.start_btn.setEnabled(True)

        if not results:
            QMessageBox.information(self, "Info", "No open ports found.")
            return

        self.last_results = results
        self.last_risk_score = risk_score
        self.last_risk_level = risk_level

        self.update_ports_table(results)
        self.update_cve_table(results)
        self.update_severity_chart(results)

        self.stack.setCurrentIndex(1)

        QMessageBox.information(
            self,
            "Scan Complete",
            f"Risk Score: {risk_score}\nRisk Level: {risk_level}"
        )

    # ======================================================
    # Update Tables
    # ======================================================

    def update_ports_table(self, results):

        rows = []
        for host, data in results.items():
            for port, info in data["ports"].items():
                rows.append((host, port, info))

        self.port_table.setRowCount(len(rows))

        for row, (host, port, info) in enumerate(rows):
            self.port_table.setItem(row, 0, QTableWidgetItem(host))
            self.port_table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.port_table.setItem(row, 2, QTableWidgetItem(info["service"]))
            self.port_table.setItem(row, 3, QTableWidgetItem(info["version"]))

    def update_cve_table(self, results):

        rows = []
        for host, data in results.items():
            for cve in data["cves"]:
                rows.append((host, cve))

        self.cve_table.setRowCount(len(rows))

        for row, (host, cve) in enumerate(rows):
            self.cve_table.setItem(row, 0, QTableWidgetItem(host))
            self.cve_table.setItem(row, 1, QTableWidgetItem(cve["cve_id"]))
            self.cve_table.setItem(row, 2, QTableWidgetItem(cve["severity"]))
            self.cve_table.setItem(row, 3, QTableWidgetItem(str(cve["score"])))
            self.cve_table.setItem(row, 4, QTableWidgetItem(cve["description"]))

    # ======================================================
    # Chart
    # ======================================================

    def update_severity_chart(self, results):

        severity_count = {}

        for host, data in results.items():
            for cve in data["cves"]:
                sev = cve["severity"]
                severity_count[sev] = severity_count.get(sev, 0) + 1

        self.severity_fig.clear()
        ax = self.severity_fig.add_subplot(111)

        if severity_count:
            ax.pie(severity_count.values(), labels=severity_count.keys(), autopct='%1.1f%%')

        self.severity_canvas.draw()

    # ======================================================
    # Export JSON
    # ======================================================

    def export_json(self):

        if not self.last_results:
            QMessageBox.warning(self, "Error", "No scan data available.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save JSON",
            "pulse_report.json",
            "JSON Files (*.json)"
        )

        if filename:
            with open(filename, "w") as f:
                json.dump(self.last_results, f, indent=4)

            QMessageBox.information(self, "Success", "JSON file saved successfully.")

    # ======================================================
    # Export PDF
    # ======================================================

    def export_pdf(self):

        if not self.last_results:
            QMessageBox.warning(self, "Error", "No scan data available.")
            return

        filename = generate_pdf(
            self.last_results,
            self.last_risk_score,
            self.last_risk_level
        )

        QMessageBox.information(self, "Success", f"PDF Generated:\n{filename}")


# ==========================================================

def main():
    app = QApplication(sys.argv)
    window = PulseGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
