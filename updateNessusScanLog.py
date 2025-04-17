#!/usr/bin/python

"""
用途: 更新Nessus掃描結果到DB
參考: https://community.tenable.com/s/question/0D53a00006N4j4zCAB/nessus-professional-api-python-script-to-download-filtered-scan-in-csv-format?language=en_US
"""

import requests, json, time, urllib3
import csv
import io
import mysql.connector
from datetime import datetime
from dotenv import load_dotenv
import os

# Variables
load_dotenv()

## DB
DB_HOST = os.getenv("DB_HOST")  # 連線主機名稱
DB_USER = os.getenv("DB_USER")  # 登入帳號
DB_PASSWD = os.getenv("DB_PASSWD")  # 登入密碼
DB_DATABASE = os.getenv("DB_DATABASE")
DB_CHARSET = os.getenv("DB_CHARSET")
DB_PORT = os.getenv("DB_PORT")
## Nessus
nessusBaseURL = os.getenv("nessusBaseURL")
nessusUsername = os.getenv("nessusUsername")
nessusPassword = os.getenv("nessusPassword")
upToThisManyDaysAgo = os.getenv("upToThisManyDaysAgo")
folderID = os.getenv("folderID")
sleepPeriod = os.getenv("sleepPeriod")

# Turn off TLS warnings
urllib3.disable_warnings()


#########################
# Nessus
#########################


def check_nessus_alive():
    """確認Nessus可以連線

    Returns:
        bool: _description_
    """
    try:
        response = requests.get(
            nessusBaseURL + "/server/status", verify=False, timeout=5
        )
        if response.status_code == 200:
            status = response.json().get("status")
            if status == "ready":
                print("[✓] Nessus Server Ready")
                return True
            else:
                print("[!] Nessus Server status: " + status)
        else:
            print(f"[!] Unexpected status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[X] 無法連線到 Nessus Server: {e}")

    return False


# 取得Token(登入)
def get_token():
    """取得Token
    Returns:
        string: token
    """
    URL = nessusBaseURL + "/session"
    TOKENPARAMS = {"username": nessusUsername, "password": nessusPassword}
    r = requests.post(url=URL, data=TOKENPARAMS, verify=False)
    jsonData = r.json()
    token = str("token=" + jsonData["token"])
    return token


# 更新表頭
def reflash_header():
    """更新表頭

    Returns:
        bool: 成功
    """
    global headers

    # Grab the token
    token = get_token()

    headers = {
        "X-Cookie": token,
        "Content-type": "application/json",
        "Accept": "text/plain",
    }

    return True


# 取得掃描清單
def get_scan_list(folderID, upToThisManyDaysAgo):
    """取得掃描清單

    Args:
        folderID (int): 資料夾ID
        upToThisManyDaysAgo (int): 篩選指定天數內

    Returns:
        list: scan list
    """

    # Look for scans from upToThisManyDaysAgo from GET /scans request
    epochTime = time.time()
    lastDay = str(epochTime - (60 * 60 * 24 * int(upToThisManyDaysAgo)))
    splitDay = lastDay.split(".", -1)
    URL = (
        nessusBaseURL
        + "/scans?folder_id="
        + str(folderID)
        + "&last_modification_date="
        + splitDay[0]
    )
    t = requests.get(url=URL, headers=headers, verify=False)
    data = t.json()

    # Cycle through the scans from upToThisManyDaysAgo looking for ones that have been completed and add them to a list
    scanIDs = []
    for line in data["scans"]:
        if line["status"] == "completed":
            scanIDs.append([line["id"], line["name"]])

    return scanIDs


# 取得指定掃描清單scan id的掃描結果
def export_scan(ID):
    """取得指定scan id的掃描結果

    Args:
        ID (int): scan id

    Returns:
        dict: _description_
    """

    # Call the POST /export function to collect details for each scan
    URL = nessusBaseURL + "/scans/" + str(ID) + "/export"

    # In this case, we're asking for a:
    #   - CSV export
    #   - Only requesting certain fields
    #   - Severity = 4 (aka Critical) only
    payload = {
        "format": "csv",
        "reportContents": {
            "csvColumns": {
                "id": True,  # Plugin ID
                "cve": False,
                "cvss": False,  # CVSS v2
                "risk": True,  # 整數型風險等級（0=Info, 1=Low, 2=Medium, 3=High, 4=Critical）
                "hostname": True,  # 主機名稱或 IP
                "protocol": True,
                "port": True,
                "plugin_name": True,  # 弱點名稱（人類可讀）
                "synopsis": True,  # 簡短摘要說明
                "description": True,  # 詳細描述
                "solution": True,  # 建議修補方法
                "see_also": False,  # 參考連結
                "plugin_output": True,  # 掃描時實際輸出結果
                "stig_severity": False,  # STIG 弱點等級
                "cvss3_base_score": False,  # CVSS v3 基本分數
                "cvss_temporal_score": False,  # CVSS v2 時效性分數（Temporal）
                "cvss3_temporal_score": False,  # CVSS v3 時效性分數
                "risk_factor": False,  # 文字型風險標籤（如 Medium, High）
                "references": False,  # 額外參考資料（URL 等）
                "plugin_information": False,  # Plugin 類型、版本等資訊
                "exploitable_with": False,  # 與哪些 exploit 框架（Metasploit、Canvas 等）配合可利用
            }
        },
        "extraFilters": {"host_ids": [], "plugin_ids": []},
        "filter.search_type": "and",
        # 風險等級不是info
        "filter.0.quality": "neq",
        "filter.0.filter": "severity",
        "filter.0.value": 0,
        # 風險等級不是low
        "filter.1.quality": "neq",
        "filter.1.filter": "severity",
        "filter.1.value": 1,
    }

    # Pass the POST request in json format. Two items are returned, file and token
    jsonPayload = json.dumps(payload)
    r = requests.post(url=URL, headers=headers, data=jsonPayload, verify=False)
    jsonData = r.json()
    scanFile = str(jsonData["file"])
    scanToken = str(jsonData["token"])

    # Use the file just received and check to see if it's 'ready', otherwise sleep for sleepPeriod seconds and try again
    status = "loading"
    while status != "ready":
        URL = nessusBaseURL + "/scans/" + str(ID) + "/export/" + scanFile + "/status"
        t = requests.get(url=URL, headers=headers, verify=False)
        data = t.json()
        if data["status"] == "ready":
            status = "ready"
        else:
            time.sleep(int(sleepPeriod))

    # Now that the report is ready, download
    URL = nessusBaseURL + "/scans/" + str(ID) + "/export/" + scanFile + "/download"
    d = requests.get(url=URL, headers=headers, verify=False)
    dataBack = d.text

    # 3. 解析 CSV 資料
    csv_text = dataBack.replace("\r\n", "\n")
    csv_file = io.StringIO(csv_text)
    reader = csv.DictReader(csv_file)

    return reader


def save_to_nessus_db(row, cursor, now=None):
    """將結果存到DB中"""

    plugin_id = int(row["Plugin ID"])
    host = row["Host"]
    protocol = row["Protocol"]
    port = int(row["Port"])
    risk = row["Risk"]
    name = row["Name"]
    synopsis = row["Synopsis"]
    description = row["Description"]
    solution = row["Solution"]
    plugin_output = row["Plugin Output"]

    if now is None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 插入或更新不變資料（plugin 資訊）
    cursor.execute(
        """
        INSERT INTO nessus_plugin (plugin_id, name, synopsis, description, solution)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            synopsis = VALUES(synopsis),
            solution = VALUES(solution)
    """,
        (plugin_id, name, synopsis, description, solution),
    )

    # 插入或更新掃描結果（變動資料）
    cursor.execute(
        """
        INSERT INTO nessus_scan         
        (Host, PluginID, Protocol, Port, Name, Risk, PluginOutput,LastScanDate)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            PluginOutput = VALUES(PluginOutput),
            LastScanDate = VALUES(LastScanDate)
    """,
        (host, plugin_id, protocol, port, name, risk, plugin_output, now),
    )


if check_nessus_alive() is False:
    print("結束腳本")
    exit()

# 建立MySQL連線
conn = mysql.connector.connect(
    host=DB_HOST,  # 連線主機名稱
    user=DB_USER,  # 登入帳號
    password=DB_PASSWD,  # 登入密碼
    database=DB_DATABASE,
    charset=DB_CHARSET,
    port=DB_PORT,
)
cursor = conn.cursor()


reflash_header()
scanIDs = get_scan_list(folderID, upToThisManyDaysAgo)

# Main loop for the program
for listID in scanIDs:
    ID = listID[0]
    NAME = str(listID[1])
    NAMECLEAN = NAME.replace("/", "-", -1)

    print("-----------------------------------------------")
    print("Starting  " + NAMECLEAN + "   id:" + str(ID))

    reader = export_scan(ID)
    idx = 0
    for idx, line in enumerate(reader, start=1):
        # print(line)
        save_to_nessus_db(line, cursor)

        # 每300筆先儲存一次
        if idx % 300 == 0:
            conn.commit()

    conn.commit()
    print("　已處理 " + str(idx) + " 筆資料")

    print("Completed " + NAMECLEAN)

cursor.close()
conn.close()
