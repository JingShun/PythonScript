import re # 處理正規表示式
import csv # 處理CSV
import sys # 讀取命令參數

# 要分析的原始檔案(僅限csv)
fileName = sys.argv[1] if len(sys.argv) > 1 else 'data.csv'
# 處理後另存檔案
reportName = sys.argv[2] if len(sys.argv) > 2 else 'report.csv'

# 解決大檔按導致的錯誤
maxInt = sys.maxsize
try:
    csv.field_size_limit(maxInt)
    break
except OverflowError:
    maxInt = int(maxInt/10)

# 開啟原始 CSV 檔案
file = open(fileName, encoding='utf8')
rows = csv.reader(file)

# 另存 CSV 檔案
newFile = open(reportName, 'w', newline='', encoding='utf8')
writer = csv.writer(newFile, delimiter=',', quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)

# 處理每行資料
for row in rows:
    # 取出該筆資料中全部車牌
    card = re.findall("[\dA-Z]{2,4}-[\dA-Z]{2,4}", ' '.join(row))
    # 將取出的車牌附加到該筆資料的最後面
    row.append(', '.join(card))
    # 另存資料
    writer.writerow(row)
    print(row)
