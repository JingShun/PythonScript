import glob
import pandas as pd
import sys  # 讀取命令參數
import os

# 要忽略前面幾行
ignoreLines = int(sys.argv[1] if len(sys.argv) > 1 else 0)
# 要合併的路徑
path = sys.argv[2] if len(sys.argv) > 2 else ''
# 處理後另存檔案
reportName = sys.argv[3] if len(sys.argv) > 3 else 'export.csv'

# 最終合併的數據
mergeData = pd.DataFrame()


# 取得Excel清單
fileList = glob.glob(os.path.join(path, "*.xls[x]*"))

# 讀取檔案清單
for file in fileList:
    print("讀取" + file)
    sheet_to_df_map = pd.read_excel(file, header=None, sheet_name=None)
    
    # 讀取sheet清單
    for sheetName in sheet_to_df_map:
        print("取出" + sheetName)

        # 取出開頭ignoreLines的行數之後的資料
        sheet_to_df_map[sheetName] = sheet_to_df_map[sheetName].iloc[ignoreLines:, :]

        # 刪掉全是NaN的列
        sheet_to_df_map[sheetName] = sheet_to_df_map[sheetName].dropna(how='all')

        # 合併兩個DataFrame
        mergeData = pd.concat([
            pd.DataFrame.from_records(mergeData),
            pd.DataFrame.from_records(sheet_to_df_map[sheetName])
        ], ignore_index=True)


print("輸出最終結果")
print(mergeData)

# 匯出成csv
#mergeData.to_csv(reportName, index=False)
