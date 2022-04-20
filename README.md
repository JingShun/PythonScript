# PythonScript
一些用python寫的小工具



## transLicensePlate.py
### 用途:
透過Python將CSV中的車牌放到最後一個欄位

本腳本實現
1. 讀取CSV
2. 透過REGEX(正規表示式)撈取特定資料並新增到最後一行
3. 匯出CSV

### 用法:
```
python3 transLicensePlate.py [<來源=data.csv> [<匯出的檔案名稱=report.csv>]]
```


## MergeExcelToCsv.py
### 用途:
透過Python合併多個Excel中的多個Sheet到CSV檔，

本腳本實現
1. 讀取Excel
2. 讀取每個Sheet
3. 忽略開頭指定行數
4. 另存成CSV
### 用法:
```python=
python3 MergeExcelToCsv.py [<要忽略的行數=0> [<相對路徑=./> [<匯出的檔案名稱=export.csv>]]]

python3 MergeExcelToCsv.py 3 ./ export.csv
```

### 備註
1. 目前已知若路徑有特殊符號，會讀不到檔案


## virustotal-search.py
### 用途:
將md5清單上傳到VirusTotal進行驗證

copy by [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite)

原始RAW: https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/virustotal-search.py

複製版本: 0.1.6

### 用法:
參考
https://www.youtube.com/watch?v=D925hYZjKY0
