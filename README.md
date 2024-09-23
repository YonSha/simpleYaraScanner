----------------------=======================================----------------------
STEPS:
1. clone
2. files handling 
Add the yara rules & the files to scan to the dedicated folders
---= OR =---
change the folder paths in the code to match your files location
# yara rules folder
yara_rules_files = glob.glob("./yara-rules/*")
# files folder to scan
files_to_scan = glob.glob("./yara_test_files/*")
3. RUN CLI: python simple_yara_scanner.py

----------------------=======================================----------------------
