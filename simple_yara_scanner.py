import glob
import os
import yara
from datetime import datetime


# yara rules folder
yara_rules_files = glob.glob("./yara-rules/*")
# files folder to scan
files_to_scan = glob.glob("./yara_test_files/*")


# To prevent ascii files error in win10 files
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def files_scanner():

    print("started scan", datetime.now())
    print(f"Found {len(files_to_scan)} Files")
    print(f"Found {len(yara_rules_files)} Yaras")
    for rule_path in yara_rules_files:
        if ".yar" not in rule_path:
            continue
        found_malicious = False

        try:
            rule = yara.compile(rule_path)
        except:
            rule = yara.load(rule_path)

        for file_path in files_to_scan:

            is_ascii_path = is_ascii(file_path)

            if not is_ascii_path and os.name == 'nt':
                with open(file_path, 'rb',buffering=1024*1024) as f:
                    match = rule.match(data=f.read(),  timeout=30)
            else:
                match = rule.match(file_path, timeout=30)

            if len(match) > 0:
                found_malicious = True
                write_to_file(rule_path, file_path)
                break
        if not found_malicious:
            write_to_file(rule_path, False)
        else:
            continue

    print("ended scan", datetime.now())

# write results to log
def write_to_file(rule_path, file_path):
    if not file_path:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f"{datetime.now()}: {rule_path} No malicious found for rule\n")
    else:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f"{datetime.now()}: {rule_path} --> {file_path} -> found malicious file!\n")



if __name__ == "__main__":
    files_scanner()
