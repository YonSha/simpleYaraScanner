import glob
import os
import yara
from datetime import datetime
import multiprocessing
from multiprocessing import Value


# yara rules folder
yara_rules_files = glob.glob("./yara-rules/*", recursive=True)
# files folder to scan
files_to_scan = glob.glob("./yara_test_files/*", recursive=True)

# To prevent ascii files error in win10 files
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def files_scanner(file_chunk,rule_path,result_value,shared_list):
    try:
        rule = yara.compile(rule_path)
    except:
        rule = yara.load(rule_path)

    for file_path in file_chunk:
        if result_value.value > 0:
            break

        is_ascii_path = is_ascii(file_path)

        if not is_ascii_path and os.name == 'nt':
            with open(file_path, 'rb',buffering=1024*1024) as f:
                match = rule.match(data=f.read(),  timeout=30)
        else:
            match = rule.match(file_path, timeout=30)

        if len(match) > 0:
            result_value.value += 1
            shared_list.append(file_path)
            break


# write results to log
def write_to_file(rule_path, file_path,):
    if not file_path:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f"{datetime.now()}: {rule_path} --> No malicious found for rule\n")
    else:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f"{datetime.now()}: {rule_path} --> {file_path} -> found malicious file!\n")

def split_into_six_equal_lists(big_list):
    n = len(big_list)
    # Determine the size of each sublist
    size = n // 6

    # Create the six sublists
    list1 = big_list[:size]
    list2 = big_list[size:size*2]
    list3 = big_list[size*2:size*3]
    list4 = big_list[size*3:size*4]
    list5 = big_list[size*4:size*5]
    list6 = big_list[size*5:]

    return list1, list2, list3, list4, list5, list6

if __name__ == "__main__":

    print("started scan", datetime.now())
    print(f"Found {len(files_to_scan)} Files")
    print(f"Found {len(yara_rules_files)} Yaras")

    chunk_one, chunk_two, chunk_three, chunk_four, chunk_five, chunk_six = split_into_six_equal_lists(files_to_scan)
    manager = multiprocessing.Manager()
    shared_list = manager.list()
    result_value = Value('i', 0)

    for rule_path in yara_rules_files:
        if ".yar" not in rule_path:
            continue
        result_value.value = 0
        process1 = multiprocessing.Process(target=files_scanner, args=(chunk_one,rule_path,result_value,shared_list))
        process2 = multiprocessing.Process(target=files_scanner, args=(chunk_two,rule_path,result_value,shared_list))
        process3 = multiprocessing.Process(target=files_scanner, args=(chunk_three,rule_path,result_value,shared_list))
        process4 = multiprocessing.Process(target=files_scanner, args=(chunk_four,rule_path,result_value,shared_list))
        process5 = multiprocessing.Process(target=files_scanner, args=(chunk_five,rule_path,result_value,shared_list))
        process6 = multiprocessing.Process(target=files_scanner, args=(chunk_six,rule_path,result_value,shared_list))

        # Start the processes
        process1.start()
        process2.start()
        process3.start()

        process1.join()
        process2.join()
        process3.join()

        if result_value.value == 0:
            write_to_file(rule_path, False)
        else:
            write_to_file(rule_path, shared_list[0])
            shared_list.pop()

    print("ended scan", datetime.now())