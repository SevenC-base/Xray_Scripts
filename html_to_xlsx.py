#!/usr/bin/env python
# -*- coding:UTF-8 -*-
# 2021/10/21 周四 10:14:56
# By  Hasaki-h1
import os
import re, json, time
import sys

import xlsxwriter


def stampToTime(stamp):
    datatime1 = time.strftime ("%Y-%m-%d %H:%M:%S", time.localtime (float (str (stamp)[0:10])))
    return datatime1


def parse_single(filename):
    with open (filename, "r", encoding="utf-8") as f:
        str1 = f.read ()
    vuln1_info = re.findall (r"<script class='web-vulns'>webVulns.push\((.*?)\)</script>", str1, re.M | re.I)
    dict2 = {}
    dict2_add = []
    dic_a = []
    for i in range (0, len (vuln1_info)):
        dict2_add.append (dict (dict2))
    for info in vuln1_info:
        name1 = vuln1_info.index (info)
        dict1 = json.loads (info)
        dict2_add[name1]["创建时间"] = stampToTime (dict1["create_time"])
        dict2_add[name1]["漏洞链接"] = dict1["target"]["url"]
        dict2_add[name1]["插件名称"] = dict1["plugin"]
        dict2_add[name1]["额外信息"] = dict1["detail"]["extra"]
        for i in range (0, len (dict1["detail"]["snapshot"])):
            request_n = "request%s" % (i + 1)
            response_n = "response%s" % (i + 1)
            dict2_add[name1][request_n] = dict1["detail"]["snapshot"][i][0]
            dict2_add[name1][response_n] = dict1["detail"]["snapshot"][i][1]
            i = int (i) + 1
        dict2_add[name1]["snapshot_len"] = len (dict1["detail"]["snapshot"])
        dic_a.append (dict2_add[name1])
    return dic_a


def write_csv(dict_results, file_n):
    ID = 1
    max1 = 0
    file_name = time.strftime ("%Y%m%d-%H%M%S-", time.localtime (float (str (time.time ())[0:10]))) + file_n + ".xlsx"
    workbook = xlsxwriter.Workbook (filename=file_name)
    worksheet = workbook.add_worksheet ()
    bold = workbook.add_format ({'bold': True})
    # 基本list_title
    list_title = ["ID", "CreateTime", "target", "PluginName/VulnType", "Extra"]
    # 生成list_title
    for dict_r in dict_results:
        if dict_r["snapshot_len"] > max1:
            max1 = dict_r["snapshot_len"]
    for l0 in range (0, max1):
        add_tit_req = "request" + str (l0)
        add_tit_res = "response" + str (l0)
        list_title.append (add_tit_req)
        list_title.append (add_tit_res)
    # 写标题
    for col_c in list_title:
        col = list_title.index (col_c)
        worksheet.write (0, col, col_c, bold)
    for dict_r in dict_results:
        row_n = dict_results.index (dict_r) + 1
        keys = list (dict_r.keys ())
        for k, v in dict_r.items ():
            col_n = keys.index (k)
            if k == "snapshot_len":
                pass
            else:
                worksheet.write (row_n, 0, str (ID))

                write_v = json.dumps (v).replace ('"', "")
                if k == "漏洞链接":
                    worksheet.write_string (row_n, col_n + 1, write_v)
                else:
                    worksheet.write (row_n, col_n + 1, write_v)
        ID = ID + 1
    worksheet.set_column ('A:A', 3)
    worksheet.set_column ('B:B', 20)
    worksheet.set_column ('C:C', 35)
    worksheet.set_column ('D:D', 30)
    worksheet.set_column ('E:E', 10)
    worksheet.set_column ('F:I', 50)
    workbook.close ()
    return file_name


def get_file_list(directory):
    """单独一个目录"""
    files_list = []
    files_path_list = []
    files_p_list = []
    if os.path.exists (directory):
        directory_n = directory
    else:
        print ("%s 不是一个有效的目录！！！" % directory)
        sys.exit ()
    # 遍历目录下读取可读文件
    all_files_directory = os.walk (directory_n, topdown=True, followlinks=True)
    for root, dirs, files in all_files_directory:
        # 获取文件路径
        for f_name in files:
            file_path_d = os.path.join (root, f_name)
            files_path_list.append (file_path_d)
            files_p_list.append (f_name)
    return files_path_list, files_p_list


def main(directory, file_n):
    all_file_path, all_file = get_file_list (directory)
    dict_all = []
    for a_f in all_file_path:
        try:
            dict_one = parse_single (a_f)
            dict_all = dict_one + dict_all
        except Exception as e:
            print ("\n---------------------------- 文件：%s 解析失败  ---------------------------- \n" % a_f.split ("\\")[-1], e)
            sys.exit (0)
        print ("\n", all_file[all_file_path.index (a_f)], "解析成功")
    f_n = write_csv (dict_all, file_n)
    print ("\n-------------%s 保存成功" % f_n)


if __name__ == "__main__":
    str1 = '''  _    _ _             _   _               _          
 | |  | | |           | | | |             | |         
 | |__| | |_ _ __ ___ | | | |_ ___   __  _| |_____  __
 |  __  | __| '_ ` _ \| | | __/ _ \  \ \/ / / __\ \/ /
 | |  | | |_| | | | | | | | || (_) |  >  <| \__ \>  < 
 |_|  |_|\__|_| |_| |_|_|  \__\___/  /_/\_\_|___/_/\_\
                                                      
                                                      '''
    print (str1)
    try:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help" or sys.argv[1] == "/?":
            print ("\neg: python html_to_xlsx.py results")
            print ("    python html_to_xlsx.py D:\\test\\results")
        else:
            if os.path.exists (sys.argv[1]):
                dir1 = os.path.abspath (sys.argv[1])
                ll = dir1.split ("\\")[-1]
                main (dir1, ll)
            else:
                print ("\n------------------------------------ 文件不存在！！！")
                print ("\neg: python html_to_xlsx.py results")
                print ("    python html_to_xlsx.py D:\\test\\results")
    except IndexError as e:
        print ("\n ----------------------------  参数异常  ---------------------------- \n")
        print ("eg: python html_to_xlsx.py results")
        print ("    python html_to_xlsx.py D:\\test\\results")
    finally:
        pass
    # parse_single("E:\\1-WebSecurity\\1-recon\\2-scanner\\Xray\\parse-results\\test\\b13794cedcebe72bb53f0d5fbcf7c4c5.html")
