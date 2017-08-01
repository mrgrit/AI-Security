"""
Update 내용
1) firewall 은 ip cache 만 쓰고 한줄한줄 insert하지 않도록 변경
2) Report 기능 추가
3) 예외 처리 적용
4) Black List / White List 해볼까..?
5) 모듈화 및 Package 적용 해볼까?
next release
1) log 쓰기
"""

import requests
import json
import pycurl
from io import BytesIO
import certifi
import datetime
from datetime import date
import xlrd
import MySQLdb
import shutil
import os
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import itertools

from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import f1_score
from sklearn.ensemble import RandomForestClassifier

###############   CONST   #############
PCA_DIM = 10
LEARNING_START_DATE = '2017-03-01'
LEARNING_END_DATE = '2017-07-14'
fw_db_times_limit = 10
#######################################

conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")

# config file load
conf = open("./ais.txt")
while True:
    line = conf.readline()
    if not line : break
    config_line = line.strip('\n').split('=')    
    if(config_line[0] == 'logdir') :
        logdir = config_line[1]    
    elif(config_line[0] == 'ibm_key1') :
        ibm_key1 = config_line[1]        
    elif(config_line[0] == 'ibm_key2') :
        ibm_key2 = config_line[1]        
    elif(config_line[0] == 'ibm_key3') :
        ibm_key3 = config_line[1]    
    elif(config_line[0] == 'alarm_log_field'):        
        alarm_log_list = list(config_line[1].split(',')) # 0 부터 시작
    elif(config_line[0] == 'ips_log_field'):        
        ips_log_list = list(config_line[1].split(',')) # 0 부터 시작
    elif(config_line[0] == 'waf_log_field'):        
        waf_log_list = list(config_line[1].split(',')) # 0 부터 시작
    elif(config_line[0] == 'web_log_field'):        
        web_log_list = list(config_line[1].split(',')) # 0 부터 시작
    elif(config_line[0] == 'fw_log_field'):        
        fw_log_list = list(config_line[1].split(',')) # 0 부터 시작
    elif(config_line[0] == 'alarmlog_file'):
        alarmlog_file = list(config_line[1].split(','))
    elif(config_line[0] == 'ipslog_file'):
        ipslog_file = list(config_line[1].split(','))
    elif(config_line[0] == 'waflog_file'):
        waflog_file = list(config_line[1].split(','))
    elif(config_line[0] == 'weblog_file'):
        weblog_file = list(config_line[1].split(','))
    elif(config_line[0] == 'fwlog_file'):
        fwlog_file = list(config_line[1].split(','))
    elif(config_line[0] == 'web_ok_file'):
        web_ok_file = list(config_line[1].split(','))
    elif(config_line[0] == 'web_rej_file'):
        web_rej_file = list(config_line[1].split(','))
    elif(config_line[0] == 'fw_pd_file'):
        fw_pd_file = list(config_line[1].split(','))
    elif(config_line[0] == 'fw_db_file'):
        fw_db_file = list(config_line[1].split(','))
    elif(config_line[0] == 'weekflag'):
        weekflag = list(config_line[1].split(','))
    elif(config_line[0] == 'fw_wkp_file'):
        fw_wkp_file = list(config_line[1].split(','))
    else :
        pass

def get_logday(return_type) :
    logday_list = []
    logday = ''
    today = str(datetime.date.today())
    today = today.split('-')    
    if return_type == 1 : # list        
        for i in range[2]:
            logday_list.append(today[i])        
        return logday_list
    elif return_type == 2: #str
        logday = str(today[0]) + str(today[1])+str(today[2])        
        return logday
      
def gen_cache_no(cache_type, logday, conn) : # Cache No 생성
    curs = conn.cursor()
    if cache_type == 'ip' : # ip or log
        cache_day = logday[2:]
        sql = 'select max(SEQ) from aw_ip_cache where write_date= %s' 

        now = str(datetime.datetime.now())
        day = datetime.date.today()
        time = now[11:]

        curs.execute(sql,(day,)) # 튜플이므로 쉼표하나 필요
        row = curs.fetchone()        
        if row == (None,) : # 당일 첫번째 write
            ip_cache_no = logday[2:]+'-'+'1'            
            return ip_cache_no
        else :
            sql = 'select ip_cache_no from aw_ip_cache where seq = %s'
            curs.execute(sql,(row,)) # 튜플이므로 쉼표하나 필요            
            row = curs.fetchone()
            a = []
            a=list(row)
            a = str(a[0]).split('-')            
            ip_cache_no = logday[2:]+'-'+str(int(a[1])+1)
            return ip_cache_no
        
    elif cache_type == 'web_log' : # web log 일 때
        cache_day = logday[2:]
        sql = 'select max(SEQ) from web_log_cache where write_date= %s'

        now = str(datetime.datetime.now())
        day = datetime.date.today()
        time = now[11:]

        curs.execute(sql,(day,)) # 튜플이므로 쉼표하나 필요
        row = curs.fetchone()        
        if row == (None,) : # 당일 첫번째 write
            web_log_cache_no = logday[2:]+'-'+'1'            
            return web_log_cache_no
        else :
            sql = 'select web_log_cache_no from web_log_cache where seq = %s'
            curs.execute(sql,(row,)) # 튜플이므로 쉼표하나 필요            
            row = curs.fetchone()
            a = []
            a=list(row)
            a = str(a[0]).split('-')            
            web_log_cache_no = logday[2:]+'-'+str(int(a[1])+1)            
            return web_log_cache_no


def check_ip_cache(ip) : # ip cache 검색해서 있으면 count를 올리고 없으면 insert
    # arg_list : logday,   
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]

    curs = conn.cursor()
    sql = 'select IP_CACHE_NO from aw_ip_cache where ip = %s'
    curs.execute(sql,(ip,))
    
    rows = curs.fetchone()
       
    if rows == None : # ip cache에 없을 때 insert
        sql = 'insert into aw_ip_cache (IP_CACHE_NO, IP, TIMES, WRITE_DATE, WRITE_TIME, MODI_TIME) values (%s,%s,%s,%s,%s,%s)'
        logday = get_logday(2)
        ip_cache_no = gen_cache_no('ip', logday, conn) # ip cache no 생성             
        curs.execute(sql,(ip_cache_no, ip, 1, day, time, now))
        conn.commit()
        return ip_cache_no
    else : # ip cache에 있을 때 update
        sql = 'update aw_ip_cache set times = times+1 , modi_time = %s where IP_CACHE_NO = %s'        
        curs.execute(sql,(now,rows[0]))
        conn.commit()
        return rows[0]

def check_web_log_cache(req, url, ref, conn) : # web log cache 검색해서 있으면 count를 올리고 없으면 insert    
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()

    sql = 'select WEB_LOG_CACHE_NO from web_log_cache where req = %s and url =%s'
    curs.execute(sql,(req, url))
    
    rows = curs.fetchone()    
    if rows == None : # web log cache에 없을 때 insert        
        sql = 'insert into web_log_cache (WEB_LOG_CACHE_NO,HIT,REQ, URL, REF, WRITE_DATE, WRITE_TIME, MODI_TIME) values (%s,%s,%s,%s,%s,%s,%s,%s)'
        logday = get_logday(2)
        web_log_cache_no = gen_cache_no('web_log',logday, conn) # web log cache no 생성        
        curs.execute(sql,(web_log_cache_no, 1, req, url, ref, day, time, now))
        conn.commit()
        return web_log_cache_no   
    else : # web log cache에 있을 때 update
        sql = 'update web_log_cache set hit=hit+1 , modi_time = %s where WEB_LOG_CACHE_NO = %s'
        logday = get_logday(2)               
        curs.execute(sql,(now,rows[0]))
        conn.commit()
        return rows[0]

 

def store_alarm_logfull(logdir,logfile,logday,alarm_log_list,conn) :    
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    sql = "insert into aw_log_full(LOG_TYPE, LOG_TIME, TIMES, AGENT, ATTACK_CODE, SOURCE_IP, DEST_IP, COMMENT, ALARM_YN, WRITE_DATE,WRITE_TIME,MODI_TIME) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)" # select 때 필드 순서 결정 -> 배열 sequencial 인덱스와 연결가능
    logset = []
    empty_list = []
    for r in range(1,sheet.nrows):
        for c in range(sheet.ncols):
            logset.append(sheet.cell_value(r,c))
        i=0        
        curs.execute(sql,('alarm',logset[int(alarm_log_list[i])],logset[int(alarm_log_list[i+1])],logset[int(alarm_log_list[i+2])],logset[int(alarm_log_list[i+3])],logset[int(alarm_log_list[i+4])]
                          ,logset[int(alarm_log_list[i+5])],'testing','Y',day,time,now))
        
        logset = []
    conn.commit()
    return 0

def store_ips_logfull(logdir,logfile,logday,ips_log_list,conn) :    
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    sql = "insert into aw_log_full(LOG_TYPE, LOG_TIME, AGENT, SOURCE_IP, DEST_IP, DEST_PORT, RESULT, METHOD, TIMES, ATTACK_CODE, COMMENT,WRITE_DATE,WRITE_TIME,MODI_TIME) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    logset = []
    empty_list = []
    for r in range(1,sheet.nrows):
        for c in range(sheet.ncols):
            logset.append(sheet.cell_value(r,c))
        i=0        
        curs.execute(sql,('ips',logset[int(ips_log_list[i])],logset[int(ips_log_list[i+1])],logset[int(ips_log_list[i+2])],logset[int(ips_log_list[i+3])],logset[int(ips_log_list[i+4])]
                          ,logset[int(ips_log_list[i+5])],logset[int(ips_log_list[i+6])],logset[int(ips_log_list[i+7])],logset[int(ips_log_list[i+8])],'testing',day,time,now))
        
        logset = []
    conn.commit()
    return 0

def update_ip_cache_no():
    curs = conn.cursor()
    day = datetime.date.today()
    now = str(datetime.datetime.now())
    select_sql = 'select distinct source_ip from aw_log_full where write_date =%s and log_type != %s and ip_cache_no is null'
    #update_sql = 'update log_full set ip_cache_no = %s where source_ip = %s and write_date = %s'
    curs.execute(select_sql,(day,'fw'))
    rows = curs.fetchall()    
    for r in rows :        
        #ip_cache_no = check_ip_cache(r[0])
        #curs.execute(update_sql,(ip_cache_no, r[0], day))
        ip_cache_no = check_ip_cache(r[0])        
        update_ipr(r[0])
    conn.commit()
    return

def update_ip_cache_no_fw():
    curs = conn.cursor()
    day = datetime.date.today()
    now = str(datetime.datetime.now())
    select_sql = 'select distinct source_ip from aw_log_full where write_date =%s and log_type = %s and ip_cache_no is null'
    
    curs.execute(select_sql,(day,'fw'))
    rows = curs.fetchall()
    for r in rows :        
        ip_cache_no = check_ip_cache(r[0])        
    conn.commit()
    return
        






def store_waf_logfull(logdir,logfile,logday,waf_log_list,conn) :
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    sql = "insert into aw_log_full(LOG_TYPE, LOG_TIME, AGENT, SOURCE_IP, DEST_IP, DEST_PORT, RESULT, METHOD, ATTACK_CODE, COMMENT,WRITE_DATE,WRITE_TIME,MODI_TIME,TIMES) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    logset = []
    empty_list = []
    result = ''
    for r in range(1,sheet.nrows):
        for c in range(sheet.ncols):
            logset.append(sheet.cell_value(r,c))
        i=0
        
        curs.execute(sql,('waf',logset[int(waf_log_list[i])],logset[int(waf_log_list[i+1])],logset[int(waf_log_list[i+2])],logset[int(waf_log_list[i+3])],logset[int(waf_log_list[i+4])]
                          ,logset[int(waf_log_list[i+5])],logset[int(waf_log_list[i+6])],logset[int(waf_log_list[i+7])],'testing',day,time,now,1))
        
        result = logset[int(waf_log_list[i+5])]
        logset = []
    conn.commit()
    return 0

def store_web_logfull(logdir,logfile,logday,web_log_list,conn) :
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    try :
        file_location = logdir+str(logday)+logfile
    except :
        return -1
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    sql = "insert into aw_log_full(LOG_TYPE, LOG_TIME, AGENT, SOURCE_IP, DEST_IP, METHOD, RESULT, COMMENT,WRITE_DATE,WRITE_TIME,MODI_TIME,IP_CACHE_NO) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    logset = []
    web_logset = []
    empty_list = []
    method_list = []
    method_ = []
    domain_ = []
    result_ = []
    method = ''
    logset_ip = ''
    current_ip =''
    req = ''
    ref = ''
    url = ''
    result = ''
    
    for r in range(1,sheet.nrows): # row 하나 읽어옴
        result_flag = 'web_ok' # default 로 web ok이고 403 이 뜨면 flag는 web_reject로 바뀜
        logset = []
        for c in range(sheet.ncols): # column 하나 읽어옴
            logset.append(sheet.cell_value(r,c)) # logset 이 하나 나옴
        logset_ip = logset[int(web_log_list[2])]            
        method_ = logset[int(web_log_list[5])].split(' ')
        domain_ = logset[int(web_log_list[7])].split('=')
        result_ = logset[int(web_log_list[4])].split(' ')
        req = method_[0]
        url = domain_[1]
        ref = method_[1]
        result = result_[-1]
        #print('result uderbar = {0}, result = {1}'.format(result_,result))
        if current_ip =='' : # 첫번째 줄일때            
            web_log_cache_no = check_web_log_cache(req,url,ref,conn)
            method_list.append(web_log_cache_no+result)
            current_ip = logset_ip
            if result == '(403)' : result_flag = 'web_reject'            
        else :            
            if current_ip == logset_ip : # logset_ip와 다음 logset_ip가 같으면 web_log_cache_no append, 다르면 insert                
                web_log_cache_no = check_web_log_cache(req,url,ref,conn)
                method_list.append(web_log_cache_no+result)
                current_ip = logset_ip
                if result == '(403)' : result_flag = 'web_reject'
            else :                
                i=0
                web_log_cache_no = check_web_log_cache(req,url,ref,conn)
                method_list.append(web_log_cache_no+result)
                method = '->'.join(method_list)
                ip_cache_no = check_ip_cache(logset[int(web_log_list[i+2])], conn, empty_list)
                if result == '(403)' : result_flag = 'web_reject'
                curs.execute(sql,('web',logset[int(web_log_list[i])],logset[int(web_log_list[i+1])],current_ip,logset[int(web_log_list[i+3])],method, result, 'testing',day,time,now,ip_cache_no))                
                current_ip = logset_ip                
                method_list = []                
                continue
    conn.commit()          
    return 0

def store_fw_logfull(logdir,logfile,logday,fw_log_list,conn) :
    now = str(datetime.datetime.now())
    #day = datetime.date.today()
    #time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    #sql = "insert into log_full(LOG_TYPE, LOG_TIME, AGENT, SOURCE_IP, DEST_IP, DEST_PORT, RESULT, COMMENT,WRITE_DATE,WRITE_TIME,MODI_TIME,IP_CACHE_NO) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    logset = []
    empty_list = []    
    for r in range(1,sheet.nrows):
        for c in range(sheet.ncols):
            logset.append(sheet.cell_value(r,c))
        bl = check_black_list(logset[int(fw_log_list[2])],conn)
        if bl == -1 :
            i=0
            r = r+1
            ip_cache_no = check_ip_cache(logset[int(fw_log_list[2])], conn, empty_list)
    #        curs.execute(sql,('fw',logset[int(fw_log_list[i])],logset[int(fw_log_list[i+1])],logset[int(fw_log_list[i+2])],logset[int(fw_log_list[i+3])],logset[int(fw_log_list[i+4])],logset[int(fw_log_list[i+5])],'testing',day,time,now,ip_cache_no))                        
            logset = []
        else :
            sql = 'update aw_ip_cache set times=times+1, fw_db = fw_db+1, modi_time = %s where ip = %s'
            curs.execute(sql,(now,logset[int(fw_log_list[2])]))
            logset = []
    conn.commit()
            
    #conn.commit()
    return r # 분석한 갯수만 Return

def store_fw_wkp_logfull(logdir,logfile,logday,fw_wkp_file,conn) : #well known port (20,21,22,23,1433,1521,3306,3389,5900)
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    workbook = xlrd.open_workbook(file_location)
    sheet = workbook.sheet_by_index(0)
    sql = "insert into aw_log_full(LOG_TYPE, LOG_TIME, SOURCE_IP, DEST_IP, DEST_PORT, RESULT, COMMENT,WRITE_DATE,WRITE_TIME,MODI_TIME) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    logset = []
    empty_list = []    
    for r in range(1,sheet.nrows):
        for c in range(sheet.ncols):
            logset.append(sheet.cell_value(r,c))      
        
        
        curs.execute(sql,('fw_wk',logset[1],logset[4],logset[7],logset[8],logset[12],'testing',day,time,now))                        
        logset = []        
    conn.commit()
            
    #conn.commit()
    return r # 분석한 갯수만 Return

def store_fw_log_light(logdir,logfile,logday,result,conn) :
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    df = pd.read_excel(file_location)
    ip_li = [] 
    ip = [] # [0]ip, [1]횟수
    ip_li = df['Unnamed: 1']
    sql = "insert into aw_log_full(LOG_TYPE, TIMES, SOURCE_IP, RESULT, WRITE_DATE, WRITE_TIME, MODI_TIME) values(%s,%s,%s,%s,%s,%s,%s)"        
    for stri in ip_li:
        ip = stri.replace("Source IP: ","").replace("(Count=","").replace(")","")
        ip = ip.split(" ")
        if result == 'Drop (102)' and int(ip[1]) < fw_db_times_limit :            
            continue
        else :
            curs.execute(sql,('fw', ip[1], ip[0], result, day , time, now))
            
    conn.commit()
    return 0

def store_web_log_light(logdir,logfile,logday,result,conn) :
    now = str(datetime.datetime.now())
    day = datetime.date.today()
    time = now[11:]
    curs = conn.cursor()
    file_location = logdir+str(logday)+logfile
    df = pd.read_excel(file_location)
    ip_li = [] 
    ip = [] # [2]ip, [3]횟수
    ip_li = df['Unnamed: 1']
    sql = "insert into aw_log_full(LOG_TYPE, TIMES, SOURCE_IP, RESULT, WRITE_DATE, WRITE_TIME, MODI_TIME) values(%s,%s,%s,%s,%s,%s,%s)"    
    for stri in ip_li:
        ip = stri.replace("Source IP: ","").replace("(Count=","").replace(")","")
        ip = ip.split(" ")                           
        curs.execute(sql,('web', ip[1], ip[0], result, day , time, now))        
    conn.commit()
    return 0

def ipr_basic(ip) :   
    now = str(datetime.datetime.now())
    ipr_li = []
    ipr = ''
    ip3 = ip.split('.')
    tot = 0
    if ip3[0] == '10' or (ip3[0] == '118' and ip3[1] == '219') or (ip3[0] == '192' and ip3[1] == '168'):
        ipr_li = ['INT',0]
        return ipr_li
    try :    
        res = requests.get('http://geoip.nekudo.com/api/'+ip)
        rej = res.json()
    except :
        ipr_li = ['ERR',0]
        return ipr_li
    try:
        if rej['country'] == [] : return ['ERR', 0]
        elif rej['country']['code'] == 'KR' :
            ipr_li = ['KR',0]
            return ipr_li
        else :
            buffer=BytesIO()
            c = pycurl.Curl()
            c.setopt(pycurl.CAINFO, certifi.where()) # ssl 인증 건너뛰기
            c.setopt(c.URL, 'https://api.xforce.ibmcloud.com/ipr/history/'+ip)
            c.setopt(pycurl.HTTPHEADER,['Accept: application/json',ibm_key1])
        
            c.setopt(c.WRITEDATA, buffer)
            c.perform()
            c.close
            
            body = buffer.getvalue()
            blj = json.loads(body.decode('iso-8859-1'))            
            for i in blj['history'] :                 
                if len(blj['history']) <= 1 :
                    tot = 0.0
                else :                
                    tot = round(tot+blj['history'][1]['score'],1)
            ipr_li = [rej['country']['code'], tot]            
            return ipr_li
    except :
        print('ipr_basic error',rej)        
        ipr_li =['ERR', 0]
        return ipr_li

def update_ipr(ip) :
    now = str(datetime.datetime.now())
    day = datetime.date.today()    
    curs = conn.cursor()
    ipr = []    
    if(ip == ['']) :            
        pass
    ipr = ipr_basic(ip)
   
    if(ipr[0] == 'INT') : # 내부 공인/사설 IP            
        sql = 'update aw_ip_cache set cc=%s, ip_gubun=3, bl_ibm=0, modi_time = %s where write_date = %s and ip = %s'
        curs.execute(sql,(ipr[0],now,day,ip))
        conn.commit()
            
    elif(ipr[0] == 'KR' ) : # 국산 IP일 때
        sql = 'update aw_ip_cache set cc=%s, ip_gubun=2, bl_ibm=0, modi_time = %s where write_date = %s and ip = %s'           
        curs.execute(sql,(ipr[0],now,day,ip))
        conn.commit()
            

    elif(ipr[0] == 'ERR') :
        sql = 'update aw_ip_cache set cc=%s, ip_gubun=-1, bl_ibm=0, modi_time = %s where write_date = %s and ip = %s'           
        curs.execute(sql,(ipr[0],now,day,ip))
        conn.commit()
          
    elif(ipr[0] != 'INT' and ipr[0] != 'KR' and ipr[0] != 'ERR') : #IPR_IBM 이 분석했을 경우 -> 해외 IP            
        sql = 'update aw_ip_cache set cc=%s, ip_gubun=1, bl_ibm = %s, modi_time = %s where write_date = %s and ip = %s'
        print(ip, "==>", ipr[1], ipr[0])
        write_log('{0} ==> {1},{2}'.format(ip, ipr[1] , ipr[0]))
        curs.execute(sql,(ipr[0],ipr[1],now,day,ip))
        conn.commit()

def basic_analysis():  # update result 할 항목을 뽑는다. ibm ipr은 update result에서 한다.
    day = datetime.date.today()   
    curs = conn.cursor()    
    res = 0    
    rows_li = list()
    sql = 'select source_ip, result, log_type, times from aw_log_full where write_date = %s'       
    curs.execute(sql,(day,))
    rows = curs.fetchall()     
    
    for i in rows :
        if i[2] == 'web' :
            if i[1] == 'web_ok' : res = 1
            else : res = 2
            easy_update_result(res,i[0],i[3],conn)
        if i[2] == 'fw' :
            if i[1] == 'Drop (102)' : res = 4
            else : res = 3
            easy_update_result(res,i[0],i[3],conn)
        if i[2] == 'waf' :
            if i[1] == 'OK (200)' : res = 5
            else : res = 6
            update_result(res,i[0],conn)
        if i[2] == 'ips' :
            if i[1] == 'Pass/Detect (101)' : res = 7
            else : res = 8            
            update_result(res,i[0],conn)

def basic_analysis2():
    day = datetime.date.today()   
    curs = conn.cursor()    
    res = 0    
    rows_li = list()
    ok_ip_select_sql = 'select distinct source_ip from aw_log_full where write_date = %s and log_type = %s and result = %s'
    rej_ip_select_sql = 'select distinct source_ip from aw_log_full where write_date = %s and log_type = %s and result != %s'
    ok_sum_times_sql = 'select sum(times) from aw_log_full where write_date = %s and log_type = %s and result = %s and source_ip = %s'
    rej_sum_times_sql = 'select sum(times) from aw_log_full where write_date = %s and log_type = %s and result != %s and source_ip = %s'
    just_ok_ip = 'select source_ip, times from aw_log_full where write_date = %s and log_type = %s and result = %s'
    just_rej_ip = 'select source_ip, times from aw_log_full where write_date = %s and log_type = %s and result != %s'
   
    # waf_ok
    write_log("working waf_ok")
    curs.execute(ok_ip_select_sql,(day,'waf','OK (200)'))
    rows = curs.fetchall()
    for ip in rows :
        curs.execute(ok_sum_times_sql,(day,'waf','OK (200)',ip[0]))
        row = curs.fetchone()
        update_result(5,ip[0],row[0])

    # waf_rej
    write_log("working waf_rej")
    curs.execute(rej_ip_select_sql,(day,'waf','OK (200)'))
    rows = curs.fetchall()
    for ip in rows :
        curs.execute(rej_sum_times_sql,(day,'waf','OK (200)',ip[0]))
        row = curs.fetchone()
        update_result(6,ip[0],row[0])

    # ips_pd
    write_log("working ips_pd")
    curs.execute(ok_ip_select_sql,(day,'ips','Pass/Detect (101)'))
    rows = curs.fetchall()
    for ip in rows :
        curs.execute(ok_sum_times_sql,(day,'ips','Pass/Detect (101)',ip[0]))
        row = curs.fetchone()
        update_result(7,ip[0],row[0])

    # ips_db
    write_log("working ips_db")
    curs.execute(rej_ip_select_sql,(day,'ips','Pass/Detect (101)'))
    rows = curs.fetchall()
    for ip in rows :
        curs.execute(rej_sum_times_sql,(day,'ips','Pass/Detect (101)',ip[0]))
        row = curs.fetchone()
        update_result(8,ip[0],row[0])
        
    # web_ok    
    write_log("working web_ok")  
    curs.execute(just_ok_ip,(day,'web','web_ok'))
    rows = curs.fetchall()
    for ip in rows :        
        easy_update_result(1,ip[0],ip[1])

    # web_rej
    write_log("working web_rej")
    curs.execute(just_rej_ip,(day,'web','web_ok'))
    rows = curs.fetchall()
    for ip in rows :        
        easy_update_result(2,ip[0],ip[1])

    #fw_accept
    write_log("working fw_accept")
    curs.execute(just_ok_ip,(day,'fw','Accept'))
    rows = curs.fetchall()
    for ip in rows :       
        easy_update_result(3,ip[0],ip[1])

    # fw_drop
    write_log("working fw_drop")
    curs.execute(just_rej_ip,(day,'fw','Accept'))
    rows = curs.fetchall()
    for ip in rows :        
        easy_update_result(4,ip[0],ip[1])

    return  

    
  
def update_result(res, ip,times) : # 1 : web ok, 2 : web reject, 3: fw pd, 4: fw db, 5: waf ok, 6: waf reject, 7: ips pd, 8: ips db
    #print(res,ip,times)
    curs = conn.cursor()
    day = datetime.date.today()    
    if res == 5 :
        update = 'update aw_ip_cache set waf_ok = waf_ok+%s where ip = %s'
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 6 :        
        update = 'update aw_ip_cache set waf_rej = waf_rej+%s where ip = %s'
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 7 :        
        update = 'update aw_ip_cache set ips_pd = ips_pd+%s where ip = %s'       
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 8 :        
        update = 'update aw_ip_cache set ips_db = ips_db+%s where ip = %s'       
        curs.execute(update,(times,ip))
        conn.commit()

def easy_update_result(res, ip, times) : # 1 : web ok, 2 : web reject, 3: fw pd, 4: fw db
    #print(res, ip, times)
    curs = conn.cursor()
    if res == 1 :                
        update = 'update aw_ip_cache set web_ok = web_ok+%s where ip = %s'        
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 2 :
        update = 'update aw_ip_cache set web_rej = web_rej+%s where ip = %s'
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 3 :        
        update = 'update aw_ip_cache set fw_pd = fw_pd+%s where ip = %s'
        curs.execute(update,(times,ip))
        conn.commit()
    elif res == 4 :        
        update = 'update aw_ip_cache set fw_db = fw_db+%s where ip = %s'
        curs.execute(update,(times,ip))
        conn.commit()


def get_log_term(write_date) :
    sql = "select distinct substring_index(log_time,' ',1) from aw_log_full where write_date = %s"
    curs = conn.cursor()
    curs.execute(sql,(write_date,))
    row = curs.fetchone()
    return row

def daily_ip_count(log_type, log_date, result_type) :
    ip_dist = tuple()
    return_li = []
    total_event = 0
    total_pd = 0
    total_db = 0
    ip_gubun_li = []
    ip_gubun = 0
    ip_gubun_ab = 0
    ip_gubun_kr = 0
    ip_gubun_int = 0
    ip_gubun_err = 0
    result = ''
    if log_type == 'ips' :
        result = 'Pass/Detect (101)'
    elif log_type == 'fw' :
        result = 'Accept'
    elif log_type == 'waf' :
        result = 'OK (200)'
    elif log_type == 'web' :
        result = 'web_ok'

    curs = conn.cursor()    

    total_event_sql = 'select count(*) from aw_log_full where log_time like %s and log_type = %s'
    curs.execute(total_event_sql,(log_date+'%',log_type,))
    total_event = curs.fetchone()
    total_pd_sql = 'select count(*) from aw_log_full where log_time like %s and log_type = %s and result = %s'
    curs.execute(total_pd_sql,(log_date+'%',log_type,result))
    total_pd = curs.fetchone()
    total_db_sql = 'select count(*) from aw_log_full where log_time like %s and log_type = %s and result != %s'
    curs.execute(total_db_sql,(log_date+'%',log_type,result))
    total_db = curs.fetchone()                 
     
    if result_type == 1 :
        ip_dist_sql = 'select distinct source_ip from aw_log_full where log_time like %s and log_type = %s and result = %s'            
    elif result_type == 2 :
        ip_dist_sql = 'select distinct source_ip from aw_log_full where log_time like %s and log_type = %s and result != %s'    
    curs.execute(ip_dist_sql,(log_date+'%',log_type,result))
    ip_dist = curs.fetchall()
    ip_dist_tot = len(ip_dist)
    cc = 'select CC from aw_ip_cache where ip = %s'
    for ip in ip_dist :        
        curs.execute(cc,(ip[0],)) # 튜플에 접근
        ip_gubun_li = curs.fetchone()
        ip_gubun = ip_gubun_li[0]
        if ip_gubun == 'INT' : 
            ip_gubun_int += 1            
        elif ip_gubun == 'KR' : 
            ip_gubun_kr += 1            
        elif ip_gubun == 'ERR' or ip_gubun == '':            
            ip_gubun_err += 1            
        else :
            ip_gubun_ab += 1
    write_log('INT =>{0} , KR =>{1}, ERR =>{2}, AB =>{3}'.format(ip_gubun_int, ip_gubun_kr, ip_gubun_err, ip_gubun_ab))
    return_li.append(total_event) #[0]
    return_li.append(total_pd) #[1]
    return_li.append(total_db) #[2]
    return_li.append(ip_dist_tot) #[3]
    return_li.append(ip_gubun_int) #[4]
    return_li.append(ip_gubun_kr) #[5]
    return_li.append(ip_gubun_ab) #[6]
    return_li.append(ip_gubun_err) #[7]   
    return return_li


def simple_daily_report(write_date, log_type) :
    weekday = 0
    return_li = []
    term = []
    return_li_a = [] # a
    return_li_b = [] # b
    curs = conn.cursor()
    term = get_log_term(write_date)
    date_li = []
    for log_date in term :
        date_tmp = log_date
        date_li = date_tmp.split('-')
        weekday = datetime.date(int(date_li[0]), int(date_li[1]), int(date_li[2])).weekday()
        write_log('{0}'.format(date_li))
        return_li_a = daily_ip_count(log_type, log_date, 1)
        return_li_b = daily_ip_count(log_type, log_date, 2)
        insert_daily_report_sql = 'insert into daily_report (log_date,log_type,event_num,pd_num,db_num,event_int,event_kr,event_ab,event_err,pd_int,pd_kr,pd_ab,pd_err,db_int,db_kr,db_ab,db_err,weekday) values (%s,%s,%s,%s, %s, %s, %s, %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        curs.execute(insert_daily_report_sql,(log_date,log_type,return_li_a[0], return_li_a[1], return_li_a[2], (return_li_a[4]+return_li_b[4]), (return_li_a[5]+return_li_b[5])
                                    ,(return_li_a[6]+return_li_b[6]),(return_li_a[7]+return_li_b[7]),return_li_a[4],return_li_a[5],return_li_a[6],return_li_a[7],return_li_b[4],return_li_b[5],return_li_b[6],return_li_b[7],weekday))
    conn.commit()
    return
        

def update_fw_ipr():
    curs = conn.cursor()
    day = datetime.date.today()  
    sql = 'select source_ip from aw_log_full where write_date = %s and log_type = %s and result = %s order by times desc limit 20'
    curs.execute(sql,(day,'fw','Drop (102)'))
    rows = curs.fetchall()
    for r in rows :
        update_ipr(r[0])
    return
        
def write_log(msg) :    
    #log_file = logdir+str(logday)+logfile
    now = datetime.datetime.now()
    day = datetime.date.today()
    f = open('./'+str(day)+'_log.txt','a')
    log_message = '['+ str(now) + ']  ' + msg + '\n'
    f.write(log_message)
    f.close()

def update_bl():
    selectSql = 'select ip, flag from aw_bl where modi_time is null and ip is not null'
    updateSql = 'update aw_ip_cache set bl_dg_yn = %s where ip = %s'
    updateModi = 'update aw_bl set modi_time = %s where ip = %s'
    curs = conn.cursor()
    now = datetime.datetime.now()
    curs.execute(selectSql)
    bl = curs.fetchall()
    for bl_tu in bl:
        print(bl_tu[0])
        if(bl_tu[0].rfind('/') != -1):
            print("CLID 발견")
            clid = bl_tu[0].split('.0/')   
            updateSql = "update aw_ip_cache set bl_dg_yn = %s where ip like %s"            
            ip = clid[0]+'%'
            print(ip)
            curs.execute(updateSql,(bl_tu[1],ip))        
        else :
            curs.execute(updateSql,(bl_tu[1],bl_tu[0]))        
        curs.execute(updateModi,(now,bl_tu[0]))
        conn.commit()
    return bl

def ipr_basic_susp(ip) :   # KR 일 때 건너뛰는 부분 제거 : 사설망 빼고 IP 넣으면 무조건 IBM 검사
    curs = conn.cursor()
    now = str(datetime.datetime.now())
    ipr_li = []
    ipr = ''
    ip3 = ip.split('.')
    tot = 0
    s_bl_ibm = 'select bl_ibm from aw_ip_cache where ip = %s'    
    curs.execute(s_bl_ibm,(ip,))
    rows = curs.fetchone()
    print("inspecting bl_ibm : ",rows)
    if ip3[0] == '10' or (ip3[0] == '118' and ip3[1] == '219') or (ip3[0] == '192' and ip3[1] == '168') or (ip3[0] == '172' and ip3[1] == '16') or (ip3[0] == '172' and ip3[1] == '17') or (ip3[0] == '172' and ip3[1] == '30'):
        ipr_li = ['INT',0]
        return 
    if rows == None or rows[0]==0 : 
        try :    
            res = requests.get('http://geoip.nekudo.com/api/'+ip)
            rej = res.json()
        except :
            ipr_li = ['ERR',0]
            #return ipr_li
            u_bl_ibm = 'update aw_ip_cache set cc=%s, bl_ibm=%s where ip = %s'
            curs.execute(u_bl_ibm,(ipr_li[0],ipr_li[1],ip))
            conn.commit()
            return
        try:
            if rej['country'] == [] :
                ipr_li = ['ERR', 0]
                u_bl_ibm = 'update aw_ip_cache set cc=%s, bl_ibm=%s where ip = %s'
                curs.execute(u_bl_ibm,(ipr_li[0],ipr_li[1],ip))
                conn.commit()
                return
            else :
                buffer=BytesIO()
                c = pycurl.Curl()
                c.setopt(pycurl.CAINFO, certifi.where()) # ssl 인증 건너뛰기
                c.setopt(c.URL, 'https://api.xforce.ibmcloud.com/ipr/history/'+ip)
                c.setopt(pycurl.HTTPHEADER,['Accept: application/json',ibm_key2])
        
                c.setopt(c.WRITEDATA, buffer)
                c.perform()
                c.close
            
                body = buffer.getvalue()
                blj = json.loads(body.decode('iso-8859-1'))            
                for i in blj['history'] :                 
                    if len(blj['history']) <= 1 :
                        tot = 0.0
                    else :                
                        tot = round(tot+blj['history'][1]['score'],1)
                ipr_li = [rej['country']['code'], tot]            
                #return ipr_li
                u_bl_ibm = 'update aw_ip_cache set cc=%s, bl_ibm=%s where ip = %s'
                curs.execute(u_bl_ibm,(ipr_li[0],ipr_li[1],ip))
                print(ip + "bl ibm 이 추가로 등록되었습니다")
                conn.commit()
                return        
        except :
            print('ipr_basic error',rej)        
            ipr_li =['ERR', 0]
            #return ipr_li
            u_bl_ibm = 'update aw_ip_cache set cc=%s, bl_ibm=%s where ip = %s'
            curs.execute(u_bl_ibm,(ipr_li[0],ipr_li[1],ip))
            conn.commit()
            return        
    else : return

def inspection(): # 관제규칙에 따라 자동으로 blacklist 등록
    day = datetime.date.today()
    #day = '2017-04-06'
    curs = conn.cursor()
    # const bl_code
    bl_ibm_score = 20 # display & bl 등록할 최소 Score
    # fwscan = 2, waf = 10 ~ 50, ips = 50 ~ 100
    black_list = 1    
    th_ip_code = 1
    fwscan_code = 2
    ipd_code = 11
    wp_code = 12
    method_code = 13
    php_code = 14
    xmlrpc_code = 51
    struts_code = 52
    ecsc_code = 53
    ncsc_code = 54
    webshell_code = 55
    wannacry_code = 56    
    bl_class_code = 80

    # ip 모아서 bl에 bl코드, flag = 1 insert
    # fwscan top 20
    # select source_ip, count(*) as a from aw_log_full where source_ip = any(select source_ip from aw_log_full where write_date = '2017-07-07' and log_type='fw' and result='Drop (102)' order by times desc) group by source_ip order by a desc limit 20
    select = 'select source_ip, count(*) as a from aw_log_full where source_ip =  any(select source_ip from aw_log_full where write_date=%s and log_type=%s and result = %s order by times desc) group by source_ip order by a desc limit 30'    
    curs.execute(select,(day,'fw','Drop (102)'))
    fwscan = curs.fetchall()
    for ip in fwscan :
        ipr_basic_susp(ip[0])        
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'    
        curs.execute(update,(ip[0],black_list,fwscan_code,day))
    conn.commit()
    print('fwscan inspect completed')
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    select = 'select ip from aw_ip_cache where modi_time like %s and (ip_gubun=1 or (ip_gubun=2 and (ips_db !=0 or waf_rej !=0))) and fw_pd = 0 and web_ok =0 and waf_ok =0 and fw_pd=0 and ip!=%s'
    curs.execute(select,(str(day)+'%',''))
    th_ip = curs.fetchall()
    for ip in th_ip :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,th_ip_code,day))
    conn.commit()
    # keyword01 - ip로 direct 접속
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s'
    curs.execute(select,('waf',day,'118.219.8.%'))
    ipd = curs.fetchall()
    for ip in ipd :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,ipd_code,day))
    conn.commit()
    # keyword02 - 워드프레스 취약점 공격
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and  result=%s and method like %s and method not like %s'
    curs.execute(select,('waf',day,'Forbidden (403)', '%wp%', '%hwp%'))
    wp = curs.fetchall()
    for ip in wp :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,wp_code,day))
    conn.commit()
    # keyword03 - method 오용
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and attack_code = %s or attack_code = %s or attack_code = %s and method not like %s and method not like %s'
    curs.execute(select,('waf',day,'HEAD', 'POST', 'PROFIND','%SGAPDFReader%', '%hakwon%'))
    method = curs.fetchall()
    for ip in method :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,method_code,day))
    conn.commit()
    # keyword04 - PHP 취약점 공격
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s'
    curs.execute(select,('waf',day,'%php%'))
    php = curs.fetchall()
    for ip in php :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,php_code,day))
    conn.commit()
    # keyword05 - XML 원격코드 실행
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s '
    curs.execute(select,('ips',day,'%xmlrpc%'))
    xmlrpc = curs.fetchall()
    for ip in xmlrpc :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,xmlrpc_code,day))
    conn.commit()
    # keyword06 - apache struts 취약점 공격
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s'
    curs.execute(select,('ips',day,'%Struts%'))
    struts = curs.fetchall()
    for ip in struts :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,struts_code,day))
    conn.commit()
    # keyword07 - ECSC(내부제외)
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s and source_ip not like %s and source_ip not like %s'
    curs.execute(select,('ips',day,'%ECSC%','118.219%','10.%'))
    ecsc = curs.fetchall()
    for ip in ecsc :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,ecsc_code,day))
    conn.commit()
    # keyword08 - NCSC(내부제외)
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s and source_ip not like %s and source_ip not like %s'
    curs.execute(select,('ips',day,'%@%','118.219%','10.%'))
    ncsc = curs.fetchall()
    for ip in ncsc :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,ncsc_code,day))
    conn.commit()
    # keyword09 - Webshell 업로드
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s and source_ip not like %s and source_ip not like %s and source_ip not like %s and method not like %s'
    check_cc = 'select cc from aw_ip_cache where ip = %s'
    curs.execute(select,('ips',day,'%Shell%','118.219%','10.%','182.162.156.%','%Src=KR%'))
    webshell = curs.fetchall()
    for ip in webshell :
        curs.execute(check_cc,(ip[0],))
        cc = curs.fetchall()
        if cc[0] != 'KR' :
            ipr_basic_susp(ip[0])
            update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
            curs.execute(update,(ip[0],black_list,webshell_code,day))        
    conn.commit()
    # keyword10 - Wannacry
    select = 'select distinct source_ip from aw_log_full where log_type=%s and write_date = %s and method like %s'
    curs.execute(select,('ips',day,'%Wannacry%'))
    wannacry = curs.fetchall()
    for ip in wannacry :
        ipr_basic_susp(ip[0])
        update = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
        curs.execute(update,(ip[0],black_list,wannacry_code,day))        
    conn.commit()

    # IBM BL Score Top
    c_ = []
    c_class=[]
    select = 'select ip from aw_ip_cache where modi_time like %s and bl_ibm > 150 and ip_gubun=1 and ip != %s'
    check_bl_class = 'select ip from aw_bl where ip = %s'
    curs.execute(select,(str(day)+'%',''))
    bl_class = curs.fetchall()
    for ip in bl_class :        
        c_=ip[0].split('.')
        c_class = c_[0] +'.'+ c_[1] +'.'+ c_[2] + '.0/24'
        curs.execute(check_bl_class,(ip[0],))
        check_bl = curs.fetchall()
        if check_bl == None :
            insert = 'insert into aw_bl (ip,flag,bl_code,write_date) values (%s,%s,%s,%s)'
            curs.execute(insert,(str(c_class),black_list,bl_class_code,day))        
        conn.commit()
    
    return



# PCA
from sklearn.decomposition import PCA
def do_pca(dataset,n):
    pca = PCA(n_components=n)
    pca.fit(dataset)
    print(pca.explained_variance_ratio_)
    x_train_transformed = pca.fit_transform(dataset)
    #print(x_train_transformed)
    return x_train_transformed


def plot_confusion_matrix(cm, classes,normalize=True,title='Confusion Matrix',cmap=plt.cm.Blues):
    plt.imshow(cm, interpolation='nearest',cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)
    
    if normalize :
        cm = cm.astype('float') / cm.sum(axis = 1)[:,np.newaxis]
    else:
        print("confusion Matrix, without normalization")
    
    print(cm)
    
    thresh = cm.max()/2.
    for i, j in itertools.product(range(cm.shape[0]),range(cm.shape[1])):
        plt.text(j,i,cm[i,j],
                horizontalalignment="center",
                color="white" if cm[i,j] > thresh else "black")
    
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('predicted label')
    plt.show()
    
def do_confusion(test,pred):

    cnf_matrix = confusion_matrix(test,pred)
    print(cnf_matrix.shape)
    # bl을 bl로 맞춘 정확도
    #accuracy = cnf_matrix[1][1]/(cnf_matrix[1][0]+cnf_matrix[1][1])
    
    plot_confusion_matrix(cnf_matrix, classes=['wl','bl'])
    
    return accuracy_score(test, pred)
    #return accuracy

def do_f1(test, pred):
    return f1_score(test, pred)

from sklearn import tree

def do_decision(x_train, y_train, test):
    clf = tree.DecisionTreeClassifier()
    clf.fit(x_train, y_train)
    y_pred = clf.predict(test)
    
    return y_pred

from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV
#from sklearn.grid_search import GridSearchCV
from sklearn.metrics import classification_report
from sklearn.neural_network import MLPClassifier

def do_nn(x,y,test,layers,a):
    clf = MLPClassifier(solver='lbfgs',alpha=a,hidden_layer_sizes=(PCA_DIM,layers),random_state=1)
    clf.fit(x,y)
    y_pred = clf.predict(test)
    return y_pred

def do_svm(x,y,test,c,g):
    print('x ==> ',x)
    print('y ==> ',y)
    print('test ==> ',test)
    clf = SVC(C=c, kernel='rbf',gamma=g) 
    print("fit => ", clf.fit(x,y))
    y_pred = clf.predict(test)
    print("y_pred = ", y_pred)
    return y_pred

def tune_svm(x,y,test):
    print('x => ', x)
    print('y => ',len(y==0), y)
    print('test => ', test)
    tuned_parameters = [{'kernel':['rbf'], 
                         'gamma':[1e-2,1e-3,1e-4,1e-5,1e-6,1e-7,1e-8,1e-9], 
                         'C' : [10,100,1000,10000,100000,1000000,10000000]}]
    
    scores = ['precision','recall']
    
    for score in scores:
        print("# Tunning hyper-parameters for %s" % score)
        print()
        clf = GridSearchCV(SVC(C=1), tuned_parameters, cv=5, scoring='%s_macro' % score)
        clf.fit(x,y)
        
        print("Best parameters set found on development set:")
        print()
        print(clf.best_params_)
        print("Grid scores on development set:")
        print()
        
        means = clf.cv_results_['mean_test_score']
        stds = clf.cv_results_['std_test_score']
        
        for mean, std, params in zip(means, stds, clf.cv_results_['params']):
            print("%0.3f (+/-%0.03f) for %r" % (mean, std *2, params))

        print()

        print("Detailed classification report:")
        print()
        print("The model is trained on the full deveopment set.")
        print("The scores are computed on the full evaluation set.")
        print()
        y_true, y_pred = y_test, clf.predict(test)
        print(classification_report(y_true, y_pred))
        print()
def do_rf(x, y, test):
    clf = RandomForestClassifier(n_estimators=20)
    clf.fit(x, y)    
    y_pred = clf.predict(test)   
    return y_pred


def data_preprocessing(start_date, end_date):
    # db에서 학습 할 데이터 불러와서 전처리
    curs = conn.cursor()
    # bl
    train_ydata_s = 'select ip, bl_ibm, times, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db, bl_dg_yn from aw_ip_cache where write_date >= %s and write_date < %s and (ip_gubun = 1 or ip_gubun = 2) and bl_ibm is not null'
    curs.execute(train_ydata_s,(start_date,end_date))
    train_yrows = curs.fetchall()    
    train_ydf = pd.DataFrame(list(train_yrows), columns=['ip', 'bl_ibm', 'times', 'web_ok', 'web_rej', 'fw_pd', 'fw_db', 'waf_ok', 'waf_rej', 'ips_pd', 'ips_db',' bl_dg_yn'])       
    train_ydf['bl_dg_yn'] = 0

    # wl : bl에 비해 wl이 지나치게 많아서 수를 줄이기 위해 수집기간을 구분해서 저장
    curs = conn.cursor()
    train_xdata_s = 'select ip, bl_ibm, times, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db, bl_dg_yn from aw_ip_cache where modi_time >= %s and modi_time < %s and (ip_gubun = 1 or ip_gubun = 2) and bl_ibm is not null and bl_dg_yn = 0 limit 5000'
    curs.execute(train_xdata_s,('2017-05-01',date.today()))
    train_xrows = curs.fetchall()    
    train_xdf = pd.DataFrame(list(train_xrows), columns=['ip', 'bl_ibm', 'times', 'web_ok', 'web_rej', 'fw_pd', 'fw_db', 'waf_ok', 'waf_rej', 'ips_pd', 'ips_db',' bl_dg_yn'])       
    train_xdf['bl_dg_yn'] = 0


    # 예측할 오늘 데이터
    test_data_s = 'select ip, bl_ibm, times, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db, bl_dg_yn from aw_ip_cache where modi_time like %s and (ip_gubun = 1 or ip_gubun = 2) and bl_ibm is not null'
    curs.execute(test_data_s,(str(date.today())+'%',))
    test_rows = curs.fetchall()    
    test_df = pd.DataFrame(list(test_rows), columns=['ip', 'bl_ibm', 'times', 'web_ok', 'web_rej', 'fw_pd', 'fw_db', 'waf_ok', 'waf_rej', 'ips_pd', 'ips_db',' bl_dg_yn'])
    test_df['bl_dg_yn'] = 0


    
    bl = pd.read_csv('bl.csv',names=['ip'])    
    # bl.csv 에 기록된 black list를 읽어 실제 차단한 ip를 기록
    for bl_ip in bl['ip'] :
        train_ydf.ix[train_ydf['ip']==bl_ip,'bl_dg_yn'] = 1        

    print(train_ydf.head())

    print("total bl count : ",len(train_ydf.loc[train_ydf['bl_dg_yn']==1]))  
    train_y=train_ydf.ix[train_ydf['bl_dg_yn']==1]
    train_df = np.concatenate([train_y,train_xdf])
    
    #print(train_df[:,-1])
    
    #train_y_label = train_df[:,-1]
    #test_y_label = test_df['bl_dg_yn']
    test_ip = test_df['ip']

    y_train = train_df[:,-1].astype(int) 
    y_test = test_df['bl_dg_yn'].astype(int)

    x_train = train_df[:,1:-2].astype(int)
    x_test = np.asarray(test_df)
    x_test = x_test[:,1:-2].astype(int)
        
    
    #tune_svm(x_train, y_train, x_test)

    y_pred = do_svm(x_train, y_train, x_test, 100000, 0.0001)
    
    test_y_label = y_pred
    report = np.column_stack((test_ip,test_y_label))

    bl_idx = np.where(report[:,1] == 1.0)    
    svm_res = report[bl_idx]
    svm_res = svm_res[:,0]
    print("svm res => ", svm_res)
    
    y_pred = do_decision(x_train, y_train, x_test)
    
    test_y_label = y_pred
    report = np.column_stack((test_ip,test_y_label))

    bl_idx = np.where(report[:,1] == 1.0)
    dt_res = report[bl_idx]
    dt_res = dt_res[:,0]
    print("dt res => ", dt_res)

    y_pred = do_rf(x_train, y_train, x_test)    
    test_y_label = y_pred
    report = np.column_stack((test_ip,test_y_label))

    bl_idx = np.where(report[:,1] == 1.0)
    rf_res = report[bl_idx]
    rf_res = rf_res[:,0]
    print("rf res => ", rf_res)

    y_pred = do_nn(x_train, y_train, x_test, 5, 1e-5)
    
    test_y_label = y_pred
    report = np.column_stack((test_ip,test_y_label))

    bl_idx = np.where(report[:,1] == 1.0)
    nn_res = report[bl_idx]
    nn_res = nn_res[:,0]
    print('nn_res =>', nn_res)

    ins1 = np.intersect1d(svm_res, rf_res)
    ins2 = np.intersect1d(dt_res, rf_res)
    ins3 = np.intersect1d(svm_res, dt_res)
    
    ins4 = np.intersect1d(ins1,ins2)
    ins5 = np.intersect1d(ins2,ins3)
    ins6 = np.union1d(ins4,ins5)
    ins7 = np.intersect1d(nn_res, ins6)
    
    return ins7
    #print("DT accuracy: ", do_confusion(y_test, y_pred))
    #print("F1 Score: ", do_f1(y_test, y_pred))


    
 
write_log('-----------ALARM LOG저장-----------')

for i in range(len(alarmlog_file)):    
    if alarmlog_file == [''] : break
    store_alarm_logfull(logdir,alarmlog_file[i],get_logday(2),alarm_log_list,conn)
#sql = 'select count(*) from log_full
write_log('-----------IPS LOG저장-------------')

for i in range(len(ipslog_file)):
    if ipslog_file == [''] : break
    store_ips_logfull(logdir,ipslog_file[i],get_logday(2),ips_log_list,conn)

write_log('-----------WAF LOG저장-------------')

for i in range(len(waflog_file)):
    if waflog_file == [''] : break
    store_waf_logfull(logdir,waflog_file[i],get_logday(2),waf_log_list,conn)

write_log('-------------WEB OK저장------------')

for i in web_ok_file :    
    if web_ok_file == [''] : break
    #try :
    store_web_log_light(logdir,i,get_logday(2),'web_ok',conn)
    #except :
    #    print("알 수 없는 ERROR 발생!!!")        
    #    continue




write_log('-----WEB REJ저장------')

for i in web_rej_file :    
    if web_rej_file == [''] : break
    try :
        store_web_log_light(logdir,i,get_logday(2),'web_rej',conn)
    except :
        write_log("알 수 없는 ERROR 발생!!!")
        continue


write_log('-------FW PD저장--------')

for i in fw_pd_file :    
    if fw_pd_file == [''] : break
    #try :
    store_fw_log_light(logdir,i,get_logday(2),'Accept',conn)
    #except :
    #    print("알 수 없는 ERROR 발생!!!")
    #    continue

write_log('-----FW DB저장-----')

for i in fw_db_file :    
    if fw_db_file == [''] : break
    #try :
    store_fw_log_light(logdir,i,get_logday(2),'Drop (102)',conn)    
    #except :
    #    print("알 수 없는 ERROR 발생!!!")
    #    continue
    
write_log('update ip cache no')    
update_ip_cache_no()

write_log('update ip cache no fw')

update_ip_cache_no_fw()

write_log('update fw ipr top 20')
update_fw_ipr()

write_log('basic analysis2')

basic_analysis2()

write_log('Inspectioning')
inspection()

write_log('update blacklist')
sql_bl = update_bl()                         
print("bl update completed")

write_log('Machine Learning')
#simple_daily_report(datetime.date.today(),'ips')
#simple_daily_report(datetime.date.today(),'waf')
#simple_daily_report(datetime.date.today(),'web')
#simple_daily_report(datetime.date.today(),'fw')
ai_bl = data_preprocessing(LEARNING_START_DATE,LEARNING_END_DATE)
print("AI 추천 Blacklist => ", ai_bl)
write_log("AI 추천 Blacklist")
write_log(str(ai_bl))

write_log('모든 프로세스 완료')

conn.close()
