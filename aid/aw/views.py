from django.shortcuts import render, redirect, get_object_or_404

# Create your views here.
from django.http import HttpResponse
from aw.models import Log_full
from aw.models import IP_Cache
from aw.models import bl as bl_
from aw.models import wl
from .forms import BlForm
import datetime
import MySQLdb


# const bl_code
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


def post(request):
    day = datetime.date.today()

    form = BlForm()
    return render(request,"aw/post.html",{'form':form})

def index(request,write_date):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = str(write_date)
    print('search day :' , day)
    curs = conn.cursor()        
    # fw scan top 20     
    fwscan = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :                           
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_row = curs.fetchone()
        fwscan.append(fwscan_row)
    
           
    
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'    
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        th_ip.append(th_ip_row)       
    

     # keyword01 - ip로 direct 접속
    ipd = []        
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_row = curs.fetchone()
        ipd.append(ipd_row)
   
    
    # keyword02 - 워드프레스 취약점 공격    
    wp = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_row = curs.fetchone()
        wp.append(wp_row)

    # keyword03 - method 오용    
    method = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        method_row = curs.fetchone()
        method.append(method_row)   

    # keyword04 - PHP 취약점 공격    
    php = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        php_row = curs.fetchone()
        php.append(php_row)   

    # keyword05 - XML 원격코드 실행   
    xmlrpc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_row = curs.fetchone()
        xmlrpc.append(xmlrpc_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_row = curs.fetchone()
        struts.append(struts_row)
        
    # keyword07 - ECSC(내부제외)     
    ecsc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_row = curs.fetchone()
        ecsc.append(ecsc_row)
        
    # keyword08 - NCSC(내부제외)    
    ncsc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_row = curs.fetchone()
        ncsc.append(ncsc_row)
        
    # keyword09 - Webshell 업로드    
    webshell = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_row = curs.fetchone()
        webshell.append(webshell_row)

    # keyword10 - Wanna Cry    
    wannacry = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_row = curs.fetchone()
        wannacry.append(wannacry_row)


    # TOP IBM Score    
    ibmScore = []
    bl_ip_sql = 'select ip from aw_ip_cache where bl_ibm > 2 and modi_time like %s order by bl_ibm desc'
    curs.execute(bl_ip_sql,(str(day)+'%',))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :    
        curs.execute(s_ip_cache,(ip[0],)) 
        ibmScore_row = curs.fetchone()
        ibmScore.append(ibmScore_row)
   

    conn.close()    
    return render(request, 'aw/index.html',{'fwscan':fwscan,
                                            'th_ip':th_ip,
                                            'ipd':ipd,
                                            'wp':wp,
                                            'method':method,
                                            'php':php,
                                            'xmlrpc':xmlrpc,
                                            'struts':struts,
                                            'ecsc':ecsc,
                                            'ncsc':ncsc,
                                            'webshell':webshell,
                                            'wannacry':wannacry,
                                            'ibmScore':ibmScore,
                                            'day':day,
                                            })

def indexToday(request):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = str(datetime.date.today())
    print("Today is ", day)
    curs = conn.cursor()
    # fw scan top 20     
    fwscan = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :                           
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_row = curs.fetchone()
        fwscan.append(fwscan_row)
    
           
    
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'    
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        th_ip.append(th_ip_row)       
    

     # keyword01 - ip로 direct 접속
    ipd = []        
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_row = curs.fetchone()
        ipd.append(ipd_row)
   
    
    # keyword02 - 워드프레스 취약점 공격    
    wp = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_row = curs.fetchone()
        wp.append(wp_row)

    # keyword03 - method 오용    
    method = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        method_row = curs.fetchone()
        method.append(method_row)   

    # keyword04 - PHP 취약점 공격    
    php = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        php_row = curs.fetchone()
        php.append(php_row)   

    # keyword05 - XML 원격코드 실행   
    xmlrpc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_row = curs.fetchone()
        xmlrpc.append(xmlrpc_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_row = curs.fetchone()
        struts.append(struts_row)
        
    # keyword07 - ECSC(내부제외)     
    ecsc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_row = curs.fetchone()
        ecsc.append(ecsc_row)
        
    # keyword08 - NCSC(내부제외)    
    ncsc = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_row = curs.fetchone()
        ncsc.append(ncsc_row)
        
    # keyword09 - Webshell 업로드    
    webshell = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_row = curs.fetchone()
        webshell.append(webshell_row)

    # keyword10 - Wanna Cry    
    wannacry = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()        
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_row = curs.fetchone()
        wannacry.append(wannacry_row)


    # TOP IBM Score    
    ibmScore = []
    bl_ip_sql = 'select ip from aw_ip_cache where bl_ibm > 2 and modi_time like %s order by bl_ibm desc'
    curs.execute(bl_ip_sql,(str(day)+'%',))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :    
        curs.execute(s_ip_cache,(ip[0],)) 
        ibmScore_row = curs.fetchone()
        ibmScore.append(ibmScore_row)
   

    conn.close()    
    return render(request, 'aw/index.html',{'fwscan':fwscan,
                                            'th_ip':th_ip,
                                            'ipd':ipd,
                                            'wp':wp,
                                            'method':method,
                                            'php':php,
                                            'xmlrpc':xmlrpc,
                                            'struts':struts,
                                            'ecsc':ecsc,
                                            'ncsc':ncsc,
                                            'webshell':webshell,
                                            'wannacry':wannacry,
                                            'ibmScore':ibmScore,
                                            'day':day,
                                            })


def everything(request,write_date):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = write_date
    print('search day :' , day)
    curs = conn.cursor()        
    # fw scan top 20
    fwscan = []    
    fwscan_ip_cache = []
    fwscan_today =[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select source_ip, times, log_type, write_date from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(sql,(ip[0],))
        fwscan_row = curs.fetchall() # IP에 대한 모든 log select
        for fw in fwscan_row:            
            if(fw[3] == str(day)) : # select 한 log 중 오늘 날짜면 fwscan_today에 넎는다.           
                fwscan_today.append(fw)                
        #fwscan_today=set(fwscan_)        
        fwscan.append(fwscan_row) # ip별로 모든 log fwscan에 append
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_ip_cache_row = curs.fetchone()
        fwscan_ip_cache.append(fwscan_ip_cache_row)
    
           
    
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'    
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        th_ip.append(th_ip_row)       
    

     # keyword01 - ip로 direct 접속
    ipd = []
    ipd_today=[]
    ipd_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ipd_row = curs.fetchall()
        for d in ipd_row:            
            if(d[7] == str(day)) : 
                ipd_today.append(d)                        
        ipd.append(ipd_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_ip_cache_row = curs.fetchone()
        ipd_ip_cache.append(ipd_ip_cache_row)
   
    
    # keyword02 - 워드프레스 취약점 공격
    wp = []
    wp_today=[]
    wp_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wp_row = curs.fetchall()
        for wps in wp_row:            
            if(wps[7] == str(day)) : 
                wp_today.append(wps)                        
        wp.append(wp_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_ip_cache_row = curs.fetchone()
        wp_ip_cache.append(wp_ip_cache_row)

    # keyword03 - method 오용
    method = []
    method_today=[]
    method_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        method_row = curs.fetchall()
        for mt in method_row:            
            if(mt[7] == str(day)) : 
                method_today.append(mt)        
        method.append(method_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        method_ip_cache_row = curs.fetchone()
        method_ip_cache.append(method_ip_cache_row)   

    # keyword04 - PHP 취약점 공격
    php = []
    php_today=[]
    php_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        php_row = curs.fetchall()
        for p in php_row:            
            if(p[7] == str(day)) : 
                php_today.append(p)                        
        php.append(php_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        php_ip_cache_row = curs.fetchone()
        php_ip_cache.append(php_ip_cache_row)   

    # keyword05 - XML 원격코드 실행
    xmlrpc = []
    xmlrpc_today=[]
    xmlrpc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        xmlrpc_row = curs.fetchall()
        for xml in xmlrpc_row:            
            if(xml[7] == str(day)) : 
                xmlrpc_today.append(xml)
        xmlrpc.append(xmlrpc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_ip_cache_row = curs.fetchone()
        xmlrpc_ip_cache.append(xmlrpc_ip_cache_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    struts_today=[]
    struts_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        struts_row = curs.fetchall()
        for st in struts_row:            
            if(st[7] == str(day)) : 
                struts_today.append(st)
        struts.append(struts_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_ip_cache_row = curs.fetchone()
        struts_ip_cache.append(struts_ip_cache_row)
        
    # keyword07 - ECSC(내부제외)
    ecsc = []
    ecsc_today=[]
    ecsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ecsc_row = curs.fetchall()
        for ec in ecsc_row:            
            if(ec[7] == str(day)) : 
                ecsc_today.append(ec)
                ecsc.append(ecsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_ip_cache_row = curs.fetchone()
        ecsc_ip_cache.append(ecsc_ip_cache_row)
        
    # keyword08 - NCSC(내부제외)
    ncsc = []
    ncsc_today=[]
    ncsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ncsc_row = curs.fetchall()
        for nc in ncsc_row:            
            if(nc[7] == str(day)) : 
                ncsc_today.append(nc)
        ncsc.append(ncsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_ip_cache_row = curs.fetchone()
        ncsc_ip_cache.append(ncsc_ip_cache_row)
        
    # keyword09 - Webshell 업로드
    webshell = []
    webshell_today=[]
    webshell_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        webshell_row = curs.fetchall()
        for ws in webshell_row:            
            if(ws[7] == str(day)) : 
                webshell_today.append(ws)
        webshell.append(webshell_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_ip_cache_row = curs.fetchone()
        webshell_ip_cache.append(webshell_ip_cache_row)

    # keyword10 - Wanna Cry
    wannacry = []
    wannacry_today=[]
    wannacry_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wannacry_row = curs.fetchall()
        for wc in wannacry_row:            
            if(wc[7] == str(day)) : 
                wannacry_today.append(wc)
        wannacry.append(wannacry_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_ip_cache_row = curs.fetchone()
        wannacry_ip_cache.append(wannacry_ip_cache_row)


    conn.close()    
    return render(request, 'aw/report.html',{'fwscan':fwscan,'fwscan_ip_cache':fwscan_ip_cache,'fwscan_today':fwscan_today,
                                            'th_ip':th_ip,
                                            'ipd':ipd,'ipd_ip_cache':ipd_ip_cache,'ipd_today':ipd_today,
                                            'wp':wp,'wp_ip_cache':wp_ip_cache,'wp_today':wp_today,
                                            'method':method,'method_ip_cache':method_ip_cache,'method_today':method_today,
                                            'php':php,'php_ip_cache':php_ip_cache,'php_today':php_today,
                                            'xmlrpc':xmlrpc,'xmlrpc_ip_cache':xmlrpc_ip_cache,'xmlrpc_today':xmlrpc_today,
                                            'struts':struts,'struts_ip_cache':struts_ip_cache,'struts_today':struts_today,
                                            'ecsc':ecsc,'ecsc_ip_cache':ecsc_ip_cache,'ecsc_today':ecsc_today,
                                            'ncsc':ncsc,'ncsc_ip_cache':ncsc_ip_cache,'ncsc_today':ncsc_today,
                                            'webshell':webshell,'webshell_ip_cache':webshell_ip_cache,'webshell_today':webshell_today,
                                            'wannacry':wannacry,'wannacry_ip_cache':wannacry_ip_cache,'wannacry_today':wannacry_today,                                            
                                            'day':day,
                                            })

def everythingToday(request):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = datetime.date.today()
    print("Today is ", day)
    curs = conn.cursor()
    # fw scan top 20
    fwscan = []    
    fwscan_ip_cache = []
    fwscan_today =[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select source_ip, times, log_type, write_date from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(sql,(ip[0],))
        fwscan_row = curs.fetchall() # IP에 대한 모든 log select
        for fw in fwscan_row:            
            if(fw[3] == str(day)) : # select 한 log 중 오늘 날짜면 fwscan_today에 넎는다.           
                fwscan_today.append(fw)                
        #fwscan_today=set(fwscan_)        
        fwscan.append(fwscan_row) # ip별로 모든 log fwscan에 append
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_ip_cache_row = curs.fetchone()
        fwscan_ip_cache.append(fwscan_ip_cache_row)
    
           
    
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []    
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'    
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        th_ip.append(th_ip_row)       
    

    # keyword01 - ip로 direct 접속
    ipd = []
    ipd_today=[]
    ipd_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ipd_row = curs.fetchall()
        for d in ipd_row:            
            if(d[7] == str(day)) : 
                ipd_today.append(d)                        
        ipd.append(ipd_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_ip_cache_row = curs.fetchone()
        ipd_ip_cache.append(ipd_ip_cache_row)
   
    
    # keyword02 - 워드프레스 취약점 공격
    wp = []
    wp_today=[]
    wp_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wp_row = curs.fetchall()
        for wps in wp_row:            
            if(wps[7] == str(day)) : 
                wp_today.append(wps)                        
        wp.append(wp_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_ip_cache_row = curs.fetchone()
        wp_ip_cache.append(wp_ip_cache_row)

    # keyword03 - method 오용
    method = []
    method_today=[]
    method_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        method_row = curs.fetchall()
        for mt in method_row:            
            if(mt[7] == str(day)) : 
                method_today.append(mt)        
        method.append(method_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        method_ip_cache_row = curs.fetchone()
        method_ip_cache.append(method_ip_cache_row)   

    # keyword04 - PHP 취약점 공격
    php = []
    php_today=[]
    php_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        php_row = curs.fetchall()
        for p in php_row:            
            if(p[7] == str(day)) : 
                php_today.append(p)                        
        php.append(php_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        php_ip_cache_row = curs.fetchone()
        php_ip_cache.append(php_ip_cache_row)   

    # keyword05 - XML 원격코드 실행
    xmlrpc = []
    xmlrpc_today=[]
    xmlrpc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        xmlrpc_row = curs.fetchall()
        for xml in xmlrpc_row:            
            if(xml[7] == str(day)) : 
                xmlrpc_today.append(xml)
        xmlrpc.append(xmlrpc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_ip_cache_row = curs.fetchone()
        xmlrpc_ip_cache.append(xmlrpc_ip_cache_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    struts_today=[]
    struts_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        struts_row = curs.fetchall()
        for st in struts_row:            
            if(st[7] == str(day)) : 
                struts_today.append(st)
        struts.append(struts_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_ip_cache_row = curs.fetchone()
        struts_ip_cache.append(struts_ip_cache_row)
        
    # keyword07 - ECSC(내부제외)
    ecsc = []
    ecsc_today=[]
    ecsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ecsc_row = curs.fetchall()
        for ec in ecsc_row:            
            if(ec[7] == str(day)) : 
                ecsc_today.append(ec)
                ecsc.append(ecsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_ip_cache_row = curs.fetchone()
        ecsc_ip_cache.append(ecsc_ip_cache_row)
        
    # keyword08 - NCSC(내부제외)
    ncsc = []
    ncsc_today=[]
    ncsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ncsc_row = curs.fetchall()
        for nc in ncsc_row:            
            if(nc[7] == str(day)) : 
                ncsc_today.append(nc)
        ncsc.append(ncsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_ip_cache_row = curs.fetchone()
        ncsc_ip_cache.append(ncsc_ip_cache_row)
        
    # keyword09 - Webshell 업로드
    webshell = []
    webshell_today=[]
    webshell_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        webshell_row = curs.fetchall()
        for ws in webshell_row:            
            if(ws[7] == str(day)) : 
                webshell_today.append(ws)
        webshell.append(webshell_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_ip_cache_row = curs.fetchone()
        webshell_ip_cache.append(webshell_ip_cache_row)
    

    # keyword10 - Wanna Cry
    wannacry = []
    wannacry_today=[]
    wannacry_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wannacry_row = curs.fetchall()
        for wc in wannacry_row:            
            if(wc[7] == str(day)) : 
                wannacry_today.append(wc)
        wannacry.append(wannacry_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_ip_cache_row = curs.fetchone()
        wannacry_ip_cache.append(wannacry_ip_cache_row)

    
    conn.close()
    return render(request, 'aw/report.html',{'fwscan':fwscan,'fwscan_ip_cache':fwscan_ip_cache,'fwscan_today':fwscan_today,
                                            'th_ip':th_ip,
                                            'ipd':ipd,'ipd_ip_cache':ipd_ip_cache,'ipd_today':ipd_today,
                                            'wp':wp,'wp_ip_cache':wp_ip_cache,'wp_today':wp_today,
                                            'method':method,'method_ip_cache':method_ip_cache,'method_today':method_today,
                                            'php':php,'php_ip_cache':php_ip_cache,'php_today':php_today,
                                            'xmlrpc':xmlrpc,'xmlrpc_ip_cache':xmlrpc_ip_cache,'xmlrpc_today':xmlrpc_today,
                                            'struts':struts,'struts_ip_cache':struts_ip_cache,'struts_today':struts_today,
                                            'ecsc':ecsc,'ecsc_ip_cache':ecsc_ip_cache,'ecsc_today':ecsc_today,
                                            'ncsc':ncsc,'ncsc_ip_cache':ncsc_ip_cache,'ncsc_today':ncsc_today,
                                            'webshell':webshell,'webshell_ip_cache':webshell_ip_cache,'webshell_today':webshell_today,
                                            'wannacry':wannacry,'wannacry_ip_cache':wannacry_ip_cache,'wannacry_today':wannacry_today,
                                            'day':day,
                                            })


def thIp(request,write_date):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = write_date
    print("Searching day is ", day)
    curs = conn.cursor()
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []
    th_ip_today=[]
    th_ip_cache=[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        for ti in th_ip_row:            
            if(ti[7] == str(day)) : 
                th_ip_today.append(ti)
        th_ip.append(th_ip_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        th_ip_cache_row = curs.fetchone()
        th_ip_cache.append(th_ip_cache_row)
    conn.close()
    return render(request,'aw/thip.html',{'th_ip':th_ip,'th_ip_cache':th_ip_cache,'th_ip_today':th_ip_today,'day':day,})

def thIpToday(request,write_date):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = datetime.date.today()
    print("Searching day is ", day)
    curs = conn.cursor()    
    # threating ip : (해외 or (국내 and (ips or WAF에 차단)) ) 이면서 web_ok = 0
    th_ip = []
    th_ip_today=[]
    th_ip_cache=[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,th_ip_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        th_ip_row = curs.fetchall()
        for ti in th_ip_row:            
            if(ti[7] == str(day)) : 
                th_ip_today.append(ti)
        th_ip.append(th_ip_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        th_ip_cache_row = curs.fetchone()
        th_ip_cache.append(th_ip_cache_row)
    conn.close()
    return render(request,'aw/thip.html',{'th_ip':th_ip,'th_ip_cache':th_ip_cache,'th_ip_today':th_ip_today,'day':day,})



def ibmScorePage(request,modi_time):
    # TOP IBM Score
    day = modi_time
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    curs = conn.cursor()
    ibmScore = []
    ibmScore_today=[]
    ibmScore_ip_cache = []
    bl_ip_sql = 'select ip from aw_ip_cache where bl_ibm > 0 and modi_time like %s order by bl_ibm desc'
    curs.execute(bl_ip_sql,(str(day)+'%',))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ibmScore_row = curs.fetchall()
        for ibs in ibmScore_row:            
            if(ibs[7] == str(day)) : 
                ibmScore_today.append(ibs)
        ibmScore.append(ibmScore_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ibmScore_ip_cache_row = curs.fetchone()
        ibmScore_ip_cache.append(ibmScore_ip_cache_row)
    conn.close()
    return render(request, 'aw/ibm.html',{'ibmScore':ibmScore,'ibmScore_ip_cache':ibmScore_ip_cache,'ibmScore_today':ibmScore_today,'day':day,})

def ibmScorePageToday(request):
    # TOP IBM Score
    day = datetime.date.today()
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    curs = conn.cursor()
    ibmScore = []
    ibmScore_today=[]
    ibmScore_ip_cache = []
    bl_ip_sql = 'select ip from aw_ip_cache where bl_ibm > 2 and modi_time like %s order by bl_ibm desc'
    curs.execute(bl_ip_sql,(str(day)+'%',))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ibmScore_row = curs.fetchall()
        for ibs in ibmScore_row:            
            if(ibs[7] == str(day)) : 
                ibmScore_today.append(ibs)
        ibmScore.append(ibmScore_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ibmScore_ip_cache_row = curs.fetchone()
        ibmScore_ip_cache.append(ibmScore_ip_cache_row)
    conn.close()
    return render(request, 'aw/ibm.html',{'ibmScore':ibmScore,'ibmScore_ip_cache':ibmScore_ip_cache,'ibmScore_today':ibmScore_today,'day':day,})

    

 
def displaySourceIP(request,source_ip):
    result = Log_full.objects.filter(source_ip=source_ip)
    ip_cache = IP_Cache.objects.filter(ip=source_ip)
    form = BlForm()    
    return render(request, 'aw/result.html',{'result':result,'form':form,'ip_cache':ip_cache})

def displayAB(request,write_date):    
    result_ab = IP_Cache.objects.filter(modi_time__contains = write_date,ip_gubun=1)
    
    return render(request,'aw/ab_result.html',{'result_ab':result_ab})

def displayABToday(request):
    day = datetime.date.today()
    write_date = day
    result_ab = IP_Cache.objects.filter(modi_time__contains = write_date,ip_gubun=1)
    
    return render(request,'aw/ab_result.html',{'result_ab':result_ab})

def displayAlarm(request, write_date):    
    # log_full의 alarm
    alarm = Log_full.objects.filter(write_date=write_date, log_type='alarm')
    # 알람의 해외 IP
    alarm_out = IP_Cache.objects.filter(modi_time__contains = write_date, ip_gubun=1)
    alarm_kr = IP_Cache.objects.filter(modi_time__contains = write_date, ip_gubun=2) 
    return render(request,'aw/alarm.html',{'alarm':alarm, 'alarm_out':alarm_out, 'alarm_kr':alarm_kr})

def displayAlarmToday(request):
    day = datetime.date.today()
    write_date = day
    # log_full의 alarm
    alarm = Log_full.objects.filter(write_date=write_date, log_type='alarm')
    # 알람의 해외 IP
    alarm_out = IP_Cache.objects.filter(modi_time__contains = write_date, ip_gubun=1)
    alarm_kr = IP_Cache.objects.filter(modi_time__contains = write_date, ip_gubun=2) 
    return render(request,'aw/alarm.html',{'alarm':alarm, 'alarm_out':alarm_out, 'alarm_kr':alarm_kr})



def bl(request,ip): # BL /WL / HD 상태 Manual 변경
    if request.method == 'POST':
        conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
        curs = conn.cursor()
        form=BlForm(request.POST)        
        flag = request.POST.getlist('flag')
        day = datetime.date.today()
        #sql = 'insert into aw_bl (ip,flag,write_date) values (%s,%s,%s)'
        u_ic = 'update aw_ip_cache set bl_dg_yn = %s where ip = %s'
        curs.execute(u_ic,(flag[0],ip))
        conn.commit()
        try :
            u_bl = 'update aw_bl set flag flag = %s where ip = %s'
            curs.execute(u_bl,(flag[0],ip))
            conn.commit()
        except :
            pass                      
        conn.close()                  
    return HttpResponse("finish")

def fwScan(request, write_date): 
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    curs = conn.cursor()
    day = write_date
    # fw scan top 20
    fwscan = []    
    fwscan_ip_cache = []
    fwscan_today =[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select source_ip, times, log_type, write_date from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(sql,(ip[0],))
        fwscan_row = curs.fetchall() # IP에 대한 모든 log select
        for fw in fwscan_row:            
            if(fw[3] == str(day)) : # select 한 log 중 오늘 날짜면 fwscan_today에 넎는다.           
                fwscan_today.append(fw)                
        #fwscan_today=set(fwscan_)        
        fwscan.append(fwscan_row) # ip별로 모든 log fwscan에 append
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_ip_cache_row = curs.fetchone()
        fwscan_ip_cache.append(fwscan_ip_cache_row)
    conn.close()
    return render(request, 'aw/fwscan.html',{'fwscan':fwscan,'fwscan_ip_cache':fwscan_ip_cache,'fwscan_today':fwscan_today,'day':day,})

def fwScanToday(request):
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    curs = conn.cursor()
    day = datetime.date.today()    
    # fw scan top 20
    fwscan = []    
    fwscan_ip_cache = []
    fwscan_today =[]
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,fwscan_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select source_ip, times, log_type, write_date from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :        
        curs.execute(sql,(ip[0],))
        fwscan_row = curs.fetchall() # IP에 대한 모든 log select
        for fw in fwscan_row:            
            if(fw[3] == str(day)) : # select 한 log 중 오늘 날짜면 fwscan_today에 넎는다.           
                fwscan_today.append(fw)                
        #fwscan_today=set(fwscan_)        
        fwscan.append(fwscan_row) # ip별로 모든 log fwscan에 append
        curs.execute(s_ip_cache,(ip[0],)) # 해당 ip에 대한 ip_cache 정보 select
        fwscan_ip_cache_row = curs.fetchone()
        fwscan_ip_cache.append(fwscan_ip_cache_row)
    conn.close()
    return render(request, 'aw/fwscan.html',{'fwscan':fwscan,'fwscan_ip_cache':fwscan_ip_cache,'fwscan_today':fwscan_today,'day':day,})


def wafAlarm(request,write_date) :
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = write_date    
    curs = conn.cursor()
    # keyword01 - ip로 direct 접속
    ipd = []
    ipd_today=[]
    ipd_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ipd_row = curs.fetchall()
        for d in ipd_row:            
            if(d[7] == str(day)) : 
                ipd_today.append(d)                        
        ipd.append(ipd_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_ip_cache_row = curs.fetchone()
        ipd_ip_cache.append(ipd_ip_cache_row)
   
    
    # keyword02 - 워드프레스 취약점 공격
    wp = []
    wp_today=[]
    wp_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wp_row = curs.fetchall()
        for wps in wp_row:            
            if(wps[7] == str(day)) : 
                wp_today.append(wps)                        
        wp.append(wp_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_ip_cache_row = curs.fetchone()
        wp_ip_cache.append(wp_ip_cache_row)

    # keyword03 - method 오용
    method = []
    method_today=[]
    method_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        method_row = curs.fetchall()
        for mt in method_row:            
            if(mt[7] == str(day)) : 
                method_today.append(mt)        
        method.append(method_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        method_ip_cache_row = curs.fetchone()
        method_ip_cache.append(method_ip_cache_row)   

    # keyword04 - PHP 취약점 공격
    php = []
    php_today=[]
    php_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        php_row = curs.fetchall()
        for p in php_row:            
            if(p[7] == str(day)) : 
                php_today.append(p)                        
        php.append(php_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        php_ip_cache_row = curs.fetchone()
        php_ip_cache.append(php_ip_cache_row)

    conn.close()
    return render(request, 'aw/waf.html',{'ipd':ipd,'ipd_ip_cache':ipd_ip_cache,'ipd_today':ipd_today,
                                          'wp':wp,'wp_ip_cache':wp_ip_cache,'wp_today':wp_today,
                                          'method':method,'method_ip_cache':method_ip_cache,'method_today':method_today,
                                          'php':php,'php_ip_cache':php_ip_cache,'php_today':php_today,'day':day,})


def wafAlarmToday(request) :
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = datetime.date.today()
    print("Today is ", day)
    curs = conn.cursor()
    # keyword01 - ip로 direct 접속
    ipd = []
    ipd_today=[]
    ipd_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'    
    curs.execute(bl_ip_sql,(day,ipd_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ipd_row = curs.fetchall()
        for d in ipd_row:            
            if(d[7] == str(day)) : 
                ipd_today.append(d)                        
        ipd.append(ipd_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ipd_ip_cache_row = curs.fetchone()
        ipd_ip_cache.append(ipd_ip_cache_row)
   
    
    # keyword02 - 워드프레스 취약점 공격
    wp = []
    wp_today=[]
    wp_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wp_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip=%s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wp_row = curs.fetchall()
        for wps in wp_row:            
            if(wps[7] == str(day)) : 
                wp_today.append(wps)                        
        wp.append(wp_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wp_ip_cache_row = curs.fetchone()
        wp_ip_cache.append(wp_ip_cache_row)

    # keyword03 - method 오용
    method = []
    method_today=[]
    method_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,method_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        method_row = curs.fetchall()
        for mt in method_row:            
            if(mt[7] == str(day)) : 
                method_today.append(mt)        
        method.append(method_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        method_ip_cache_row = curs.fetchone()
        method_ip_cache.append(method_ip_cache_row)   

    # keyword04 - PHP 취약점 공격
    php = []
    php_today=[]
    php_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,php_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        php_row = curs.fetchall()
        for p in php_row:            
            if(p[7] == str(day)) : 
                php_today.append(p)                        
        php.append(php_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        php_ip_cache_row = curs.fetchone()
        php_ip_cache.append(php_ip_cache_row)
    conn.close()
    return render(request, 'aw/waf.html',{'ipd':ipd,'ipd_ip_cache':ipd_ip_cache,'ipd_today':ipd_today,
                                            'wp':wp,'wp_ip_cache':wp_ip_cache,'wp_today':wp_today,
                                            'method':method,'method_ip_cache':method_ip_cache,'method_today':method_today,
                                            'php':php,'php_ip_cache':php_ip_cache,'php_today':php_today,'day':day,})


def ipsAlarm(request, write_date) :
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = write_date
    print("Today is ", day)
    curs = conn.cursor()
    # keyword05 - XML 원격코드 실행
    xmlrpc = []
    xmlrpc_today=[]
    xmlrpc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        xmlrpc_row = curs.fetchall()
        for xml in xmlrpc_row:            
            if(xml[7] == str(day)) : 
                xmlrpc_today.append(xml)
        xmlrpc.append(xmlrpc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_ip_cache_row = curs.fetchone()
        xmlrpc_ip_cache.append(xmlrpc_ip_cache_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    struts_today=[]
    struts_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        struts_row = curs.fetchall()
        for st in struts_row:            
            if(st[7] == str(day)) : 
                struts_today.append(st)
        struts.append(struts_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_ip_cache_row = curs.fetchone()
        struts_ip_cache.append(struts_ip_cache_row)
        
    # keyword07 - ECSC(내부제외)
    ecsc = []
    ecsc_today=[]
    ecsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ecsc_row = curs.fetchall()
        for ec in ecsc_row:            
            if(ec[7] == str(day)) : 
                ecsc_today.append(ec)
                ecsc.append(ecsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_ip_cache_row = curs.fetchone()
        ecsc_ip_cache.append(ecsc_ip_cache_row)
        
    # keyword08 - NCSC(내부제외)
    ncsc = []
    ncsc_today=[]
    ncsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ncsc_row = curs.fetchall()
        for nc in ncsc_row:            
            if(nc[7] == str(day)) : 
                ncsc_today.append(nc)
        ncsc.append(ncsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_ip_cache_row = curs.fetchone()
        ncsc_ip_cache.append(ncsc_ip_cache_row)
        
    # keyword09 - Webshell 업로드
    webshell = []
    webshell_today=[]
    webshell_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        webshell_row = curs.fetchall()
        for ws in webshell_row:            
            if(ws[7] == str(day)) : 
                webshell_today.append(ws)
        webshell.append(webshell_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_ip_cache_row = curs.fetchone()
        webshell_ip_cache.append(webshell_ip_cache_row)
    

    # keyword10 - Wanna Cry
    wannacry = []
    wannacry_today=[]
    wannacry_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wannacry_row = curs.fetchall()
        for wc in wannacry_row:            
            if(wc[7] == str(day)) : 
                wannacry_today.append(wc)
        wannacry.append(wannacry_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_ip_cache_row = curs.fetchone()
        wannacry_ip_cache.append(wannacry_ip_cache_row)
    conn.close()
    return render(request, 'aw/ips.html',{'xmlrpc':xmlrpc,'xmlrpc_ip_cache':xmlrpc_ip_cache,'xmlrpc_today':xmlrpc_today,
                                            'struts':struts,'struts_ip_cache':struts_ip_cache,'struts_today':struts_today,
                                            'ecsc':ecsc,'ecsc_ip_cache':ecsc_ip_cache,'ecsc_today':ecsc_today,
                                            'ncsc':ncsc,'ncsc_ip_cache':ncsc_ip_cache,'ncsc_today':ncsc_today,
                                            'webshell':webshell,'webshell_ip_cache':webshell_ip_cache,'webshell_today':webshell_today,
                                            'wannacry':wannacry,'wannacry_ip_cache':wannacry_ip_cache,'wannacry_today':wannacry_today,
                                            'day':day,
                                            })


def ipsAlarmToday(request) :
    conn = MySQLdb.connect('localhost','root','rhrnak#33','ais', charset = "utf8")
    day = datetime.date.today()
    print("Today is ", day)
    curs = conn.cursor()
    # keyword05 - XML 원격코드 실행
    xmlrpc = []
    xmlrpc_today=[]
    xmlrpc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,xmlrpc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        xmlrpc_row = curs.fetchall()
        for xml in xmlrpc_row:            
            if(xml[7] == str(day)) : 
                xmlrpc_today.append(xml)
        xmlrpc.append(xmlrpc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        xmlrpc_ip_cache_row = curs.fetchone()
        xmlrpc_ip_cache.append(xmlrpc_ip_cache_row)
    
    # keyword06 - apache struts 취약점 공격
    struts = []
    struts_today=[]
    struts_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,struts_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        struts_row = curs.fetchall()
        for st in struts_row:            
            if(st[7] == str(day)) : 
                struts_today.append(st)
        struts.append(struts_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        struts_ip_cache_row = curs.fetchone()
        struts_ip_cache.append(struts_ip_cache_row)
        
    # keyword07 - ECSC(내부제외)
    ecsc = []
    ecsc_today=[]
    ecsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ecsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ecsc_row = curs.fetchall()
        for ec in ecsc_row:            
            if(ec[7] == str(day)) : 
                ecsc_today.append(ec)
                ecsc.append(ecsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ecsc_ip_cache_row = curs.fetchone()
        ecsc_ip_cache.append(ecsc_ip_cache_row)
        
    # keyword08 - NCSC(내부제외)
    ncsc = []
    ncsc_today=[]
    ncsc_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,ncsc_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        ncsc_row = curs.fetchall()
        for nc in ncsc_row:            
            if(nc[7] == str(day)) : 
                ncsc_today.append(nc)
        ncsc.append(ncsc_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        ncsc_ip_cache_row = curs.fetchone()
        ncsc_ip_cache.append(ncsc_ip_cache_row)
        
    # keyword09 - Webshell 업로드
    webshell = []
    webshell_today=[]
    webshell_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,webshell_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        webshell_row = curs.fetchall()
        for ws in webshell_row:            
            if(ws[7] == str(day)) : 
                webshell_today.append(ws)
        webshell.append(webshell_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        webshell_ip_cache_row = curs.fetchone()
        webshell_ip_cache.append(webshell_ip_cache_row)
    

    # keyword10 - Wanna Cry
    wannacry = []
    wannacry_today=[]
    wannacry_ip_cache = []
    bl_ip_sql = 'select ip from aw_bl where write_date = %s and bl_code = %s and flag = %s'
    curs.execute(bl_ip_sql,(day,wannacry_code,black_list))
    bl_ip = curs.fetchall()    
    sql = 'select log_time, source_ip, dest_ip, dest_port, times, method, attack_code, write_date, log_type from aw_log_full where source_ip = %s'
    s_ip_cache = 'select ip, times, cc, bl_ibm, write_date, web_ok, web_rej, fw_pd, fw_db, waf_ok, waf_rej, ips_pd, ips_db from aw_ip_cache where ip = %s'
    for ip in bl_ip :
        curs.execute(sql,(ip[0],))
        wannacry_row = curs.fetchall()
        for wc in wannacry_row:            
            if(wc[7] == str(day)) : 
                wannacry_today.append(wc)
        wannacry.append(wannacry_row) 
        curs.execute(s_ip_cache,(ip[0],)) 
        wannacry_ip_cache_row = curs.fetchone()
        wannacry_ip_cache.append(wannacry_ip_cache_row)
    conn.close()     
    return render(request, 'aw/ips.html',{'xmlrpc':xmlrpc,'xmlrpc_ip_cache':xmlrpc_ip_cache,'xmlrpc_today':xmlrpc_today,
                                            'struts':struts,'struts_ip_cache':struts_ip_cache,'struts_today':struts_today,
                                            'ecsc':ecsc,'ecsc_ip_cache':ecsc_ip_cache,'ecsc_today':ecsc_today,
                                            'ncsc':ncsc,'ncsc_ip_cache':ncsc_ip_cache,'ncsc_today':ncsc_today,
                                            'webshell':webshell,'webshell_ip_cache':webshell_ip_cache,'webshell_today':webshell_today,
                                            'wannacry':wannacry,'wannacry_ip_cache':wannacry_ip_cache,'wannacry_today':wannacry_today,
                                            'day':day,
                                            })



