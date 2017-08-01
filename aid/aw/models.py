from django.db import models
from aw.choices import *
import datetime


# Create your models here.

class Log_full(models.Model):
    log_full_no=models.IntegerField(primary_key=True)
    log_type=models.CharField(max_length=20)
    log_time=models.CharField(max_length=30)
    source_ip=models.CharField(max_length=16)
    dest_ip=models.CharField(max_length=16)
    dest_port=models.CharField(max_length=12)
    result=models.CharField(max_length=50)
    method=models.CharField(max_length=10000)
    get_post=models.CharField(max_length=10)
    raw=models.CharField(max_length=1000)
    attack_code=models.CharField(max_length=500)
    times=models.IntegerField()
    agent=models.CharField(max_length=30)
    comment=models.CharField(max_length=500)
    risk_score=models.IntegerField()
    write_time=models.CharField(max_length=20)
    modi_time=models.CharField(max_length=30)
    alarm_yn=models.CharField(max_length=3)
    ip_cache_no=models.CharField(max_length=16)
    attack_cache_no=models.CharField(max_length=16)
    write_date=models.CharField(max_length=12)

    def __str__(self):
        return self.source_ip

class IP_Cache(models.Model):
    ip_cache_no = models.CharField(max_length=16)
    ip = models.CharField(max_length=16, primary_key = True)
    cc = models.CharField(max_length=3)
    ip_comment = models.CharField(max_length=500)
    ip_gubun = models.IntegerField(default=0)
    times = models.IntegerField(default=0)    
    bl_ibm = models.IntegerField(default=0)
    bl_dg_yn = models.IntegerField(default=0)
    bl_etc = models.CharField(max_length=50)
    block_yn = models.CharField(max_length=3)
    write_time = models.CharField(max_length=20)
    modi_time = models.CharField(max_length=40)
    write_date = models.CharField(max_length=15)
    seq = models.IntegerField(default=0)
    web_ok = models.IntegerField(default=0)
    web_rej = models.IntegerField(default=0)
    fw_pd = models.IntegerField(default=0)
    fw_db = models.IntegerField(default=0)
    waf_ok = models.IntegerField(default=0)
    waf_rej = models.IntegerField(default=0)
    ips_pd = models.IntegerField(default=0)
    ips_db = models.IntegerField(default=0)

    def __str__(self):
        return self.ip

class bl(models.Model):    
    ip = models.CharField(max_length=16, primary_key = True)    
    write_time = models.CharField(max_length=20)
    modi_time = models.CharField(max_length=40)
    write_date = models.CharField(max_length=15)
    flag = models.IntegerField(choices = BL_CHOICES, default=1)
    
    def __str__(self):
        return self.ip

    def today(self):
        day = datetime.date.today()
        self.write_date = day
        self.save()
        

class wl(models.Model):    
    ip = models.CharField(max_length=16, primary_key = True)    
    write_time = models.CharField(max_length=20)
    modi_time = models.CharField(max_length=40)
    write_date = models.CharField(max_length=15)
    flag = models.IntegerField(default=0)
    
    def __str__(self):
        return self.ip
"""
class dashboard(models.Model):
    write_date = models.CharField(max_length=15)
    log_time = models.CharField(max_length=30)
    source_ip = models.CharField(max_length=16)
    dest_ip = models.CharField(max_length=16)
    dest_port = models.CharField(max_length=5)    
    times_log_full= models.IntegerField(default=0)
    method = models.CharField(max_length=10000)    
    attack_code = models.CharField(max_length=500)
    keyword = = models.CharField(max_length=100)
    cc = = models.CharField(max_length=3)
    times_ip_cache= models.IntegerField(default=0)
    bl_ibm= models.IntegerField(default=0)
    bl_dg_yn = models.IntegerField(default=0)
    web_ok = models.IntegerField(default=0)
    web_rej= models.IntegerField(default=0)
    fw_pd= models.IntegerField(default=0)
    fw_db= models.IntegerField(default=0)
    waf_ok= models.IntegerField(default=0)
    waf_rej= models.IntegerField(default=0)
    ips_pd= models.IntegerField(default=0)
    ips_db= models.IntegerField(default=0)
"""
