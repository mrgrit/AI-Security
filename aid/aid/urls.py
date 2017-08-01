"""aid URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from aw import views
import datetime

day = datetime.date.today()

write_date = day

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^index/(?P<write_date>.+)',views.index),
    url(r'^index/', views.indexToday),
    url(r'^report/(?P<write_date>.+)',views.everything),
    url(r'^report/', views.everythingToday),
    url(r'^show/(?P<source_ip>.+)$',views.displaySourceIP),
    url(r'^show_ab/(?P<write_date>.+)$',views.displayAB),
    url(r'^show_ab/$',views.displayABToday),
    url(r'^alarm/',views.displayAlarmToday, name = "alarm"),
    url(r'^alarm/(?P<write_date>.+)',views.displayAlarm),
    url(r'^post/$',views.post,name="post_test"),
    url(r'^bl/(?P<ip>.+)$',views.bl,name = "bl"),
    url(r'^fwscan/(?P<write_date>.+)',views.fwScan),
    url(r'^fwscan/',views.fwScanToday),
    url(r'^ibm/(?P<modi_time>.+)',views.ibmScorePage),
    url(r'^ibm/',views.ibmScorePageToday),
    url(r'^thip/(?P<write_date>.+)',views.thIp),
    url(r'^thip/',views.thIpToday),
    url(r'^waf/(?P<write_date>.+)',views.wafAlarm),
    url(r'^waf/',views.wafAlarmToday),
    url(r'^ips/(?P<write_date>.+)',views.ipsAlarm),
    url(r'^ips/',views.ipsAlarmToday),
]
