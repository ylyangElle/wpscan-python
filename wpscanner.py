import os
from InfoCollection.BruteAdmin import *
from InfoCollection.PluginScan import *
from InfoCollection.ThemeScan import *
from InfoCollection.WpInfo import *
from InfoCollection.WpScan import *
from InfoCollection.ContentScan import *
from AuxiliaryModule.clean_cache import *

#参数输入
#先跳过
#url = "http://162.14.97.39/wordpress/"
url= "https://www.zhangxinxu.com/wordpress/"
#url = "https://hosekdentistry.com"
url = "http://wordy"
#用户输入
"""user_inputs = {
    "basic_url": url,
    "username_lists": [],
    
}"""
#初始化网站信息对象
wp_info = WpInfo(url)

#扫描 1.是否使用了cms 2.wp的版本
WpScan(wp_info)
#使用的插件以及主题信息扫描
PluginScan(wp_info)
ThemeScan(wp_info)
#暴力破解密码
#BruteAdmin(wp_info, )
clean_cache(r"AuxiliaryModule\caches")
wp_info.output()