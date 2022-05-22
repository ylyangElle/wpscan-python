import os
from urllib.request import *
from urllib.error import HTTPError

from AuxiliaryModule.http_req import *
import re

class WpScan:
    def __init__(self, wp_info):
        self.wp = wp_info
        self.is_wp()
        
    def is_wp(self): #判断该网站是否使用了wp
        if self.__is_index_has_wp_content() or self.__is_login_exists() or self.__is_spec_file_exists():
            self.wp_version()
        else:
            print("[!!] 该网站没有使用wordpress!!")
            exit()
       
    def __is_index_has_wp_content(self):
        sub_dir = "index.php"
        html_str = 'wp-[a-z]*'
        
        html_str_re = re.compile(html_str)
        if req_and_parse(self.wp, find_type=0, sub_dir=sub_dir, find_str=html_str_re):
            return True
        else:
            return False
        
    def __is_login_exists(self):
        sub_dir = "wp-login.php"
        
        if http_request(self.wp, sub_dir=sub_dir):
            return True
        else:
            return False
        
    def __is_spec_file_exists(self):
        sub_dirs = ["wp-trackback.php", "wp-links-opml.php", "wp-includes/js/colorpicker.js"]
        for dir in sub_dirs:
            if http_request(self.wp, sub_dir=dir):
                return True
        return False
    
    def wp_version(self):
        version_index = self.__wp_version_index()
        version_readme = self.__wp_version_readme()
        if version_index:
            print("[**] WordPress Version is {}".format(version_index))
            self.wp.wp_version = version_index
        elif version_readme:
            print("[**] WordPress Version is {}".format(version_readme))
            self.wp.wp_version = version_readme
        else:
            print("[!] 找不到版本信息！！！")
            print("[!] {} {}".format(version_index, version_readme))
    
    def __wp_version_index(self):
        sub_dir = "index.php"
        html_label = "meta"
        html_attrs = {
            'name': 'generator',
        }
        find_attr = 'content'
  
        results = req_and_parse(self.wp, find_type=1, sub_dir=sub_dir, \
            find_attrs=find_attr, find_label=html_label, limit_attrs=html_attrs)
        if results:
            return results[0]
        else:
            return False
        
    def __wp_version_readme(self):
        sub_dir = "readme.html"
        html_str = "Version (.*)"
        regex = re.compile(html_str)
        
        results = req_and_parse(self.wp, find_type=0, sub_dir=sub_dir, find_str=regex)
        if results:
            return results[0]
        else:
            return False
        