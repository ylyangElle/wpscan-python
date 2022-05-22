import os
import re
from urllib.request import *
from urllib.error import HTTPError
import json

from AuxiliaryModule.clean_cache import *
from AuxiliaryModule.http_req import *

class ThemeScan:
    def __init__(self, wp_info) -> None:
        self.wp = wp_info
        self.cache_dir = r"AuxiliaryModule/caches"
        self.themes_json = r"database/vulnerability/themes.json"
        self.target_vuln_themes = r"AuxiliaryModule\caches\plugin_theme_version\has_vuln_themes.json"

        
        clean_cache(self.target_vuln_themes)

        self.themes_scan_from_index()

        self.themes_scan_from_wp_dir()
        
        
    def __find_vuln_of_themes(self):
        with open(self.themes_json, "r") as f:
            vuln_themes = json.load(f)
            
        wp_has_themes_vuln = {}
        
        for themes_name in self.wp.themes.keys():
            for vuln_themes_name in vuln_themes.keys():
                if themes_name in vuln_themes_name or vuln_themes_name in themes_name:
                    for ver_vuln in vuln_themes[vuln_themes_name]:
                        if ver_vuln in self.wp.themes[themes_name]:
                            #存储目标中存在漏洞的themes名、版本以及对应的exp
                            if vuln_themes_name in wp_has_themes_vuln.keys():
                                wp_has_themes_vuln[vuln_themes_name].append(ver_vuln)
                            else:
                                wp_has_themes_vuln[vuln_themes_name] = [ver_vuln]

                            self.wp.exps["theme"].append(vuln_themes[vuln_themes_name][ver_vuln])
               
        with open(self.target_vuln_themes, "w") as f:                            
            json.dump(wp_has_themes_vuln, f)
            
        self.wp.vuln_themes = wp_has_themes_vuln   
                             
    def __themes_dict_combine(self, new_themes):
        
        for key, value in new_themes.items():
            wp_theme_dir = urljoin("wp-content/themes", key)
            self.wp.dirs.append(wp_theme_dir)
            
            if key not in self.wp.themes.keys():
                self.wp.themes[key] = value
            else:
                self.wp.themes[key].append(value)
                
    def themes_scan_from_index(self):
        #解析index.php，提取其中的插件名
        regex = re.compile("\/wp-content\/themes\/(.*?)/.*?.[js|css]?[v|ver]=(.*?)\'")   
        themes_name_and_version = req_and_parse(self.wp, find_type = 0, sub_dir = "index.php", find_str=regex)
        
        if not themes_name_and_version:
            return
        
        #将插件名加到wp_dirs.txt以及wp_themes.txt中
        themes = {}
        for theme, ver in themes_name_and_version:
            if theme not in themes.keys():
                themes[theme] = [ver]
            else:
                themes[theme].append(ver)
        #存储themes信息到wp中
        self.__themes_dict_combine(themes)
        self.__find_vuln_of_themes()

    def __lower_and_join_the_theme_name(self, key):
        if " " in key:
            key = key.replace(" ", "-")
        return key.lower()
    
    def themes_scan_from_wp_dir(self):
        #读themes database
        with open(self.themes_json, "r") as f:
            themes = json.load(f)
        #将官方的插件名拼接到url中，访问，如果存在，加到wp_dirs.txt以及wp_themes.txt中

        themes_new = {}
        for key in themes.keys():
            
            key_url = self.__lower_and_join_the_theme_name(key)
            wp_theme_dir = "wp-content/themes/" + key_url
            
            if not http_request(self.wp, sub_dir=wp_theme_dir):
                continue
            else:    
                
                #通过wp-content/themes/key/readme.txt找插件的版本信息
                regex = re.compile(r"== Changelog ==\n\n= (.*?) =")
                ver_from_readme = req_and_parse(self.wp, find_type=0, sub_dir=wp_theme_dir+"/readme.txt", find_str=regex)
                ver_from_readme = ver_from_readme[0]
                #存储当前存在漏洞的theme的信息
                #{name: version}
                themes_new[key] = ver_from_readme
                if ver_from_readme in themes[key].keys():
                    self.wp.exps["theme"].append(themes[key][ver_from_readme]["exp_dir"])
                    
        
        #将各种信息存在wp中
        self.__themes_dict_combine(themes_new)
        self.wp.vuln_themes = self.wp.vuln_themes | themes_new
                
        #输出可能存在的漏洞
        
