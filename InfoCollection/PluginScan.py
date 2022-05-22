import os
import re
from urllib.request import *
from urllib.error import HTTPError
import json

from AuxiliaryModule.clean_cache import *
from AuxiliaryModule.http_req import *

class PluginScan:
    def __init__(self, wp_info) -> None:
        self.wp = wp_info
        self.cache_dir = r"AuxiliaryModule/caches"
        self.plugins_json = r"database/vulnerability/plugins.json"
        self.target_vuln_plugins = r"AuxiliaryModule\caches\plugin_theme_version\has_vuln_plugins.json"

        
        clean_cache(self.target_vuln_plugins)

        self.plugins_scan_from_index()

        self.plugins_scan_from_wp_dir()
        
        
        
    def __find_vuln_of_plugins(self):
        with open(self.plugins_json, "r") as f:
            vuln_plugins = json.load(f)
            
        wp_has_plugins_vuln = {}
        
        for plugins_name in self.wp.plugins.keys():
            for vuln_plugins_name in vuln_plugins.keys():
                if plugins_name in vuln_plugins_name or vuln_plugins_name in plugins_name:
                    for ver_vuln in vuln_plugins[vuln_plugins_name]:
                        if ver_vuln in self.wp.plugins[plugins_name]:
                            #存储目标中存在漏洞的plugins名、版本以及对应的exp
                            if vuln_plugins_name in wp_has_plugins_vuln.keys():
                                wp_has_plugins_vuln[vuln_plugins_name].append(ver_vuln)
                            else:
                                wp_has_plugins_vuln[vuln_plugins_name] = [ver_vuln]

                            self.wp.exps["plugin"].append(vuln_plugins[vuln_plugins_name][ver_vuln])
      
        with open(self.target_vuln_plugins, "w") as f:                            
            json.dump(wp_has_plugins_vuln, f)
            
        self.wp.vuln_plugins = wp_has_plugins_vuln   
                             
    def __plugins_dict_combine(self, new_plugins):
        
        for key, value in new_plugins.items():
            wp_plugin_dir = urljoin("wp-content/plugins", key)
            self.wp.dirs.append(wp_plugin_dir)
            
            if key not in self.wp.plugins.keys():
                self.wp.plugins[key] = value
            else:
                self.wp.plugins[key].append(value)
                
    def plugins_scan_from_index(self):
        #解析index.php，提取其中的插件名
        regex = re.compile("\/wp-content\/plugins\/(.*?)/.*?.[js|css]?[v|ver]=(.*?)\'")   
        plugins_name_and_version = req_and_parse(self.wp, find_type = 0, sub_dir = "index.php", find_str=regex)
        
        if not plugins_name_and_version:
            return
        
        #将插件名加到wp_dirs.txt以及wp_plugins.txt中
        plugins = {}
        for plugin, ver in plugins_name_and_version:
            if plugin not in plugins.keys():
                plugins[plugin] = [ver]
            else:
                plugins[plugin].append(ver)
        #存储plugins信息到wp中
        self.__plugins_dict_combine(plugins)
        self.__find_vuln_of_plugins()

    def __lower_and_join_the_plugin_name(self, key):
        if " " in key:
            key = key.replace(" ", "-")
        return key.lower()
    
    def plugins_scan_from_wp_dir(self):
        #读plugins database
        with open(self.plugins_json, "r") as f:
            plugins = json.load(f)
        #将官方的插件名拼接到url中，访问，如果存在，加到wp_dirs.txt以及wp_plugins.txt中

        plugins_new = {}
        for key in plugins.keys():
            
            key_url = self.__lower_and_join_the_plugin_name(key)
            wp_plugin_dir = "wp-content/plugins/" + key_url
            
            if not http_request(self.wp, sub_dir=wp_plugin_dir):
                continue
            else:    
                
                #通过wp-content/plugins/key/readme.txt找插件的版本信息
                regex = re.compile(r"== Changelog ==\n\n= (.*?) =")
                ver_from_readme = req_and_parse(self.wp, find_type=0, sub_dir=wp_plugin_dir+"/readme.txt", find_str=regex)
                ver_from_readme = ver_from_readme[0]
                #存储当前存在漏洞的plugin的信息
                #{name: version}
                plugins_new[key] = ver_from_readme
                if ver_from_readme in plugins[key].keys():
                    self.wp.exps["plugin"].append(plugins[key][ver_from_readme]["exp_dir"])
                    
        
        #将各种信息存在wp中
        self.__plugins_dict_combine(plugins_new)
        self.wp.vuln_plugins = self.wp.vuln_plugins | plugins_new
                
        #输出可能存在的漏洞
        
