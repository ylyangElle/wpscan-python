import os
import re
from urllib.request import *
from urllib.error import HTTPError
import json

from AuxiliaryModule.clean_cache import *
from AuxiliaryModule.http_req import *

class ContentScan:
    #index: plugin or theme
    def __init__(self, wp_info, index) -> None:
        self.wp = wp_info
        self.index = index
        self.cache_dir = r"AuxiliaryModule/caches"
        self.contents_json = r"database/vulnerability/{0}s.json".format(index)
        self.target_vuln_contents = r"AuxiliaryModule\caches\{0}_theme_version\has_vuln_{1}s.json".format(index, index)

        
        clean_cache(self.target_vuln_contents)

        self.contents_scan_from_index()

        self.contents_scan_from_wp_dir()
        
        
    def __find_vuln_of_contents(self):
        with open(self.contents_json, "r") as f:
            vuln_contents = json.load(f)
            
        wp_has_contents_vuln = {}
        
        for contents_name in self.wp.contents.keys():
            for vuln_contents_name in vuln_contents.keys():
                if contents_name in vuln_contents_name or vuln_contents_name in contents_name:
                    for ver_vuln in vuln_contents[vuln_contents_name]:
                        if ver_vuln in self.wp.contents[contents_name]:
                            #存储目标中存在漏洞的contents名、版本以及对应的exp
                            if vuln_contents_name in wp_has_contents_vuln.keys():
                                wp_has_contents_vuln[vuln_contents_name].append(ver_vuln)
                            else:
                                wp_has_contents_vuln[vuln_contents_name] = [ver_vuln]

                            self.wp.exps[self.index].append(vuln_contents[vuln_contents_name][ver_vuln])
               
        with open(self.target_vuln_contents, "w") as f:                            
            json.dump(wp_has_contents_vuln, f)
            
        self.wp.vuln_contents = wp_has_contents_vuln   
                             
    def __contents_dict_combine(self, new_contents):
        
        if self.index == "plugin":
            for key, value in new_contents.items():
                wp_content_dir = urljoin("wp-content/{}".format(self.index), key)
                self.wp.dirs.append(wp_content_dir)
                
                if key not in self.wp.plugins.keys():
                    self.wp.plugins[key] = value
                else:
                    self.wp.plugins[key].append(value)
        elif self.index == "theme":
            for key, value in new_contents.items():
                wp_content_dir = urljoin("wp-content/{}".format(self.index), key)
                self.wp.dirs.append(wp_content_dir)
                
                if key not in self.wp.themes.keys():
                    self.wp.themes[key] = value
                else:
                    self.wp.themes[key].append(value)
                
    def contents_scan_from_index(self):
        #解析index.php，提取其中的插件名
        regex = re.compile("\/wp-content\/{}s\/(.*?)/.*?.[js|css]?[v|ver]=(.*?)\"".format(self.index))   
        contents_name_and_version = req_and_parse(self.wp, find_type = 0, sub_dir = "index.php", find_str=regex)
        
        if not contents_name_and_version:
            return
        
        #将插件名加到wp_dirs.txt以及wp_contents.txt中
        contents = {}
        for content, ver in contents_name_and_version:
            if content not in contents.keys():
                contents[content] = [ver]
            else:
                contents[content].append(ver)
        #存储contents信息到wp中
        self.__contents_dict_combine(contents)
        self.__find_vuln_of_contents()

    def __lower_and_join_the_content_name(self, key):
        if " " in key:
            key = key.replace(" ", "-")
        return key.lower()
    
    def contents_scan_from_wp_dir(self):
        #读contents database
        with open(self.contents_json, "r") as f:
            contents = json.load(f)
        #将官方的插件名拼接到url中，访问，如果存在，加到wp_dirs.txt以及wp_contents.txt中

        contents_new = {}
        for key in contents.keys():
            
            key_url = self.__lower_and_join_the_content_name(key)
            wp_content_dir = "wp-content/{}s/".format(self.index) + key_url
            
            if not http_request(self.wp, sub_dir=wp_content_dir):
                continue
            else:    
                
                #通过wp-content/contents/key/readme.txt找插件的版本信息
                regex = re.compile(r"== Changelog ==\n\n= (.*?) =")
                ver_from_readme = req_and_parse(self.wp, find_type=0, sub_dir=wp_content_dir+"/readme.txt", find_str=regex)
                ver_from_readme = ver_from_readme[0]
                #存储当前存在漏洞的content的信息
                #{name: version}
                contents_new[key] = ver_from_readme
                if ver_from_readme in contents[key].keys():
                    self.wp.exps[self.index].append(contents[key][ver_from_readme]["exp_dir"])
                    
        
        #将各种信息存在wp中
        self.__contents_dict_combine(contents_new)
        self.wp.vuln_contents = self.wp.vuln_contents | contents_new
                
        #输出可能存在的漏洞
        return
