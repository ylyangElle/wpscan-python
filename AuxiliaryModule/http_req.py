import os
from re import sub
from urllib.error import HTTPError
from urllib.request import urlopen
from urllib.parse import urljoin
from bs4 import BeautifulSoup

user_agent = {'User-Agent': \
    'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_5; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Chrome/9.0.597.15 Safari/534.13'
    }
#urlopen怎样添加代理
def http_request(wp, sub_dir = None, headers = user_agent):
    try:
        #req = urlopen(urljoin(wp.basic_url, sub_dir), headers = headers)

        req = urlopen(urljoin(wp.basic_url, sub_dir))
        if sub_dir is not None:
            wp.dirs.append(sub_dir)
        return [req.code, req.read().decode('utf-8', 'ignore')]
    except HTTPError as e:
        if e.code == 404:
            return False
        else:
            return [e.code, "None"]
          
def resp_parse(res_text, find_type, find_label=None, limit_attrs=None, find_attrs=None, find_str=None):
    if find_type == 1 and find_label is not None and limit_attrs is not None and find_attrs is not None:
        soup = BeautifulSoup(res_text, "html.parser", from_encoding='utf-8')
        elements = soup.find_all(find_label, limit_attrs)
        results = []        
        for e in elements:
            results.append(e.attrs[find_attrs])
        return results
    elif find_type == 0 and find_str is not None:
        matches = find_str.findall(res_text)
        if len(matches) > 0 and matches[0] is not None and matches[0] != "":
            return matches

def req_and_parse(wp, find_type, headers=user_agent, sub_dir=None, find_label=None, limit_attrs=None, find_attrs=None, find_str=None):
    #cache_path = os.path.join(os.getcwd(), 'AuxiliaryModule\caches')
    #cache_file_name = sub_dir.split(".")[0] + ".txt"
    cache_path = r"AuxiliaryModule\caches"
    cache_sub_dir_path = os.path.join(cache_path, sub_dir.replace("/", "-"))

    if os.path.exists(cache_sub_dir_path):
        with open(cache_sub_dir_path, encoding='utf-8') as f:
            res_text = f.read()
    else:  
        #os.makedirs(cache_sub_dir_path)
        res = http_request(wp, sub_dir=sub_dir, headers=headers)
        if res:
            res_text = res[1]
            #print(res_text)
            with open(cache_sub_dir_path, "w", encoding='utf-8') as f:
                f.write(res_text)
        else:
            return None
    results = resp_parse(res_text, find_label=find_label, limit_attrs=limit_attrs, find_type=find_type, find_str=find_str, find_attrs=find_attrs)
    return results
            