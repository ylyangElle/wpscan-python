class WpInfo:
    basic_url = ""
    dirs = [] #网站目录
    wp_version = "0.0.0"
    plugins = {}
    themes = {}
    users = {}
    
    vuln_plugins = {}
    vuln_themes = {}
    exps = {
        "wp_version": [],
        "theme": [],
        "plugin": []
    }
    
    def __init__(self, url) -> None:
        self.basic_url = url
    def output(self):
        print("******************************************")
        print(self.wp_version)
        print(self.plugins)
        print(self.vuln_plugins)
        print(self.themes)
        print(self.vuln_themes)
        print(self.exps)

        
    