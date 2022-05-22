import os

def clean_cache(dir):
    if not os.path.exists(dir):
        return
    if os.path.isfile(dir):
        os.remove(dir)
    else:
        filelist = os.listdir(dir)
        for f in filelist:
            file_path = os.path.join(dir, f)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                clean_cache(file_path)