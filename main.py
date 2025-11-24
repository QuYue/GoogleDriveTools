from gdrive import GoogleDriveTools

gdtools = GoogleDriveTools()



# 1. 上传
gdtools.upload(local_file="settings.yaml")  # 用 settings.yaml 的其他配置

# 2. 多文件上传
