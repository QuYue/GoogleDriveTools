# -*- encoding: utf-8 -*-
'''
@Time     :   2025/11/19 17:47:45
@Author   :   QuYue
@File     :   cli.py
@Email    :   quyue1541@gmail.com
@Desc:    :   cli
'''


import argparse
from .core import GoogleDriveTools

def build_parser():
    parser = argparse.ArgumentParser(
        description="Google Drive Upload Tool (CLI)"
    )
    parser.add_argument(
        "-n", "--name", nargs="+", required=True,
        help="One or more local files to upload."
    )
    parser.add_argument(
        "-s", "--save_file_name", nargs="+",
        help="One or more filenames to use in Google Drive. "
             "If omitted, uses local filenames."
    )
    parser.add_argument(
        "-i", "--save_folder_id",
        help="Destination folder ID in Google Drive. "
             "If omitted, uploads to the root directory."
    )
    parser.add_argument(
        "-p", "--proxy",
        help="Proxy server address, e.g., socks5://127.0.0.1:1080. "
             "If omitted, uses proxy from settings.yaml or no proxy."
    )
    parser.add_argument(
        "-c", "--cred",
        help="Path to Google OAuth credentials JSON file. "
             "If omitted, uses the path from settings.yaml."
    )
    parser.add_argument(
        "-l", "--log",
        help="Log file name. If omitted, logs to console or settings.yaml config."
    )
    parser.add_argument(
        "--settings", default="settings.yaml",
        help="Path to settings.yaml. Default: settings.yaml"
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # 初始化类（内部会读 settings.yaml）
    gdt = GoogleDriveTools(settings_path=args.settings)

    # 如果需要，让 CLI 覆盖 settings 里的值：
    if args.proxy:
        gdt.settings.proxy.proxy_server = args.proxy
    if args.cred:
        gdt.settings.google_drive.credentials_file = args.cred
    if args.log:
        gdt.settings.upload.log = args.log

    # 上传文件
    local_files = args.name
    save_names = args.save_file_name
    folder_id = args.save_folder_id

    gdt.upload(
        local_file=local_files,
        save_file_name=save_names,
        folder_id=folder_id,
    )


if __name__ == "__main__":
    main()