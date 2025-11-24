# -*- encoding: utf-8 -*-
'''
@Time     :   2025/11/14 15:36:41
@Author   :   QuYue
@File     :   upload.py
@Email    :   quyue1541@gmail.com
@Desc:    :   upload
'''

#%% Import Packages
import os
import sys
import socket
import logging
import argparse
import yaml
import socks
import httplib2
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload


#%% Load Settings
class AttrDict(dict):
    """
    Dictionary that supports attribute-style access and
    recursively wraps nested dicts/lists into AttrDict.
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        # Use our own update so that values get wrapped
        self.update(*args, **kwargs)

    @classmethod
    def _wrap(cls, value):
        """Recursively wrap dicts as AttrDict and lists of dicts as list[AttrDict]."""
        if isinstance(value, dict) and not isinstance(value, AttrDict):
            return cls(value)
        elif isinstance(value, list):
            return [cls._wrap(v) for v in value]
        else:
            return value

    def __setitem__(self, key, value):
        # Ensure any assigned value is wrapped
        super().__setitem__(key, self._wrap(value))

    def update(self, *args, **kwargs):
        other = dict(*args, **kwargs)
        for k, v in other.items():
            self[k] = v

    def __getattr__(self, item):
        # Attribute-style access: obj.x -> obj["x"]
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)

    def __setattr__(self, key, value):
        # Internal attributes (starting with "_") go to the instance dict
        if key.startswith("_"):
            return super().__setattr__(key, value)
        # User-facing attributes go into the dict
        self[key] = value

    def __delattr__(self, key):
        if key.startswith("_"):
            return super().__delattr__(key)
        try:
            del self[key]
        except KeyError:
            raise AttributeError(key)
        

# Load settings from settings.yaml
def load_setting(setting_yaml='settings.yaml'):
    with open(setting_yaml, 'r') as f:
        Parm = yaml.safe_load(f)
    Parm = AttrDict(Parm)
    return Parm

# Load settings by Arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Google Drive Upload Tool Parameters")
    parser.add_argument("-n", "--name", default=None, nargs='+',
        help="The file (or files list) name to upload. Default: None (uses the file from setting.yaml).")
    parser.add_argument("-s", "--save_file_name", default=None, nargs='+',
        help="The file (or files list) name in Google Drive. Default: None (uses the local file name).")
    parser.add_argument("-i", "--save_folder_id", default=None, 
        help="Destination save folder ID in Google Drive. Default: None (uploads to the root directory).")
    parser.add_argument("-p","--proxy", default=None,
        help="Proxy server address, e.g., 127.0.0.1:1080. Default: None (no proxy is applied unless specified in setting.yaml).")
    parser.add_argument("-c", "--cred", default=None,
        help="Path to the Google OAuth credentials JSON file. Default: None (uses the path from setting.yaml).")
    parser.add_argument("-l", "--log", default=None,
        help="Log file name. Default: None (console-only or configured via setting.yaml).")
    return parser.parse_args()

# Merge Settings
def merge_settings(Parm, args):
    if args.name: Parm.upload.local_file = args.name
    if args.save_file_name: Parm.upload.save_file_name = args.save_file_name
    if args.save_folder_id: Parm.upload.save_folder_id = args.save_folder_id
    if args.proxy: Parm.proxy.proxy_server = args.proxy
    if args.cred: Parm.google_drive.credentials_file = args.cred
    if args.log: Parm.upload.log = args.log
    return Parm


#%% Setup Logger
def setup_logger(log_file=None):
    if log_file:
        # Redirect stdout & stderr to log file
        logf = open(log_file, "a", encoding="utf-8")
        sys.stdout = logf
        sys.stderr = logf

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(logf)
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
    return logging.getLogger("gdrive")


#%% Check Credentials File
def check_credentials_file(credentials_path, logger):
    if not os.path.exists(credentials_path):
        logger.error("Credentials file %s not found. \nPlease Download it from Google Cloud Console. \nThen save it to 'Json' folder as credentials.json", credentials_path)
        sys.exit(1)

#%% Setup Proxy
def setup_proxy(proxy_str, logger, default_port=1080, default_type="http"):
    """
    Set proxy
    Supported formats:
        - 127.0.0.1:1080
        - http://127.0.0.1:1080
        - socks5://127.0.0.1:1080
        - socks4://127.0.0.1:1080
        - 127.0.0.1
        - localhost
        - socks5://127.0.0.1
        - http://localhost
    """
    # Clean all environment proxies to avoid interference
    for key in ["HTTP_PROXY","HTTPS_PROXY","NO_PROXY",
                "http_proxy","https_proxy","no_proxy",
                "ALL_PROXY","all_proxy"]:
        os.environ.pop(key, None)
    proxy = proxy_str.strip()

    # Step 1. Extract proxy type / protocol (if provided)
    proxy_type = default_type.lower()
    if "://" in proxy: # e.g. "socks5://****"  or "http://****"
        proto, proxy = proxy.split("://", 1)
        proxy_type = proto.lower()
    # normalize acceptable type values
    if proxy_type not in ["http", "https", "socks", "socks4", "socks5"]:
        proxy_type = default_type
    # "socks" should be treated as "socks5"
    if proxy_type == "socks":
        proxy_type = "socks5"

    # Step 2. Extract host and port
    if ":" in proxy:
        host, port = proxy.split(":", 1)
        port = int(port)
    else:
        host = proxy
        port = default_port  # Auto-fill port if not provided
    logger.info("Set proxy: %s://%s:%s.", proxy_type, host, port)
    SOCKS_MAP = {"http": socks.HTTP, "https": socks.HTTP, "socks4": socks.SOCKS4, "socks5": socks.SOCKS5}
    proxy_info = httplib2.ProxyInfo(proxy_type=SOCKS_MAP[proxy_type], proxy_host=host, proxy_port=port)
    proxy = {'info': proxy_info, 'type': proxy_type, 'host': host, 'port': port}
    
    # Step 3. Set os environment
    if proxy_type == "http":
        os.environ["HTTP_PROXY"]  = f"http://{host}:{port}"
        os.environ["HTTPS_PROXY"] = f"http://{host}:{port}"
    elif proxy_type in ("socks", "socks5"):
        os.environ["ALL_PROXY"] = f"socks5://{host}:{port}"
    elif proxy_type == "socks4":
        os.environ["ALL_PROXY"] = f"socks4://{host}:{port}"
    return proxy

def debug_test_proxy(proxy, logger, oauth_scope):
    logger.info("Testing proxy connectivity via %s://%s:%s ...", proxy['type'], proxy['host'], proxy['port'])
    http = httplib2.Http(timeout=15, proxy_info=proxy['info'])
    try:
        resp, _ = http.request(oauth_scope, "GET")
        logger.info("Received HTTP %s (200/401/403 are OK, means proxy works)", resp.status)
    except Exception as e:
        logger.error("Proxy connectivity test failed: %s", e)
        raise


#%% Get Drive
def get_drive_service(credentials_path="./Json/credentials.json",
                      SCOPES="https://www.googleapis.com/auth/drive.file",
                      token_path="./Json/token.json", save_token=True,
                      proxy=None, logger=None):

    # Step 1. Get OAuth token
    creds = None
    # Load existing OAuth token from token file (if enabled)
    if save_token:
        if os.path.exists(token_path):
            try:
                creds = Credentials.from_authorized_user_file(token_path, SCOPES)
                logger.info("Loaded OAuth token from %s", token_path)
            except Exception as e:
                logger.warning("Failed to load token. Re-authorizing OAuth: %s", e)
                creds = None

    # If no valid credential, attempt refresh or re-authenticate
    if not creds or not creds.valid:
        # Refresh expired token using refresh token
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Token successfully refreshed.")
            except Exception as e:
                logger.error("Failed to refresh token: %s", e)
                creds = None
        # If still no valid credential → re-authorize using credentials.json
        if not creds:
            if not os.path.exists(credentials_path):
                logger.error("Credentials file %s not found. "
                             "Download it from Google Cloud Console.", credentials_path)
                sys.exit(1)

            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            # OAuth requires a local browser to complete authorization
            creds = flow.run_local_server(port=0)
            logger.info("OAuth authorization completed.")

        # Save the newly obtained token
        if save_token:
            with open(token_path, "w") as f:
                f.write(creds.to_json())
                logger.info("Token saved to %s", token_path)

    # # Step 2. Build Http client: with proxy or direct connection
    if proxy:
        # Build a proxy-enabled Http client
        base_http = httplib2.Http(timeout=120, proxy_info=proxy["info"])
        authed_http = AuthorizedHttp(creds, http=base_http)
        logger.info("Using proxy connection: %s://%s:%s", proxy["type"], proxy["host"], proxy["port"])
    else:
        # Build a direct Http client (no proxy)
        base_http = httplib2.Http(timeout=120)
        authed_http = AuthorizedHttp(creds, http=base_http)
        logger.info("Using direct connection.")

    # ---------------------------------------------------------
    # NOTE:
    # Do NOT pass credentials= to build(), only pass http=.
    # The AuthorizedHttp instance already contains the credentials.
    # ---------------------------------------------------------
    service = build(
        "drive",
        "v3",
        http=authed_http,
        cache_discovery=False
    )
    logger.info("Google Drive service initialized successfully.")
    return service


#%% Upload Function 
def upload_file_to_drive(service,
                         local_file,
                         save_file_name=None,
                         save_folder_id=None, 
                         logger=None):
    """
    Upload a file to Google Drive.
    :param service: Authorized Google Drive service instance.
    :param local_file: Path to the local file (list) to upload.
    :param save_file_name: Desired name for the file in Drive. If None, uses the local file's base name.
    :param save_folder_id: ID of the Drive folder to upload into. If None, uploads to the root directory.
    """
    # local_file is list or str
    # if isinstance(local_file, str):
    #     local_file_list = [local_file]
    # else:
    #     local_file_list = local_file

    # If local_file exists
    if not os.path.exists(local_file):
        raise FileNotFoundError(f"Local file not found: {local_file}")
    # Prepare save file
    if save_file_name is None:
        save_file_name = os.path.basename(local_file)
    file_metadata = {"name": save_file_name}
    if save_folder_id:
        file_metadata["parents"] = [save_folder_id]

    # Upload file
    logger.info("Preparing to upload: %s → Drive filename: %s", local_file, save_file_name)
    media = MediaFileUpload(local_file, resumable=True) # can handle large files (resumable upload)
    request = service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id")
    response = None
    while response is None:
        status, response = request.next_chunk()
        if status:
            logger.info("Upload progress: %.2f%%", status.progress() * 100)
    file_id = response.get("id")
    logger.info("Upload completed, file ID: %s", file_id)
    return file_id

def upload_files_to_drive(service,
                         local_file,
                         save_file_name=None,
                         save_folder_id=None, 
                         logger=None):
    """
    Upload a file to Google Drive.
    :param service: Authorized Google Drive service instance.
    :param local_file: Path to the local file (list) to upload.
    :param save_file_name: Desired name for the file in Drive. If None, uses the local file's base name.
    :param save_folder_id: ID of the Drive folder to upload into. If None, uploads to the root directory.
    """
    # To local_file_list 
    if isinstance(local_file, str):
        local_file_list = [local_file]
    else:
        local_file_list = local_file
    
    # To save_file_list
    save_file_list = []
    if save_file_name is None:
        save_file_list = [os.path.basename(f) for f in local_file_list]
    elif isinstance(save_file_name, list):
        save_file_list = save_file_name
    elif isinstance(save_file_name, str):
        save_file_list = [save_file_name] * len(local_file_list)

    # Check
    for local_file in local_file_list:
        # Check local file exists
        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file not found: {local_file}")
    # Check save file name
    if len(save_file_list) != len(local_file_list):
        raise ValueError("Length of save_file_name list must match local_file list.")
    
    # Upload files
    logger.info("Preparing to upload %d files.", len(local_file_list))
    file_id_list = []
    for n in range(len(local_file_list)):
        logger.info("Progress: [ %d / %d ]" , n+1, len(local_file_list))
        local_file = local_file_list[n]
        save_file_name = save_file_list[n]
        file_id = upload_file_to_drive(service, local_file, save_file_name, save_folder_id, logger)
        file_id_list.append(file_id)
    return file_id_list


#%% Run Function
def run():
    Parm = load_setting('settings.yaml')
    args = parse_args()
    Parm = merge_settings(Parm, args)
    logger = setup_logger(Parm.upload.log)
    check_credentials_file(Parm.google_drive.credentials_file, logger)
    proxy = None
    if Parm.proxy.proxy_server:
        proxy = setup_proxy(Parm.proxy.proxy_server, logger)
        debug_test_proxy(proxy, logger, Parm.google_drive.oauth_scope[0])
    drive_service = get_drive_service(credentials_path=Parm.google_drive.credentials_file,
                        SCOPES=Parm.google_drive.oauth_scope[0],
                        token_path=Parm.google_drive.save_token_file,
                        save_token=Parm.google_drive.save_token,
                        proxy=proxy, logger=logger)

    file_id_list = upload_files_to_drive(drive_service,
                            local_file=Parm.upload.local_file,
                            save_file_name=Parm.upload.save_file_name,
                            save_folder_id=Parm.upload.save_folder_id,
                            logger=logger)
    logger.info("All uploads completed")
    

#%% Main
if __name__ == "__main__":
    run()
