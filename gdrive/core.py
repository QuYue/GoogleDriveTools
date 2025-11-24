# -*- encoding: utf-8 -*-
'''
@Time     :   2025/11/18 17:26:53
@Author   :   QuYue
@File     :   core.py
@Email    :   quyue1541@gmail.com
@Desc:    :   core
'''

#%% Import Packages
# Basic
import os
import sys
import io
import logging
import socket
import yaml
import socks
import httplib2

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

# Self-defined
from .utils import AttrDict, parse_proxy


#%% GoogleDriveTools
class GoogleDriveTools:
    """
    High-level wrapper around Google Drive API for uploading and downloading
    files using settings.yaml and optional proxy.
    """

    def __init__(self, settings_path: str = "settings.yaml"):
        self.settings = self.load_settings(settings_path, inplaces=False)
        self.logger = self.setup_logger(self.settings.upload.log, inplaces=False)
        
        # Proxy
        socket.setdefaulttimeout(60)
        self.set_proxy(self.settings.proxy.proxy_server)

        # Build Drive service
        self.service = self._build_drive_service()

    def set_proxy(self, proxy_str: str | None):
        # Set up proxy for HTTP requests
        # step 1. clear all environment proxies to avoid interference
        for key in [
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "no_proxy",
            "ALL_PROXY", "all_proxy"]:
            os.environ.pop(key, None)
        # step 2. Set proxy from settings
        proxy_str = self.settings.proxy.proxy_server
        self.proxy = None
        if proxy_str:
            self.proxy = self._build_proxy_info(proxy_str)
            if self.proxy:
                # step 3. Set os environment
                if self.proxy['ptype'] in ("http", "https"):
                    os.environ["HTTP_PROXY"]  = f"http://{self.proxy['host']}:{self.proxy['port']}"
                    os.environ["HTTPS_PROXY"] = f"http://{self.proxy['host']}:{self.proxy['port']}"
                elif self.proxy['ptype'] in ("socks", "socks5"):
                    os.environ["ALL_PROXY"] = f"socks5://{self.proxy['host']}:{self.proxy['port']}"
                elif self.proxy['ptype'] == "socks4":
                    os.environ["ALL_PROXY"] = f"socks4://{self.proxy['host']}:{self.proxy['port']}"
                self.logger.info("Using proxy %s://%s:%s",
                                self.proxy["ptype"], self.proxy["host"], self.proxy["port"])
        else:
            self.logger.info("No proxy configured. Using direct connection.")
        
    def load_settings(self, path: str, inplaces: bool = True) -> AttrDict:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if inplaces:
            self.settings = AttrDict(data)
            return self.settings
        else:
            return AttrDict(data)
        
    def setup_logger(self, log_file=None, inplaces=True) -> logging.Logger:
        logger = logging.getLogger("gdrive")
        logger.setLevel(logging.INFO)

        # Avoid duplicate handlers if setup_logger is called multiple times
        if logger.handlers:
            if inplaces:
                self.logger = logger
                return self.logger
            else:
                return logger
        # Handlers
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        if log_file:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            # Redirect stdout & stderr to log file
            logf = open(log_file, "a", encoding="utf-8")
            sys.stdout = logf
            sys.stderr = logf
        else:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(formatter)
            logger.addHandler(sh)
        if inplaces:
            self.logger = logger
            return self.logger
        else:
            return logger
        
    def _build_proxy_info(proxy_str: str | None):
        # Build httplib2.ProxyInfo from proxy_str
        if not proxy_str:
            return None

        SOCKS_MAP = {
            "http": socks.HTTP,
            "https": socks.HTTP,
            "socks4": socks.SOCKS4,
            "socks5": socks.SOCKS5,
        }
        ptype, host, port = parse_proxy(proxy_str)
        proxy_type = SOCKS_MAP.get(ptype, socks.HTTP)

        info = httplib2.ProxyInfo(
            proxy_type=proxy_type,
            proxy_host=host,
            proxy_port=port)
        
        return {
            "ptype": ptype,
            "host": host,
            "port": port,
            "info": info,
        }

    def _build_drive_service(self):
        # Build Google Drive API service
        # step 1. Load settings
        gd = self.settings.google_drive
        scopes = gd.oauth_scope
        credentials_path = gd.credentials_file
        token_path = gd.save_token_file
        save_token = bool(gd.save_token)
        creds = None

        # step 2. Get OAuth token
        # load existing OAuth token from token file (if enabled)
        if save_token and os.path.exists(token_path):
            try:
                creds = Credentials.from_authorized_user_file(token_path, scopes)
                self.logger.info("Loaded token from %s", token_path)
            except Exception as e:
                self.logger.warning("Failed to load token, will re-auth: %s", e)
                creds = None

        # if no valid credential, attempt refresh or re-authenticate
        if not creds or not creds.valid:
            #  refresh token 
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    self.logger.info("Token refreshed successfully.")
                except Exception as e:
                    self.logger.error("Token refresh failed: %s", e)
                    creds = None
            # re-authorize using credentials.json
            if not creds:
                if not os.path.exists(credentials_path):
                    self.logger.error(
                        "Credentials file %s not found. "
                        "Download it from Google Cloud Console.", credentials_path)
                    raise FileNotFoundError(credentials_path)
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
                creds = flow.run_local_server(port=0)
                self.logger.info("OAuth authorization completed.")

            # Save the token for the next run
            if save_token:
                with open(token_path, "w", encoding="utf-8") as f:
                    f.write(creds.to_json())
                self.logger.info("Token saved to %s", token_path)

        # step 3. Build HTTP client: with or without proxy
        if self.proxy:
            base_http = httplib2.Http(timeout=120, proxy_info=self.proxy["info"])
            self.logger.info("Using proxy connection: %s://%s:%s.",
                            self.proxy["ptype"], self.proxy["host"], self.proxy["port"])
        else:
            base_http = httplib2.Http(timeout=120)
            self.logger.info("Using direct connection.")
        authed_http = AuthorizedHttp(creds, http=base_http)

        service = build("drive", "v3", http=authed_http, cache_discovery=False)
        self.logger.info("Google Drive service initialized.")
        return service

    # ---------- public: upload ----------
    def upload(self,
               local_file=None,
               save_file_name=None,
               folder_id=None) -> list[tuple[str, str]]:
        """
        Upload one or multiple files to Google Drive.
        Parameters
        ----------
        local_file : str or list[str] or None
            Path or list of paths. If None, use settings.upload.local_file.
        save_file_name : str or list[str] or None
            Name(s) to use on Drive. If None, use local filenames.
        folder_id : str or None
            Drive folder ID. If None, upload to root or settings.upload.save_folder_id.

        Returns 
        -------
        List of (local_path, file_id)
        """
        # Defaults from settings
        if local_file is None:
            local_file = self.settings.upload.local_file
        if folder_id is None:
            folder_id = self.settings.upload.save_folder_id
        if save_file_name is None:
            save_file_name = self.settings.upload.save_file_name

        # Normalize to list (local_file)
        if isinstance(local_file, (str, os.PathLike)):
            local_files_list = [str(local_file)]
        else:
            local_files_list = list(local_file)

        # Normalize to list (save_file_name)
        if save_file_name is None:
            save_names_list =  [os.path.basename(f) for f in local_files_list]
        elif isinstance(save_file_name, (str, os.PathLike)):
            save_names_list = [str(save_file_name)]
        else:
            save_names_list = list(save_file_name)

        # Check
        # Check save names length
        if len(save_names_list) != len(local_files_list):
            raise ValueError("save_file_name must be None, or a list of the same length as local_file.")
        # Check local files exist
        for local_files in local_files_list:
            if not os.path.exists(local_files):
                raise FileNotFoundError(f"Local file not found: {local_file}")

        # Upload files
        results = []
        for n in range(len(local_files_list)):
            self.logger.info("Upload Progress: [ %d / %d ]", n+1, len(local_files_list))
            local_file = local_files_list[n]
            save_file_name = save_names_list[n]
            file_id = self._upload_single(local_file, save_file_name, folder_id)
            results.append((local_file, file_id))
        return results

    def _upload_single(self, 
                       local_file: str,
                       save_file_name: str | None,
                       folder_id: str | None) -> str:
        # If local_file exists
        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file not found: {local_file}")
        # Prepare save file
        if save_file_name is None:
            save_file_name = os.path.basename(local_file)
        file_metadata = {"name": save_file_name}
        if folder_id:
            file_metadata["parents"] = [folder_id]
        
        # Upload file
        media = MediaFileUpload(local_file, resumable=True)
        self.logger.info("Uploading %s -> %s ...", local_file, save_file_name)
        request = self.service.files().create(
            body=file_metadata,
            media_body=media,
            fields="id",
        )
        response = None
        while response is None:
            status, response = request.next_chunk()
            if status:
                self.logger.info("Uploading file: %.2f%%",  status.progress() * 100)
        file_id = response.get("id")
        self.logger.info("Upload finished. File Id=%s", file_id)
        return file_id

    # ---------- public: download ----------
    def download(self,
                 file_id: str | list[str] | None = None,
                 save_local_dir: str | None = None) -> list[str]:
        """
        Download one or multiple files from Google Drive.

        Parameters
        ----------
        file_id : str or list[str] or None
            One file ID or a list of file IDs. If None, use settings.download.file_id.
        save_local_dir : str or list[str] or None
            Local directory to save file(s). If None, use current working directory.

        Returns
        -------
        list[str]
            A list of local file paths of the downloaded files.
        """
        # Defaults from settings
        if file_id is None:
            try:
                file_id = self.settings.download.file_id
            except Exception:
                raise ValueError("file_id is None and settings.download.file_id not found.")
        if save_local_dir is None:
            save_local_dir = self.settings.download.save_local_dir

        # Normalize file_id to list
        if isinstance(file_id, str):
            file_id_list = [file_id]
        else:
            file_id_list = list(file_id)

        # Check
        # Check save_local_dir exists
        if (save_local_dir is not None) and (not os.path.exists(save_local_dir)):
            os.makedirs(save_local_dir, exist_ok=True)

        # Download files
        results = []
        for n in range(len(file_id_list)):
            self.logger.info("Download Progress: [ %d / %d ]", n+1, len(file_id_list))
            file_id = file_id_list[n]
            local_path = self._download_single(file_id, save_local_dir)
            results.append(local_path)
        return results
    
    def _download_single(self,
                         file_id: str,
                         save_local_dir: str | None = None) -> str:
        # Check file exists on Drive 
        try:
            meta = self.service.files().get(fileId=file_id, fields="name").execute()
        except Exception as e:
            self.logger.error("Failed to get metadata for file_id=%s: %s", file_id, e)
            return None

        if not meta:
            self.logger.error("File ID %s not found on Google Drive.", file_id)
            return None
        
        # Prepare 
        file_name = meta.get("name", file_id)
        local_path = os.path.join(save_local_dir, file_name)

        # Download file
        try:
            request = self.service.files().get_media(fileId=file_id)
            with io.FileIO(local_path, "wb") as fh:
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                    if status:
                        self.logger.info(
                            "Downloading file: %.2f%%",
                            status.progress() * 100,
                        )
        except Exception as e:
            self.logger.error("Download failed for file_id=%s: %s", file_id, e)
            # If download fails, it may leave an incomplete/empty file, which can be optionally removed
            try:
                if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                    os.remove(local_path)
            except Exception:
                pass
            return None
        self.logger.info("Download finished: %s", local_path)
        return local_path


