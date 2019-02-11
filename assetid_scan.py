import argparse
import datetime
import difflib
import glob
import hashlib
import re
import requests
import os
import pathlib
import sys
import shutil
import tarfile
import tempfile

import git

asset_cache = {}
def get_asset(asset_path):
    if asset_path in asset_cache:
        return asset_cache[asset_path]

    # Fetch the asset data
    if re.match("^https?://", asset):
        r = requests.get(asset)
        # Github uses UTF-8 encoding, check others
        r.encoding = "UTF-8"
        if r.status_code == 200:
            asset_data = r.text
        else:
            raise Exception("Unable to obtain asset from {} code {}".format(asset, r.status_code))
    elif os.path.isfile(asset):
        if not os.path.isfile(asset):
            raise Exception("Asset '{}' does not exist".format(asset))
        with open(asset, "rb") as f:
            asset_data = f.read().decode("UTF-8")

    asset_cache[asset_path] = asset_data
    return asset_data

class CodeBase:
    def __init__(self, path, use_cache=True):
        self.path = path
        self.use_cache = use_cache
        self.saved_path = self.get_file()
        self.dir_listing = None

    def get_file(self):
        if os.path.exists(self.path):
            return self.path

        assetid_directory = os.path.join(pathlib.Path.home(), ".assetid_scan")
        file_directory = os.path.join(assetid_directory, hashlib.sha256(self.path.encode()).hexdigest())
        os.makedirs(file_directory, exist_ok=True)

        if self.use_cache:
            # print("Checking cache for '{}'".format(file_directory))
            match = glob.glob(os.path.join(file_directory, "blob.*"))
            if len(match) > 0:
                return match[0]

        # Extract the extension
        if self.path.endswith(".tar.gz"):
            file_extension = ".tar.gz"
        else:
            _, file_extension = os.path.splitext(self.path)
        file_path = os.path.join(file_directory, "blob{}".format(file_extension))


        with open(os.path.join(file_directory, "path.txt"), "w") as f:
            f.write(self.path)

        print("Downloading '{}'".format(self.path))
        r = requests.get(self.path, stream=True)
        if r.status_code == 200:
            r.raw.decode_content = True

            if r.headers.get("content-disposition", None) is not None:
                header = r.headers["content-disposition"]
                if "filename=" in header:
                    _file_path = header.split("filename=")[1]
                    # Extract the extension
                    if _file_path.endswith(".tar.gz"):
                        file_extension = ".tar.gz"
                    else:
                        _, file_extension = os.path.spliext(_file_path)
                    file_path = os.path.join(file_directory, "blob{}".format(file_extension))

            print("Saving to '{}'".format(file_path))
            with open(file_path, "wb") as f:
                shutil.copyfileobj(r.raw, f)
            return file_path
        raise Exception("Unable to obtain file from {} code {}".format(self.path, r.status_code))

    def list_files(self):
        paths = []
        if not os.path.isdir(self.saved_path):
            raise Exception("'{}' is not a directory".format(self.saved_path))
        for root, subdirs, files in os.walk(self.saved_path):
            for file in files:
                paths.append(os.path.join(root.replace(self.saved_path, ""), file))
        return paths

    def find_file(self, asset_path):
        # Delay population of the directory listing until it is actually used
        if self.dir_listing is None:
            self.dir_listing = {}
            for path in self.list_files():
                lookup = os.path.basename(path)
                self.dir_listing.setdefault(lookup, []).append(path)


        pathid_parts = asset_path.split("/")
        dir_listing = self.dir_listing.get(os.path.basename(asset_path), [])
        for i in range(1, len(pathid_parts) + 1):
            possible_path = "/{}".format(os.path.join(*pathid_parts[i * -1:]))
            possible_paths = [x for x in dir_listing if x.endswith(possible_path)]
            if len(possible_paths) == 1:
                found_asset_path = possible_paths[0]
                break
            elif len(possible_paths) == 0:
                if i > 1:
                    possible_path = os.path.join(*pathid_parts[(i - 1) * -1:])
                    possible_paths = [x for x in dir_listing if possible_path in x]
                    if len(possible_paths) > 3:
                        possible_paths = possible_paths[:3] + ["..."]
                    raise Exception("Ambiguous path {} matches [{}]. Use {}:<translated path> to specify the intended repository path.".format(asset_path, ",".join(possible_paths), asset_path))
                break
        if found_asset_path is None:
            raise Exception("Path not found '{}'. Use {}:<translated path> to specify the intended repository path.".format(asset_path, asset_path))
        return found_asset_path

    def compare(self, asset, codebase_path):
        asset_data = get_asset(asset)
        with open(codebase_path) as f:
            codebase_data = f.read()
        ratio = difflib.SequenceMatcher(None, asset_data, codebase_data).quick_ratio()
        print("{}:{} [{}]".format(asset, codebase_path, ratio))
        return ratio


class TarCodeBase(CodeBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tarfile = None

    def list_files(self):
        paths = []
        if not os.path.isfile(self.saved_path) and not any(self.saved_path.endswith(x) for x in [".tar", ".tar.gz", ".tgz"]):
            raise Exception("'{}' is not a tar archive".format(self.saved_path))
        with tarfile.open(self.saved_path, "r:*") as f:
            for member in f.getmembers():
                if member.isfile():
                    paths.append(member.name)
        return paths

    def compare(self, asset, codebase_path):
        asset_data = get_asset(asset)

        if self.tarfile is None:
            self.tarfile = tarfile.open(self.saved_path, "r:*")

        member = self.tarfile.getmember(codebase_path)
        codebase_data = self.tarfile.extractfile(member).read().decode("UTF-8")

        ratio = 1 if asset_data == codebase_data else difflib.SequenceMatcher(None, asset_data, codebase_data).quick_ratio()
        print("{}:{} [{}]".format(asset, codebase_path, ratio))
        return ratio

class GitCodeBase(CodeBase):
    def get_file(self):
        if os.path.exists(self.path):
            if not os.path.isdir(os.path.join(self.path, ".git")):
                raise Exception("Not a valid git repository '{}'".format(self.path))
            return self.path

        assetid_directory = os.path.join(pathlib.Path.home(), ".assetid_scan")
        file_directory = os.path.join(assetid_directory, hashlib.sha256(self.path.encode()).hexdigest())
        os.makedirs(file_directory, exist_ok=True)

        if self.use_cache:
            if os.path.isdir(os.path.join(file_directory, ".git")):
                return file_directory

        print("Cloning '{}' to '{}'".format(self.path, file_directory))
        git.Repo.clone_from(self.path, file_directory)
        print("Git clone complete")
        return file_directory

    def compare(self, asset, codebase_path):
        repo = git.Repo(codebase.saved_path)
        tags = sorted(repo.tags, key=lambda x: x.commit.committed_date)

        asset_data = get_asset(asset)
        asset_data_striped = asset_data.rstrip("\n")

        # Standardise the codebase_path
        if codebase_path.startswith("/"):
            codebase_path = ".{}".format(codebase_path)

        asset_ratio = 0
        asset_commit = None
        asset_next_commit = "HEAD"

        commits = list(repo.iter_commits(paths=[codebase_path]))
        next_commit = "HEAD"
        print("Processing {} at {}, {} commits...".format(asset, codebase_path, len(commits)))
        for commit in commits:
            asset_history_data = repo.git.show("{}:{}".format(commit, codebase_path))

            commit_ratio = 1 if asset_data == asset_history_data or asset_data_striped == asset_history_data else difflib.SequenceMatcher(None, asset_data, asset_history_data).quick_ratio()
            if commit_ratio > asset_ratio:
                asset_ratio = commit_ratio
                asset_commit = commit
                asset_next_commit = next_commit

            next_commit = commit


        if asset_ratio < 0.6:
            print("Only weak match found.")
        print("{}: {} created {} - {} ".format(asset_commit, asset_ratio, datetime.datetime.utcfromtimestamp(asset_commit.committed_date).isoformat(), datetime.datetime.utcfromtimestamp(asset_next_commit.committed_date).isoformat()))

        # List all tags tied to a commit which is greater than the
        if len(tags):
            for tag in tags:
                if tag.commit.committed_date < asset_commit.committed_date:
                    continue
                print(tag, datetime.datetime.utcfromtimestamp(tag.commit.committed_date).isoformat())

        return asset_ratio


# TODO: Zip


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AssetId Scanner")
    parser.add_argument("--code", "-c", type=str, action="append", help="the code base to work on")
    # parser.add_argument("--branch", "-b", type=str, default="master")
    parser.add_argument("assets", nargs="*")

    args = parser.parse_args()

    codebases = []
    for codebase in args.code:
        if os.path.isdir(codebase):
            if os.path.isdir(os.path.join(codebase, ".git")):
                codebases.append(GitCodeBase(codebase))
            else:
                codebases.append(CodeBase(codebase))
        elif codebase.startswith("git@") or codebase.endswith(".git"):
            codebases.append(GitCodeBase(codebase))
        elif any(codebase.endswith(x) for x in [".tar", ".tar.gz", ".tgz"]):
            codebases.append(TarCodeBase(codebase))
        else:
            # See if when the code base is acquired we end up with a better idea of it's type
            c = CodeBase(codebase)
            if any(c.saved_path.endswith(x) for x in [".tar", ".tar.gz", ".tgz"]):
                codebases.append(TarCodeBase(codebase))
            else:
                codebases.append(c)

    assets = []
    for asset in args.assets:
        if os.path.isdir(asset):
            for root, subdirs, files in os.walk(asset):
                for file in files:
                    assets.append(os.path.join(root, file))
        else:
            assets.append(asset)

    for codebase in codebases:
        print("[+] {}".format(codebase.path))
        for asset in assets:

            codebase_path = None

            # No codebase path specified
            try:
                if re.match("^(https?://)?[^:]+$", asset):
                    # Attempt to automatically identify the git repo asset path
                    codebase_path = codebase.find_file(asset)
                else:
                    asset, codebase_path = asset.rsplit(":", 1)
                    codebase_path = codebase.find_file(codebase_path)
            except Exception as e:
                print("[!] find_file: {}".format(str(e)))
                continue

            try:
                if codebase.compare(asset, codebase_path) < 1:
                    print("[!] Unmatched file, moving on")
                    break
            except Exception as e:
                print("[!] compare: {}".format(str(e)))
