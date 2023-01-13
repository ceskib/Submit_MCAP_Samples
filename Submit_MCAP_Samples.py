import os
import sys
import argparse
import datetime
import time
import json
import requests
import hashlib
import config
import eml_parser

parser = argparse.ArgumentParser(
    prog = "Submit MCAP Samples",
    description = """Utility for uploading single or multiple files to the Malicious Code Analysis Platform (MCAP)
    for processing and reporting.
    """
)
parser.add_argument("sample", help="Sample file or directory")
mcap_args = parser.add_argument_group()
# mcap_args.add_argument("-w", "--wait", action="store_true", help="Wait for MCAP to complete processing each file")
mcap_args.add_argument("-e", "--email", action="store_true", help="Notify processing completion with an email")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode for testing")
args = parser.parse_args()

# MCAP Settings
tg_url = "https://mcap.cisecurity.org/api/sample/"
tg_api_key = config.api_key

input_param = args.sample
input_files = []

form_headers = {"Accept": "application/json", "Authorization": "Bearer " + tg_api_key}

def json_serial(obj):
  if isinstance(obj, datetime.datetime):
      serial = obj.isoformat()
      return serial

def md5hash(file):
    BSIZE = 65536
    hashmd5 = hashlib.md5()
    while True:
        info = open(file, "rb").read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()

def rename_eml(eml_file):
    with open(file, "rb") as fhdl:
        raw_email = fhdl.read()

    ep = eml_parser.EmlParser()
    parsed_eml = ep.decode_email_bytes(raw_email)

    email_dict = json.loads(json.dumps(parsed_eml, default=json_serial))
    tmp_name = email_dict["header"]["subject"]
    eml_new_name = tmp_name[0:55] + ".eml"
    
    if args.debug or args.verbose:
        print("Submitted Filename:", eml_file)
        print("New Filename: ", eml_new_name)

    os.rename(eml_file, eml_new_name)

    return eml_new_name

def submit_file(form_data, file):
    try:
        response = requests.post(tg_url + "submit?", files=file, data=form_data, headers=form_headers, verify=True)
        if response.status_code == 200:
            if args.debug or args.verbose:
                print(response.json())

            print()
            print("[ MCAP STATUS: Successful file submission ]")
            print("--------------------------------------------------------------------------")
            print("  Submitted at: {0}".format(str(response.json()["sample"]["created_at"])))
            print("  Sample ID: {0}".format(str(response.json()["sample"]["mcap_id"])))
            print()
            print("  Submitted file: {0}".format(str(response.json()["sample"]["filename"])))
            print("--------------------------------------------------------------------------")
            print()

            return response.json()["sample"]["mcap_id"]
        else:
            print("ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(response.text)))
            sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__,
            funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e)))
        sys.exit()

# def get_report(mcap_id):
#     """ 
#     Poll the API for the sample to complete processing
#     """

#     processed = False

#     if args.debug or args.verbose:
#         print("Preparing for status check for MCAP_ID:", mcap_id)

#     while processed != True:
#         time.sleep(10)
#         try:
#             response = requests.get(tg_url + "status?", params={"mcap_id":mcap_id}, headers=form_headers, verify=True)
#             if response.status_code == 200:
#                 print(".", end=" ", flush=True)
#                 if response.text != "[]":
#                     if args.debug or args.verbose:
#                         print()
#                         print("Headers")
#                         print(response.headers)
#                         print()
#                     processed = True
#                     print(response.json())
#             else:
#                 print(
#                     "ERROR: Something went wrong in {0}. Error: {1}"
#                     .format(sys._getframe().f_code.co_name, str(response.text))
#                 )
#                 sys.exit()
#         except Exception as e:
#             exc_type, exc_obj, exc_tb = sys.exc_info()
#             print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__,
#                 funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e)))
#             sys.exit()

# If the supplied parameter is a file validate it exists
if not os.path.exists(input_param):
    sys.exit("{}: error: file '{}' doesn't exist".format(sys.argv[0], input_param))

if os.path.isdir(input_param):
    unique_files = []
    print()
    print("You have supplied a directory")
    print()
    for (dirpath, dirnames, filenames) in os.walk(input_param):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            file_hash = md5hash(file_path)
            if file_hash not in unique_files:
                unique_files.append(file_hash)
                input_files.append(file_path)
            else:
                os.remove(file_path)
else:
    input_files.append(input_param)

print("------------------------")
print("SUBMITTING [{0}] FILE(S)".format(str(len(input_files))))
print("------------------------")

# Sources
# 1 - Drive-by-Download
# 2 - Phishing E-mail
# 3 - Un-Authorized Download/Install
# 4 - Application Exploitation
# 5 - Possible APT Activity
# 6 - Other/Unknown

for file in input_files:
    form_data = {"source": 2, "private": 1, "email_notification": 0}
    
    sample_file = rename_eml(file)
    
    if args.debug:
        print("Debug mode set, not sending.")
    else:
        sample = {"sample_file": open(sample_file, "rb")}
        mcap_id = submit_file(form_data, sample)
        # get_report(mcap_id)
