import os
import sys
import json
import requests
import hashlib

# MCAP Settings
tg_url = 'https://mcap.cisecurity.org/api/sample/submit'
tg_api_key = ''

form_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + tg_api_key}

def md5hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()

def submit_file(form_data, file):
    try:
        subres = requests.post(tg_url + '?', files=file, data=form_data, headers=form_headers, verify=True)
        if subres.status_code == 200:
            print()
            print("[ MCAP STATUS: Successful file submission ]")
            print('--------------------------------------------------------------------------')
            print("  Submitted at: {0}".format(str(subres.json()["sample"]["created_at"])))
            print("  Sample ID: {0}".format(str(subres.json()["sample"]["mcap_id"])))
            print()
            print("  Submitted file: {0}".format(str(subres.json()["sample"]["filename"])))
            print('--------------------------------------------------------------------------')
            print()
            print(subres.json())
##            return sampleid
        else:
            print("ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(subres.text)))
            sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__,
            funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e)))
        sys.exit()


# Validate a parameter was provided as an argument
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s sample' % sys.argv[0])

input_param = sys.argv[1]
input_files = []
unique_files = []

# Debug mode
if input_param == 'debug':
    pass

# If the supplied parameter is a file validate it exists
if not os.path.exists(input_param):
    sys.exit('File {} doesn\'t exist'.format(input_param))

# Check if the supplied parameter is a directory
if os.path.isdir(input_param):
    print()
    print('You have supplied a directory')
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
    # Append the provided parameter to input_files
    input_files.append(input_param)

print("------------------------")
print("SUBMITTING [ {0} ] FILES".format(str(len(input_files))))
print("------------------------")
print()
for file in input_files:
    form_data = {'source': 2, 'private': 1, 'email_notification': 0}
    sample = {'sample_file': open(file, 'rb')}
    
    submit_file(form_data, sample)
