#!/usr/bin/python
#
# Remove PII (personally identifying information)
# Some insitutions are sensitive to user PII being loaded to BigQuery. 
# The following code hashes or nullifies PII data.

import os, sys
import csv
import gzip
import glob as glob
import hashlib
import edx2bigquery_config

hashpwd = getattr(edx2bigquery_config, "HASHPWD", None)
hashint = getattr(edx2bigquery_config, "HASHINT", None)

file_pii_columns = {
    'certificates.csv.gz': {
        'piicols': ['id','user_id','name'],
    },
    'enrollment.csv.gz': {'piicols': ['id','user_id']},
    'forum.mongo': {'piicols': []}, #'NEEDS ATTENTION',
    'forum-rephrased.json.gz': {'piicols': ['author_id', 'author_username', 'endorsement.user_id']}, #'NEEDS ATTENTION',
    'profiles.csv.gz': {'piicols': ['id','user_id','name','meta','mailing_address','goals','bio','profile_image_uploaded_at']},
    'student_anonymoususerid.csv.gz': {'piicols': ['id','user_id','anonymous_user_id']},
    'student_languageproficiency.csv.gz': {'piicols': ['id','user_profile_id']},
    'studentmodule.csv.gz': {'piicols': ['student_id']},
    'teams.csv.gz': {'piicols': ['team_id','name','topic_id','description','discussion_topic_id','team_size']},
    'teams_membership.csv.gz': {'piicols': ['user_id','team_id']},
    'user_api_usercoursetag.csv.gz': {'piicols': ['user_id']},
    'user_id_map.csv.gz': {'piicols': ['id','username','hash_id']}, #'NEEDS ATTENTION',
    'users.csv.gz': {'piicols': ['id','username','first_name','last_name','email','password','is_staff','is_superuser','email_tag_filter_strategy']},
    'verify_student_verificationstatus.csv.gz': {'piicols': ['user_id']},
    'wiki_article.csv.gz': {'piicols': ['owner_id','group_id']},
    'wiki_articlerevision.csv.gz': {'piicols': ['user_message','ip_address','user_id','modified','created','article_id','content','title']},
}

def hashfn(x, key, hpw=hashpwd, rshift=hashint):
    if x != '':
        if key in ['user_id', 'uid', 'id', 'student_id', 'is_staff', 'author_id']:
            # print x, type(x), rshift, type(rshift)
            return int(hashlib.sha512(str(x) + str(rshift)).hexdigest()[:14], 16)
        else:
            return hashlib.sha512(x + hpw).hexdigest()
    else:
        return ''

def remove_pii_from_sql(file_org, hpw=hashpwd, rshift=hashint):
    file_bak = file_org +'.bak'
    os.rename(file_org, file_bak)
    file_base = os.path.basename(file_org)

    with gzip.open(file_bak, 'r') as finput:
        reader = csv.reader(finput)
        header = reader.next()
        matches = [header.index(col) for col in file_pii_columns[file_base]['piicols']]

        with gzip.open(file_org, 'w') as foutput: 
            writer = csv.writer(foutput)
            writer.writerow(header)
            if reader:
                for row in reader:
                    for m in matches:
                        if header[m] in ['bio','mailing_address','goals', 'password','is_superuser','email_tag_filter_strategy']:
                            row[m] = 'Removed'
                        elif header[m] == 'email':
                            row[m] = hashfn(row[m], header[m], hpw, rshift)+'@gmail.com'
                        else:
                            row[m] = hashfn(row[m], header[m], hpw, rshift)
                    writer.writerow(row)
            else:
                print "Cannot read this file!!!!!!!!!!!"

    os.remove(file_bak)

    return None


def process_directory(courses, param, hpw, rshift):
    '''
    basedir = directory whose contents were arranged by the waldofy function.
    '''
     # dirname must have date in it

    ### Clean Waldofied SQL Directory
    files = glob.glob('%s/*/*/*' % param.the_basedir)
    files.sort()
    print param.the_basedir

    for fn in files:
        fn_base = os.path.basename(fn)
        if fn_base in file_pii_columns:
            print "-----------------------------------"
            print "Removing PII from:  %s" % fn
            print "Specific columns are: %s" % str(file_pii_columns[fn_base]['piicols'])
            remove_pii_from_sql(fn, hpw, rshift)
        sys.stdout.flush()


if __name__ == "__main__":
    remove_pii_from_file('certificates.csv',None)




