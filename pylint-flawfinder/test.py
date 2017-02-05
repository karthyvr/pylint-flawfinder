# Author: Karthy Vaiyampalayam Ramakrishnan
# Student ID: 1001244142
# Secure Programming Assignment 2
# detailed comments are provided before each method

import boto
import subprocess
from boto.s3.key import Key
from boto.s3.connection import S3Connection
import urllib
import md5
import MySQLdb
import os
from datetime import timedelta
from flask import Flask, request, redirect, url_for, render_template, send_file, Response, make_response, session
from pylint import epylint as lint
from subprocess import Popen, PIPE
import random
import configinfo
import re

configdetails = configinfo

app = Flask(__name__)

# session configurations for the session identifier
# specify the time out value in the session for 1 minute
app.secret_key = os.urandom(64)

# get the RDS data base connection
def mysqldbconn():
    conndb = MySQLdb.connect(host= configdetails.rdsmysqlhost,
                      user=configdetails.rdsmysqluser,
                      passwd=configdetails.rdsmysqlpasswd,
                      db=configdetails.rdsmysqldb)
    print 'obtained db connection'
    return conndb
# get the AWS s3 connection
def getconnection():
    AWS_ACCESS_KEY_ID = configdetails.AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY = configdetails.AWS_SECRET_ACCESS_KEY
    conn=S3Connection(AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,validate_certs=False,is_secure=False)
    return conn
# use this location for temporary file download
file_dir =  configdetails.file_dir
# home page for this application
@app.route('/')
def welcome():
    print"inside welcome"
    for the_file in os.listdir(file_dir):
        file_path = os.path.join(file_dir, the_file)
    try:
        if os.path.isfile(file_path):
            os.unlink(file_path)
    except Exception as e:
        print(e)
    return render_template('user.html')

# validates the user by getting the user  login details
# connects to the mysql RDS and retrieves the information
# using a MD5 Hashing technique for password field so that it cannot be recovered
# if it does not match it is redirected to the index page with an error message

@app.route('/checkuser', methods=['POST'])
def checkuser():
    print "checkuserrrr"
    ip_username =  request.form['username']
    ip_userpwd =  request.form['userpwd']
    if re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', ip_userpwd):
        print 'removing from session'
        if 'user_name' in session:
            session['user_name'] = None
        password_hashed = str(md5.new(ip_userpwd).hexdigest())
        connDb =mysqldbconn()
        print"after my sql db connection"
        cursor = connDb.cursor()
        print"before the check user queryy "
        cursor.execute("select * from checkuser where username ='"+ip_username+"'and userpwd ='"+password_hashed+"'")
        resultList = []

        row_count = cursor.rowcount
        source='Database'
        if row_count <= 0:
            print"within the no user found block"
            result_message = ip_username +' is not a valid user...please retry!'
            connDb.close()
            return render_template('user.html',result_msg=result_message)

            error_msg='No results found'
        else:
                  for row in cursor:
                                #session['user_quota'] = row[2]
                                session['user_name'] = ip_username
                                result_message = 'welcome ...!'+ ip_username + '....!'
                                Current_user_quota = None#session['user_quota']
                                connDb.close()
                                return render_template('index.html',result_msg=result_message, user_name=ip_username, Current_user_quota=Current_user_quota)
    else:
            result_message = ip_username +' is not a valid user...please retry!'
            return render_template('user.html',result_msg=result_message)                   

    # Local validate user from the password file
    # with open('password.txt') as f:
    # below is the block for storing the password in the file.
    # with open('/var/www/html/flaskapp/password.txt') as f:
    #     content = f.readlines()
    # print content
    # for name in content:
    #     name = name[:-1]
    #     print name
    #     if name == ip_username:
    #         print "user exists"
    #         result_message = 'welcome ...!'+ ip_username + '....!'
    #         return render_template('index.html',result_msg=result_message)
    # result_message = ip_username +' is not a valid user...please retry!'
    # return render_template('user.html',result_msg=result_message)


# if it is a new user redirect them to registration form
# Get the Details from the user and connect to RDS mysql
# if the provided user name is not there insert a new record 
# redirect the new user to the login page 
# if the user details already exists put in an error message for the user 
@app.route('/registeruser', methods=['POST'])
def registeruser():
    print 'in register user'
    return render_template('registeruser.html')

@app.route('/register', methods=['POST'])
def register():
    print 'in register'
    ip_username =  request.form['username']
    ip_userpwd =  request.form['userpwd']
    
    print 'removing old user from session'
    if 'user_name' in session:
        session['user_name'] = None
    connDb =mysqldbconn()
    cursor = connDb.cursor()
    cursor.execute("select * from checkuser where username ='"+ip_username+"'")
    resultList = []

    row_count = cursor.rowcount
    source='Database'
    if row_count <= 0:
        password_hash = str(md5.new(ip_userpwd).hexdigest())

        cursor.execute("INSERT into checkuser(username, userpwd, userquota)"
                         "values (%s, %s, %s)",
                            (ip_username, password_hash,2000))
        connDb.commit()
        result_message = ip_username +' is now a registered user...please logg in!'
        connDb.close()
        return render_template('user.html',result_msg=result_message)

# index page of the application

@app.route('/index')
def index():
    return render_template('index.html')

# log out functionality

@app.route('/logout')
def logout():
    print 'in logout'
    if 'user_name' in session:
        session['user_name'] = None
    return render_template('user.html')

# upload the code files which is the input to the static analysis tools
# As and when the file is uploaded the static analysis tool is triggered
# Flaw finder and pylint is used

@app.route('/goupload')
def goupload():
    print 'in goupload'
    ip_username = session['user_name']
    print ip_username
    return render_template('upload.html',user_name=ip_username)

@app.route('/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        conn = getconnection()
        ip_username = session['user_name']
        my_bucket_name = configdetails.inputfilebucket
        my_bucket = conn.get_bucket(my_bucket_name)
        print my_bucket.name
        input_file = request.files['input_file']
        files_list = listalldocuments(ip_username)
        if files_list is not None:
            for i in files_list:
                if i.name == input_file.filename:
                    print "file already exists"
                    upload_message = input_file.filename +' already exists ..!'
                    return render_template('upload.html', result_msg=upload_message)
            
        else:    
            print"before puttinh inyo bucket karthy"
            k = Key(my_bucket)
            ipfilename = input_file.filename
            bucketfilenameext = ipfilename.split('.')
            bucketfilename = ip_username + '_' + bucketfilenameext[0] + '.' + bucketfilenameext[1]
            k.key=bucketfilename
            k.set_contents_from_string(input_file.read())
            file_report = open(file_dir + bucketfilename, 'wb')
            k.get_contents_to_file(file_report)
            file_report.close()
            generatepylintanalysisreport(bucketfilename)
            generateflawfinderanalysisreport(bucketfilename)
            upload_message = bucketfilename +' uploaded successfully..!'
            os.remove(file_dir+bucketfilename)

    return render_template('upload.html', result_msg=upload_message)


# Method to execute the pylint static analysis tool
# used lint.pyrun to execute the pylint static analysis tool
# input is the code file uploaded by user 
# output is the report generated and will be displayed to the user he can view/delete/download reports

def generatepylintanalysisreport(filename):
    print"within generatepylintanalysisreport "
    (pylint_stdout, pylint_stderr) = lint.py_run(file_dir + filename, return_std=True)
    conn = getconnection()
    my_bucket_name_report = configdetails.pylintreportbucket
    my_bucket_report = conn.get_bucket(my_bucket_name_report)
    k = Key(my_bucket_report)
    pylintfilename = filename.split('.')[0]
    new_filename = pylintfilename + '_pylintreport' + '.txt'
    k.key = new_filename
    k.set_contents_from_string(pylint_stdout.read())
    print"after puttinh inyo bucket outputstaticreport"

# Method to execute the flawfinder static analysis tool
# used a python subprocess to execute the flaw finder static analysis tool
# input is the code file uploaded by user 
# output is the report generated and will be displayed to the user he can view/delete/download reports

def generateflawfinderanalysisreport(filename):
    print"within generateflawfinderanalysisreport "
    flawfinder_file_path = file_dir + filename
    p = Popen(['flawfinder', '--html', flawfinder_file_path], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    conn = getconnection()
    my_bucket_name_report = configdetails.flawfinderreportbucket
    my_bucket_report = conn.get_bucket(my_bucket_name_report)
    k = Key(my_bucket_report)
    flawfinderfilename = filename.split('.')[0]
    new_filename = flawfinderfilename + '_flawfinderreport' + '.txt'
    k.key = new_filename
    k.set_contents_from_string(p.stdout.read())
   

# method to list the input code file / Flawfinder Report file / Pylint report file

@app.route('/list')
def list():
    print "inside the list file function "
    ip_username = session['user_name']
    files_list = listalldocuments(ip_username)
    report_list = listalldocumentsreport(ip_username)
    flawreport_list = listalldocumentsflawreport(ip_username)

    return render_template('list.html', files_list=files_list, report_list=report_list, flawreport_list=flawreport_list)

# delete / download / view methods for the input file provided by user
# input file will be in Amazon s3 storage
# based on user action each method will be triggered 

@app.route('/deleteordownload')
def deleteordownload():
    print "deleteOrDownload"
    ip_filename = request.args.get('filename')
    ip_operation = request.args.get('operation')

    if ip_operation == 'Download':
        return redirect(url_for('download', filename=ip_filename))
    elif ip_operation == 'Delete':
        return redirect(url_for('delete', filename=ip_filename))
    elif ip_operation == 'View':
        return redirect(url_for('view', filename=ip_filename))

@app.route('/delete/<filename>')
def delete(filename):
    print "In Delete"
    ip_username = session['user_name']
    conn = getconnection()
    my_bucket_name = configdetails.inputfilebucket
    my_bucket = conn.get_bucket(my_bucket_name)
    my_bucket.delete_key(filename)
    files_list = listalldocuments(ip_username)
    report_list = listalldocumentsreport(ip_username)
    flawreport_list = listalldocumentsflawreport(ip_username)
    return render_template('list.html', result_msg="File deleted successfully..!", files_list=files_list, report_list=report_list, flawreport_list=flawreport_list)

@app.route('/download/<filename>')
def download(filename):
    print "In Download"
    conn = getconnection()
    my_bucket_name = configdetails.inputfilebucket
    my_bucket = conn.get_bucket(my_bucket_name)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=True)


@app.route('/view/<filename>')
def view(filename):
    conn = getconnection()
    my_bucket_name = configdetails.inputfilebucket
    my_bucket = conn.get_bucket(my_bucket_name)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=False)

# delete / download / view methods for the pylint file provided by pylint static analysis tool
# pylint report file will be in Amazon s3 storage
# based on user action each method will be triggered     

@app.route('/deleteordownloadreport')
def deleteordownloadreport():
    print "deleteOrDownload pylint report"
    ip_filename = request.args.get('filename')
    ip_operation = request.args.get('operation')

    if ip_operation == 'Downloadpylintreport':
        return redirect(url_for('downloadreport', filename=ip_filename))
    elif ip_operation == 'Deletepylintreport':
        return redirect(url_for('deletereport', filename=ip_filename))
    elif ip_operation == 'Viewpylintreport':
        return redirect(url_for('viewreport', filename=ip_filename))

@app.route('/deletereport/<filename>')
def deletereport(filename):
    print "In Delete pylint report"
    ip_username = session['user_name']
    conn = getconnection()
    my_bucket_name = configdetails.pylintreportbucket
    my_bucket = conn.get_bucket(my_bucket_name)
    my_bucket.delete_key(filename)
    files_list = listalldocuments(ip_username)
    report_list = listalldocumentsreport(ip_username)
    flawreport_list = listalldocumentsflawreport(ip_username)
    return render_template('list.html', result_msg="File deleted successfully..!",files_list=files_list, report_list=report_list, flawreport_list=flawreport_list)

@app.route('/downloadreport/<filename>')
def downloadreport(filename):
    print "In Download pylint report "
    conn = getconnection()
    my_bucket_name = configdetails.pylintreportbucket
    my_bucket = conn.get_bucket(my_bucket_name)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=True)


@app.route('/viewreport/<filename>')
def viewreport(filename):
    conn = getconnection()
    my_bucket_name_report = configdetails.pylintreportbucket
    my_bucket = conn.get_bucket(my_bucket_name_report)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=False)

# delete / download / view methods for the flawfinder file provided by flawfinder static analysis tool
# flawfinder report file will be in Amazon s3 storage
# based on user action each method will be triggered   

@app.route('/deleteordownloadflawreport')
def deleteordownloadflawreport():
    print "deleteOrflawDownload"
    ip_filename = request.args.get('filename')
    ip_operation = request.args.get('operation')

    if ip_operation == 'Downloadflawfinderreport':
        return redirect(url_for('downloadflawreport', filename=ip_filename))
    elif ip_operation == 'Deleteflawfinderreport':
        return redirect(url_for('deleteflawreport', filename=ip_filename))
    elif ip_operation == 'Viewflawfinderreport':
        return redirect(url_for('viewflawreport', filename=ip_filename))

@app.route('/deleteflawreport/<filename>')
def deleteflawreport(filename):
    print "In Delete"
    ip_username = session['user_name']
    conn = getconnection()
    my_bucket_name = configdetails.flawfinderreportbucket
    my_bucket = conn.get_bucket(my_bucket_name)
    my_bucket.delete_key(filename)
    files_list = listalldocuments(ip_username)
    report_list = listalldocumentsreport(ip_username)
    flawreport_list = listalldocumentsflawreport(ip_username)
    return render_template('list.html', result_msg="File deleted successfully..!", files_list=files_list, report_list=report_list, flawreport_list=flawreport_list)

@app.route('/downloadflawreport/<filename>')
def downloadflawreport(filename):
    print "In Download"
    conn = getconnection()
    my_bucket_name = configdetails.flawfinderreportbucket
    my_bucket = conn.get_bucket(my_bucket_name)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=True)


@app.route('/viewflawreport/<filename>')
def viewflawreport(filename):
    conn = getconnection()
    my_bucket_name_report = configdetails.flawfinderreportbucket
    my_bucket = conn.get_bucket(my_bucket_name_report)
    k = Key(my_bucket)
    k.key = filename
    file_download = open(file_dir + filename, 'wb')
    k.get_contents_to_file(file_download)
    file_download.close()
    file_download = open(file_dir + filename, 'rb')
    return send_file(file_download.name, as_attachment=False)


# lists all the files in the Amazon s3 buckets
# Three buckets are used
# one for input file provided by user
# second for report file generated by pylint tool
# Third for report file generated by the flawfinder tool

def listalldocuments(ip_username):
    conn = getconnection()
    my_bucket_name = configdetails.inputfilebucket
    bucket  = conn.get_bucket(my_bucket_name)
    rs = bucket.list()
    files_list = []
    for i in rs:
        if ip_username == (i.name).split('_')[0]:
            files_list.append(i)
            return files_list
   

def listalldocumentsreport(ip_username):
    conn = getconnection()
    my_bucket_name_report = configdetails.pylintreportbucket
    bucket  = conn.get_bucket(my_bucket_name_report)
    rs = bucket.list()
    files_list = []
    for i in rs:
        if ip_username == (i.name).split('_')[0]:
            files_list.append(i)
            return files_list
   

def listalldocumentsflawreport(ip_username):
    conn = getconnection()
    my_bucket_name_report = configdetails.flawfinderreportbucket
    bucket  = conn.get_bucket(my_bucket_name_report)
    rs = bucket.list()
    files_list = []
    for i in rs:
        if ip_username == (i.name).split('_')[0]:
            files_list.append(i)
            return files_list
   

if __name__ == '__main__':
    # app.run()
    # forlocal run uncomment below
    
    app.run(
        host='0.0.0.0',
        port=int('8080'),
        debug=True
    )
