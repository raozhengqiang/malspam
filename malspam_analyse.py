import sys
import os
import ConfigParser
import json
import time
from malspam_report import analyse_sample
from operate_db import operate_database
def start_analyse_report(start_id,end_id,_date):
    cf = ConfigParser.ConfigParser()
    cf.read(os.path.join(os.getcwd(),'path.conf'))
    opts=cf.options("dir")
    for i in range(start_id,end_id+1):
        print i
        origin_path=os.path.join(cf.get("dir",opts[0]),str(i))
        report=open(os.path.join(origin_path,"reports","report.json"))
        #report=open(os.path.join(r"C:\Users\test\Desktop\rao1\virustotal3\rao",str(i),"reports","report.json"))
        setting=json.load(report)
        _analyse_sample=analyse_sample(setting)
        sha1_file,sha1,state=_analyse_sample.state_decide()
        list_file_operation=_analyse_sample.analyse_file_operation()
        list_command_line=_analyse_sample.analyse_command_line()
        #print list_file_operation
        if state=="no":
            for i in range(0,len(list_file_operation)):
                if "file_created" in list_file_operation[i] and ".exe" in list_file_operation[i]:
                    if sha1_file[-4:]==".ps1":
                        state="run_powershell"
                    elif sha1_file[-4:]==".bat":
                        state="run_command"
                    
            state="no run"
        if sha1=="":
            continue
        import_to_db(sha1_file,sha1,state,list_file_operation,list_command_line,_date)
        file_transform(sha1_file,sha1,state,cf,origin_path,_date)
        

def import_to_db(sha1_file,sha1,state,list_file_operation,list_command_line,date):
    operate_database_=operate_database(sha1_file,sha1,state,list_file_operation,list_command_line,date)
    operate_database_.insert_to_db()

def file_transform(sha1_file,sha1,state,cf,origin_path,_date):
    #date=time.strftime('%Y-%m-%d',time.localtime(time.time()))
    cf.read(os.path.join(os.getcwd(),'path.conf'))
    opts=cf.options("dir")
    goal_path=os.path.join(cf.get("dir",opts[1]),_date)
    isExists=os.path.exists(goal_path)
    if not isExists:
        os.makedirs(goal_path)
    sha1_dir=os.path.join(goal_path,sha1)
    sha1IsExists=os.path.exists(sha1_dir)
    if not sha1IsExists:
        os.makedirs(sha1_dir)
    if sha1_file[-3:]=='ps1' or sha1_file[-3:]=='bat':
        
        origin_dir=os.path.join(os.getcwd(),'files',_date,'ps1_bat_file')
    else:
        origin_dir=os.path.join(os.getcwd(),'files',_date,'download_file')
    _list=os.listdir(origin_dir)
    for i in range(0,len(_list)):
        if sha1 in _list[i]:
            cmd="cp "+os.path.join(origin_dir,_list[i])+" "+sha1_dir
            os.popen(cmd)
            break
    if state=='runpayload':
        cmd="cp "+os.path.join(origin_path,"reports","report.json")+" "+sha1_dir
        os.popen(cmd)
        cmd="cp -r "+os.path.join(origin_path,"files")+" "+sha1_dir
        os.popen(cmd)
        
    
    
    
    
def print_help():
    print "python start_id end_id date"

if __name__=="__main__":
    if len(sys.argv)!=4:
        print_help()
    else:
        start_id=int(sys.argv[1])
        end_id=int(sys.argv[2])
        date=sys.argv[3]
        start_analyse_report(start_id,end_id,date)
        

        
