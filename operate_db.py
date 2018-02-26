import pymysql
import os
import datetime

class operate_database(object):
    def __init__(self,sha1_file,sha1,state,list_file_operation,list_command_line,date):
        self._sha1_file=sha1_file
        self._sha1=sha1
        self._state=state
        self._list_file_operation=list_file_operation
        self._list_command_line=list_command_line
        self._date=date
        

    def insert_to_db(self):
        obj={}
        conn=pymysql.connect(host='10.5.32.24',user='root',password='123456',db='refer_url_data',charset='utf8')
        cursor=conn.cursor()
        cursor.execute("set names utf8")
        obj=self.make_obj(obj)
        str_file_operation=""
        str_command_line=""
        for i in range(0,len(self._list_file_operation)):
            if i!=len(self._list_file_operation)-1:
                str_file_operation=str_file_operation+self._list_file_operation[i]+"\n"
            else:
                str_file_operation=str_file_operation+self._list_file_operation[i]

        for i in range(0,len(self._list_command_line)):
            if i!=len(self._list_command_line):
                str_command_line=str_command_line+"command_line:"+self._list_command_line[i]+"\n"
            else:
                str_command_line=str_command_line+"command_line:"+self._list_command_line[i]

        sqlStr='insert into malspam_data (sha1,file_name,process,file_operation,processtree_command_line,date) values (%s,%s,%s,%s,%s,%s)'
	       
	try:
            cursor.execute(sqlStr,(obj['sha1'],obj['file_name'],obj['process'],str_file_operation,str_command_line,obj['date']))
            conn.commit()
        except:
            conn.rollback()
            print "Unexpected error:{}".format(sys.exc_info()[0])


    def make_obj(self,obj):
        
        obj['file_name']=self._sha1_file
        obj['sha1']=self._sha1
        obj['process']=self._state
        obj['date']=self._date
        return obj
