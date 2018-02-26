import sys
import os
import ConfigParser

class analyse_sample(object):
    def __init__(self,setting):
        self._setting_=setting

    def state_decide(self):
        sha1_file=""
        sha1=""
        state=""
        try:
            tree_root=self._setting_['behavior']['processtree'][1]
            line=str(tree_root["command_line"])
            sha1_file=line.split("\\")[-1]
            sha1=sha1_file.split(".")[0]
            if len(tree_root['children'])==0:
                state="no run"
                #print state
            else:
                tree=tree_root['children']
                #print str(tree[0]['process_name'])
                process_name=str(tree[0]['process_name'])
                command_line=str(tree[0]['command_line'])
                state=self.get_step(tree,process_name,command_line)
                #print state
                if state=='no':
                    if 'powershell' in process_name:
                        state="run_powershell"
                    if 'cmd' in process_name:
                        state="run_command"
        except:
            print "Unexpected error:{}".format(sys.exc_info()[0])
        return sha1_file,sha1,state

    def get_step(self,tree,process_name,command_line):
        
        now_state=''
        if(len(tree)==0):
            if 'powershell' in process_name:
                now_state="run_powershell"
            elif 'cmd' in process_name:
                now_state="run_command"
            elif "exe" in command_line[-5:]:
                #print command_line+"--------------------"
                now_state='runpayload'
            else:
                now_state='no'
                #print command_line+"******************88"
            return now_state
        else:
            tree=tree[0]
            if str(tree['command_line'])[-4:]=='.exe':
                now_state='runpayload'
                return now_state
            process_name=str(tree['process_name'])
            command_line=str(tree['command_line'])
            tree=tree['children']
        
            now_state=self.get_step(tree,process_name,command_line)
            return now_state

    def analyse_file_operation(self):
        
        #setting=self.load_Font()
        list_file_operation=[]
        list_type=[]

        cf = ConfigParser.ConfigParser()

        type_dir='path.conf'

        cf.read(type_dir)
        opts=cf.options("type")
        try:
            summary=self._setting_['behavior']['summary']
            if self._setting_.has_key('dropped'):

                dropped=self._setting_['dropped']


                for i in range(0,len(dropped)):
                    #print i
                    if dropped[i].has_key('filepath'):
                        filepath=str(dropped[i]['filepath'])
                        size=str(dropped[i]['size'])
                        sha256=str(dropped[i]['sha256'])

                        for j in range(0,len(opts)):
                            if str(cf.get("type",opts[j])) in filepath:
                                list_file_operation.append("file_created:"+filepath+"  "+size+"  "+sha256)
                    



            if summary.has_key('file_deleted'):
                file_deleted_list=summary['file_deleted']
                len_file_deleted_list=len(file_deleted_list)
                for i in range(0,len_file_deleted_list):
                    for j in range(0,len(opts)):
                        if str(cf.get("type",opts[j])) in str(file_deleted_list[i]):
                            list_file_operation.append("file_deleted:"+str(file_deleted_list[i]))
        except:
            print "Unexpected error:{}".format(sys.exc_info()[0])
        return list_file_operation


    def analyse_command_line(self):
        list_command_line=[]
        try:
            tree_root=self._setting_['behavior']['processtree'][1]
            list_command_line.append(str(tree_root['command_line']))
            tree_root=tree_root['children']
            list_command_line=self.get_step_comannd_line(tree_root,list_command_line)
            #for i in range(0,len(list_command_line)):
                #print list_command_line[i]+"\n"
        except:
            print "Unexpected error:{}".format(sys.exc_info()[0])
        return list_command_line

    def get_step_comannd_line(self,tree,list_command_line):
        if(len(tree)==0):
            return list_command_line
        else:
            tree=tree[0]
            list_command_line.append(str(tree['command_line']))
            tree=tree['children']
            list_command_line=self.get_step_comannd_line(tree,list_command_line)
            return list_command_line
            

        
