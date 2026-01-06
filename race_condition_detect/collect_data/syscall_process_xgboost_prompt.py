#xgboost 훈련 데이터 만드는 코드
from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import csv
import time
from ctypes import *

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--print", action="store_true")
parser.add_argument("--count", action="store_true")
parser.add_argument("-t", "--time", type=float, default=0.1)
parser.add_argument("-l", "--label", type=int, default=0)
parser.add_argument("-n", "--name", type=str, default='poc')
args = parser.parse_args()

text = r"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>

#define LAST_SYSCALL_NUMBER 450
#define SCHED_ON 1
#define SCHED_OFF 0
#define PRINT_MODE

#ifdef COUNT
struct syscall_info{
    u32 pid;
    u32 tid;
    u64 syscall_number;
    u64 count;
    u32 is_not_first;
    char task_name[TASK_COMM_LEN];
};

#else

struct syscall_info{
    u32 pid;
    u32 tid;
    u64 syscall_number;
    u64 count;
    u32 is_not_first;
    char task_name[TASK_COMM_LEN];
};

struct key_prev_syscall_argument{
    u64 pid_tgid;
    u64 syscall_number;
};

struct prev_syscall_argument //이전 직전의 시스템콜변수를 저장하는 변수
{
    u64 prev_args[6];
};

struct syscall_info_key{
    u64 pid;
    u64 syscall_number;
};

struct key_thread_syscall_info
{
    u32 pid;
    u32 tid;
    u64 syscall_number;
};

struct thread_syscall_info
{
    //시스템콜 관련
    u64 syscall_count; //시스템콜 몇번불렀는지
    u64 syscall_vel;   //시스템콜 호출 속도
    u64 syscall_argument_similar; //유사한 인자를 넣어서 시스템콜을 호출하였는지 확인
    u64 prev_syscall_number;    //직전 호출한 시스템콜 기록
    u64 syscall_kind_similar;   //시스템콜 유사도

    //출력용
    char task_name[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
    u32 no_name;

    //개별적인 시스템콜
    u64 prev_args[6];
    u64 syscall_number;

    u32 is_first;
};

struct prev_thread_syscall_info
{
    u32 pid;
    u32 tid;
    u64 prev_syscall_number;
    u32 is_first;
};

//시스템콜종류 관련
BPF_HASH(data_syscall_info, struct syscall_info_key, struct syscall_info);
BPF_HASH(data_thread_syscall_info, struct key_thread_syscall_info ,struct thread_syscall_info);
BPF_HASH(data_prev_thread_syscall_info, u64, struct prev_thread_syscall_info);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 syscall_argument_similar = 0;

    struct thread_syscall_info * val_thread_syscall_info, zero_val_thread_syscall_info = {};
    struct key_thread_syscall_info key_val_thread_syscall_info = {};
    struct prev_thread_syscall_info * val_prev_thread_syscall_info, zero_val_prev_thread_syscall_info = {};

    key_val_thread_syscall_info.pid = pid;
    key_val_thread_syscall_info.tid = tid;
    key_val_thread_syscall_info.syscall_number = args->id;

    val_thread_syscall_info = data_thread_syscall_info.lookup_or_try_init(&key_val_thread_syscall_info,&zero_val_thread_syscall_info);
    val_prev_thread_syscall_info = data_prev_thread_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_prev_thread_syscall_info);
    if(val_thread_syscall_info && val_prev_thread_syscall_info)
    {
        if(val_prev_thread_syscall_info->is_first == 0)
        {
            val_prev_thread_syscall_info->pid = pid;
            val_prev_thread_syscall_info->tid = tid;
            val_prev_thread_syscall_info->prev_syscall_number = 595959;
            val_prev_thread_syscall_info->is_first = 1;
        }
        if(val_thread_syscall_info->is_first == 0)
        {
            for(int i = 0 ; i < 2 ; ++i)
            {
                val_thread_syscall_info->prev_args[i] = 59595959;   //처음값을 초기화
            }
            val_thread_syscall_info->pid = pid;
            val_thread_syscall_info->tid = tid;
            val_thread_syscall_info->syscall_number = args->id;
            char name[TASK_COMM_LEN];
            bpf_get_current_comm(&name, sizeof(name));
            bpf_probe_read_str((char*)val_thread_syscall_info->task_name,sizeof(name),name);   
            val_thread_syscall_info->pid = pid;
            val_thread_syscall_info->is_first = 1;
        }
        val_thread_syscall_info->syscall_count += 1;
        for(int i = 0 ; i < 2; ++i)
        {
            if(val_thread_syscall_info->prev_args[i] == args->args[i])
            {
                syscall_argument_similar = 1;
            }
            val_thread_syscall_info->prev_args[i] = args->args[i];
        }
        if(syscall_argument_similar == 1)
        {
            val_thread_syscall_info->syscall_argument_similar += 1;
        }
        if(val_prev_thread_syscall_info->prev_syscall_number == args-> id)
        {
            val_thread_syscall_info->syscall_kind_similar += 1;
        }
        val_prev_thread_syscall_info->prev_syscall_number = args->id;
    }    
done :
    return 0;
}

#endif
"""

if args.count:
    text = ("#define COUNT\n" + text)

file_name_ori = input('파일 이름을 입력해주세요: ')

bpf = BPF(text=text)

def print_process_info():
    print_data_prev_thread_syscall_info = bpf['data_prev_thread_syscall_info']
    print_data_thread_syscall_info = bpf["data_thread_syscall_info"]
    global print_type
    global print_line_count
    collect_print_data_prev_thread_syscall_info = print_data_prev_thread_syscall_info.items_lookup_and_delete_batch()
    collect_print_data_thread_syscall_info = print_data_thread_syscall_info.items_lookup_and_delete_batch()
    dictionary_collect_print_data_syscall_info = {}

    #syscall info 출력
    for k, v in collect_print_data_thread_syscall_info:
        if dictionary_collect_print_data_syscall_info.get(v.pid) == None:
            dictionary_collect_print_data_syscall_info[v.pid] = {}
        if dictionary_collect_print_data_syscall_info[v.pid].get('syscall_total_count') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['syscall_total_count'] = 0
        dictionary_collect_print_data_syscall_info[v.pid]['syscall_total_count'] += v.syscall_count
        if dictionary_collect_print_data_syscall_info[v.pid].get('syscall_argument_similar') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['syscall_argument_similar'] = 0
        dictionary_collect_print_data_syscall_info[v.pid]['syscall_argument_similar'] += v.syscall_argument_similar
        if dictionary_collect_print_data_syscall_info[v.pid].get('syscall_kind_similar') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['syscall_kind_similar'] = 0
        dictionary_collect_print_data_syscall_info[v.pid]['syscall_kind_similar'] += v.syscall_kind_similar
        if dictionary_collect_print_data_syscall_info[v.pid].get('syscall_invocate_list') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['syscall_invocate_list'] = []
        dictionary_collect_print_data_syscall_info[v.pid]['syscall_invocate_list'].append((v.syscall_count,v.syscall_number,syscall_name(v.syscall_number).decode('utf-8')))
        if dictionary_collect_print_data_syscall_info[v.pid].get('pid') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['pid'] = v.pid
        if dictionary_collect_print_data_syscall_info[v.pid].get('process_name') == None:
            dictionary_collect_print_data_syscall_info[v.pid]['process_name'] = (v.task_name).decode('utf-8')

    for k, v in dictionary_collect_print_data_syscall_info.items():
        v['syscall_kind'] = len(v['syscall_invocate_list'])           #종류 개수 더함
        sorted_list = sorted(v['syscall_invocate_list'], key=lambda x: -x[0])
        v['syscall_invocate_list'] = sorted_list
        for i in range(v['syscall_kind'], 6):
            v['syscall_invocate_list'].append((0,0,'empty'))
        v['syscall_top1'] =  v['syscall_invocate_list'][0][0]
        v['syscall_top2'] =  v['syscall_invocate_list'][1][0]
        v['syscall_top3'] =  v['syscall_invocate_list'][2][0]
        v['syscall_top4'] =  v['syscall_invocate_list'][3][0]
        v['syscall_top5'] =  v['syscall_invocate_list'][4][0]
        v['syscall_top6'] =  v['syscall_invocate_list'][5][0]
        if v['syscall_total_count'] != 0:
            v['syscall_argument_similar'] = round(v['syscall_argument_similar']/v['syscall_total_count'],3)
            v['syscall_kind_similar'] = round(v['syscall_kind_similar']/v['syscall_total_count'],3)
        else:
            v['syscall_argument_similar'] = 0
            v['syscall_kind_similar'] = 0
    #데이터 생성 완성
    
    if args.label == 0:
        for k, v in dictionary_collect_print_data_syscall_info.items():
            if v['syscall_total_count'] != 0 and v['process_name'] == args.name:
                write_data = [print_type,v['pid'],v['process_name'],v['syscall_total_count'], v['syscall_argument_similar'], v['syscall_kind_similar'], v['syscall_kind'], v['syscall_top1'],v['syscall_top2'],v['syscall_top3'],v['syscall_top4']
                ,v['syscall_top5'],v['syscall_top6'],1]
                writer.writerow(write_data)
                print_line_count += 1
                if args.print:
                    print(write_data)
            elif v['syscall_total_count'] != 0:
                write_data = [print_type,v['pid'],v['process_name'],v['syscall_total_count'], v['syscall_argument_similar'], v['syscall_kind_similar'], v['syscall_kind'], v['syscall_top1'],v['syscall_top2'],v['syscall_top3'],v['syscall_top4']
                ,v['syscall_top5'],v['syscall_top6'],args.label]
                writer.writerow(write_data)
                print_line_count += 1
                if args.print:
                    print(write_data)

        print_type += 1
    else:
        for k, v in dictionary_collect_print_data_syscall_info.items():
            if v['syscall_total_count'] != 0:
                write_data = [print_type,v['pid'],v['process_name'],v['syscall_total_count'], v['syscall_argument_similar'], v['syscall_kind_similar'], v['syscall_kind'], v['syscall_top1'],v['syscall_top2'],v['syscall_top3'],v['syscall_top4']
                ,v['syscall_top5'],v['syscall_top6']]
                writer.writerow(write_data)
                print_line_count += 1
                if args.print:
                    print(write_data)
        print_type += 1

print_line_count = 0        #현재 몇줄까지 입력되어 있는지 저장하는 변수
print_line_check = 100000   #몇줄까지는 입력할 수 있는지 정하는 변수
print_type = 0                   
file_number = 0             #현재 몇번째 파일로 저장하는지 지정하는 변수
file_name = file_name_ori +'_'+str(file_number)

f = open(file_name+'.csv', 'w')
writer = csv.writer(f)

print_type = 0
is_print = 0
first_time = 0
exiting = 0
print('start')
title_data = []
if args.label == -1:
    title_data = ['Print_Type','PID','Process_Name','SYSCALL_TOTAL_COUNT','SYSCALL_ARGUMENT_SIMILAR','SYSCALL_KIND_SIMILAR','SYSCALL_KIND','SYSCALL_TOP1','SYSCALL_TOP2','SYSCALL_TOP3','SYSCALL_TOP4','SYSCALL_TOP5','SYSCALL_TOP6']
elif args.label == 0 or args.label == 1:
    title_data = ['Print_Type','PID','Process_Name','SYSCALL_TOTAL_COUNT','SYSCALL_ARGUMENT_SIMILAR','SYSCALL_KIND_SIMILAR','SYSCALL_KIND','SYSCALL_TOP1','SYSCALL_TOP2','SYSCALL_TOP3','SYSCALL_TOP4','SYSCALL_TOP5','SYSCALL_TOP6','DANGER']
writer.writerow(title_data)
print_line_count += 1
while True:
    try:
        if args.count:
            if print_line_count > print_line_check:         #특정 줄수 이상을 넘으면 파일을 닫고 새로운 파일을 만든다.
                print_line_count = 0
                f.close()
                file_number += 1
                file_name = file_name_ori +'_'+ str(file_number)
                f = open(file_name+'.csv', 'w')
                writer = csv.writer(f)
                writer.writerow(title_data)
                print_line_count += 1
        else:
            print_process_info()
            if print_line_count > print_line_check:         #특정 줄수 이상을 넘으면 파일을 닫고 새로운 파일을 만든다.
                print_line_count = 0
                f.close()
                file_number += 1
                file_name = file_name_ori +'_'+ str(file_number)
                f = open(file_name+'.csv', 'w')
                writer = csv.writer(f)
                writer.writerow(title_data)
                print_line_count += 1
        sleep(args.time)
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if exiting:
        #f.close()
        print("Detaching...")
        exit()