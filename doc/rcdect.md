```c
struct thread_syscall_info {
    u64 syscall_count;
    u64 syscall_vel; 
    u64 syscall_argument_similar;
    u64 prev_syscall_number;
    u64 syscall_kind_similar;

    char task_name[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
    u32 no_name;

    u64 prev_args[6];   
    u64 syscall_number;  

    u32 is_first;      
};
```

