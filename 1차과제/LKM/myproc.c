// writer: Jeonghwa Yu
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <asm/uaccess.h>

#define PROC_DIRNAME "myproc"
#define PROC_FILENAME "myproc"

#define MAX_QUEUE 1000

// for using circular queue
struct c_queue{
	unsigned long long block_num;
	const char* fs_name;
	long long time;
};
// extern function for extract data in queue
extern int dequeue(struct c_queue* q);

// queue buffer
char q_log[MAX_QUEUE][100];

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

static int my_open(struct inode *inode, struct file *file){
	printk(KERN_INFO "Simple Module Open!!\n");

	return 0;
}

// proc 파일에 읽기 요청으로 buffer의 내용을 가져오기 위해 사용
static ssize_t my_read(struct file *file, char __user *user_buffer, 
						size_t count, loff_t *ppos){
	printk(KERN_INFO "Module read!!\n");
	
	// 이미 read가 호출 된 적 있다면 더이상 읽어올 필요 없이 종료
	if (*ppos > 0){
		return 0;
	}

	// buffer의 길이
	int len;
	len = sizeof(q_log);

	// user space로 데이터 옮기기
	if (copy_to_user(user_buffer, q_log, len)){
		return -EFAULT;
	}
	
	*ppos += len;
	return len;
}

// proc 파일에 쓰기 요청으로 buffer에 circular queue 안의 내용을 담기 위해 사용
static ssize_t my_write(struct file *file, const char __user *user_buffer,
						size_t count, loff_t *ppos){
	printk(KERN_INFO "Simple Module Write!!\n");

	int cnt = 0;
	while(1){
		struct c_queue q;
		int result;

		// queue의 data 하나씩 추출
		result = dequeue(&q);

		// 추출할 데이터가 없으면 loop 종료
		if (result == -1){
			break;
		}
		// 추출한 데이터를 버퍼에 기록
		else {
			sprintf(q_log[cnt], "FS name: %s, time: %lld, Block number: %Lu\n", 
					q.fs_name, q.time, q.block_num);
			cnt++;
		}
	}
	return count;
}

static const struct file_operations myproc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_write,
	.read = my_read
};

// module init
static int __init simple_init(void){
	printk(KERN_INFO "Simple Module Init!!\n");

	// proc_dir and proc_file 생성
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file = proc_create(PROC_FILENAME, 0600, proc_dir, &myproc_fops);

	return 0;
}

// module exit
static void __exit simple_exit(void){
	printk(KERN_INFO "Simple Module Exit!!\n");

	// remove proc_dir and proc_file
	remove_proc_entry(PROC_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("JH");
MODULE_DESCRIPTION("myproc test");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");

