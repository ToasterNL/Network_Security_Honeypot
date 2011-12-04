#define LINUX
#define MODNAME "honing"

#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LKM toy for honeypot auditing");
MODULE_AUTHOR("Aram Verstegen");

#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <asm/uaccess.h>

static struct honing_config {
	int hidden;
	int loaded;
} honing;

void honing_log(const char* fmt, ...);
static long sys_execve_addr;

module_param(sys_execve_addr, long, 0000);
MODULE_PARM_DESC(sys_execve_addr, "The address of sys_execve to hook to");

char* argv_to_string(char __user * __user *argv){
	size_t bytes_needed = 0;
	int argc = 0;
	char *str = NULL, *newstr = NULL;
	unsigned int page_faults;
	mm_segment_t oldfs = get_fs();
	if(!argv){
		goto out;
	}

	/* first arg length + 1 space as malloc size */
	set_fs(get_ds());
	bytes_needed = strlen(argv[0])+1;
       	if((str = kmalloc(bytes_needed, GFP_ATOMIC)) == NULL){
		goto out;
	}
	memset(str, 0, bytes_needed);
	
	for(argc = 0; argv[argc]; argc++){
		/* str end - arglen - 1 space */
		/* memcpy is normally considered evil in the kernel */
		while(copy_from_user(str+bytes_needed-strlen(argv[argc])-1, argv[argc], strlen(argv[argc])) !=0){
			// keep copying
			page_faults++;
			if(page_faults > 0){
				printk("Encountered %i pagefaults when calling copy_from_user!\n", page_faults);
				kfree(str);
				str = NULL;
				goto out;
			}
		}
		page_faults = 0;
		/*memcpy(str+bytes_needed-strlen(argv[argc])-1, argv[argc], strlen(argv[argc]));*/
		/* set space in last field */
		memset(str+bytes_needed-1, ' ', 1);

		if(argv[argc+1]){ /* has next */
			bytes_needed += strlen(argv[argc+1]) + 1; /* string plus a space or \0 */
			if((newstr = krealloc(str, bytes_needed, GFP_ATOMIC)) == NULL){
				kfree(str);
				str = NULL;
				goto out;
			}
			str = newstr;
		}
	}
	/* make last space a \0 */
	memset(str+bytes_needed-1, 0, 1);
out:
	set_fs(oldfs);
	return str;
}

void hide_lkm(void){
	__this_module.list.prev->next = __this_module.list.next;
	__this_module.list.next->prev = __this_module.list.prev;
}

void unhide_lkm(void){
	__this_module.list.prev->next = (struct list_head *)&__this_module.list;
	__this_module.list.next->prev = (struct list_head *)&__this_module.list;
}

void honing_log(const char* fmt, ...){
	va_list argp;
	char *str = NULL, *newstr = NULL, *newfmt = NULL;
	char *prefix = "honing: %s";
	size_t newfmt_len = strlen(prefix)+strlen(fmt)+1;

	size_t size = 256;
	signed int n = 0;

	/* prefix format string */
	if((newfmt = kmalloc(newfmt_len, GFP_ATOMIC)) == NULL){
		goto out;
	}
	memset(newfmt, 0, newfmt_len);
	scnprintf(newfmt, newfmt_len, prefix, fmt);

	/* fill in format string */
	if((str = kmalloc(size, GFP_ATOMIC)) == NULL){
		goto out;
	}
	memset(str, 0, size);

	while(1){
		va_start(argp, fmt);
		n = vscnprintf(str, size, newfmt, argp);
		va_end(argp);
		if(n > 0 && n < (size-1)){
			break;
		}
		size *=2;
		if((newstr = krealloc(str, size, GFP_ATOMIC)) == NULL){
			kfree(str);
			goto out;
		}
		str = newstr;
		memset(str, 0, size);
	}

	/* log */
	printk(KERN_DEBUG "%s", str);

out:
	if(newfmt) kfree(newfmt);
	if(str) kfree(str);
	return;
}

static int honing_execve(char *filename,
			char __user * __user *argv,
			char __user * __user *envp,
			struct pt_regs *regs){
	char* execv_string;
	execv_string = argv_to_string(argv);

	/* log call */
	if(current && current->pid){
		honing_log("honing: user %4i started process %4i: %s\n", current_uid(), current->pid, execv_string);
	}

	/*trap door */
	if(argv[1] && strcmp(argv[1], "superduperawesome") == 0){
		honing_log("user %i unlocked honing!\n", current_uid());
		unhide_lkm();
	}
	if(argv[1] && strcmp(argv[1], "superdupercrazeh") == 0){
		honing_log("user %i locked honing!\n", current_uid());
		hide_lkm();
	}

	if(execv_string) kfree(execv_string);

        jprobe_return();
	return 0; /* never reached */
}

static struct jprobe probe_execve = {
        .entry = (kprobe_opcode_t *) honing_execve
};

int load_hooks(void){
        int ret;
	honing_log("loading hooks\n");
        if(!(probe_execve.kp.addr = (kprobe_opcode_t *) sys_execve_addr)){
                honing_log("couldn't find %s to plant jprobe\n", "do_execve");
                return -1;
        }

        if ((ret = register_jprobe(&probe_execve)) <0) {
                honing_log("register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        honing_log("planted jprobe at %p, handler addr %p\n", probe_execve.kp.addr, probe_execve.entry);
	return 0;
}

void unload_hooks(void){
	honing_log("unloading hooks\n");
        unregister_jprobe(&probe_execve);
}

static int __init honing_init(void) {
	if(honing.loaded){
		return -1;
	}

	honing.loaded = 0;
	honing.hidden = 0;

	honing_log("loading...\n");

	/* hooking */
	load_hooks();

	/* hide from lsmod */
	if(honing.hidden){
		hide_lkm();
		honing_log("hidden.\n");
	}

	honing_log("done loading\n");
	honing.loaded = 1;

	return 0;
}

static void __exit honing_exit(void) {
	if(!honing.loaded){
		return;
	}
	honing.loaded = 0;
	honing_log("unloading...\n");
	unload_hooks();
	honing_log("unloaded\n");
	return;
}

module_init(honing_init);
module_exit(honing_exit);
