#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include "monitor_ioctl.h"

#define TIMER_INTERVAL_MS 1000

struct monitored_container {
    pid_t pid;
    char container_id[64];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int soft_limit_hit;
    struct list_head list;
};

static LIST_HEAD(container_list);
static DEFINE_SPINLOCK(list_lock);
static struct timer_list monitor_timer;

static long get_rss_bytes(pid_t pid) {
    struct task_struct *task;
    struct mm_struct *mm;
    long rss = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) return -1;

    mm = get_task_mm(task);
    if (mm) {
        rss = get_mm_rss(mm) << PAGE_SHIFT;
        mmput(mm);
    }
    return rss;
}

static void log_soft_limit_event(const char *container_id, pid_t pid, long rss) {
    pr_warn("CONTAINER_MONITOR: [SOFT LIMIT] Container %s (PID %d) exceeded soft limit. Current RSS: %ld bytes\n", container_id, pid, rss);
}

static void kill_process(const char *container_id, pid_t pid, long rss) {
    struct task_struct *task;
    struct kernel_siginfo info;

    pr_err("CONTAINER_MONITOR: [HARD LIMIT] Container %s (PID %d) exceeded hard limit with RSS: %ld bytes. Issuing SIGKILL.\n", container_id, pid, rss);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        memset(&info, 0, sizeof(info));
        info.si_signo = SIGKILL;
        info.si_code = SI_KERNEL;
        send_sig_info(SIGKILL, &info, task);
    }
}

static void monitor_timer_callback(struct timer_list *t) {
    struct monitored_container *curr, *tmp;
    long rss;

    spin_lock(&list_lock);
    list_for_each_entry_safe(curr, tmp, &container_list, list) {
        rss = get_rss_bytes(curr->pid);
        
        if (rss < 0) {
            list_del(&curr->list);
            kfree(curr);
            continue;
        }

        if (rss > curr->hard_limit_bytes) {
            kill_process(curr->container_id, curr->pid, rss);
            list_del(&curr->list);
            kfree(curr);
        } else if (rss > curr->soft_limit_bytes && !curr->soft_limit_hit) {
            log_soft_limit_event(curr->container_id, curr->pid, rss);
            curr->soft_limit_hit = 1;
        }
    }
    spin_unlock(&list_lock);

    mod_timer(&monitor_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
}

static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct monitor_request req;
    struct monitored_container *new_container, *curr, *tmp;
    int found;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    switch (cmd) {
        case MONITOR_REGISTER:
            new_container = kmalloc(sizeof(*new_container), GFP_KERNEL);
            if (!new_container) return -ENOMEM;
            
            new_container->pid = req.pid;
            strncpy(new_container->container_id, req.container_id, sizeof(new_container->container_id) - 1);
            new_container->soft_limit_bytes = req.soft_limit_bytes;
            new_container->hard_limit_bytes = req.hard_limit_bytes;
            new_container->soft_limit_hit = 0;

            spin_lock(&list_lock);
            list_add(&new_container->list, &container_list);
            spin_unlock(&list_lock);
            break;

        case MONITOR_UNREGISTER:
            found = 0;
            spin_lock(&list_lock);
            list_for_each_entry_safe(curr, tmp, &container_list, list) {
                if (curr->pid == req.pid) {
                    list_del(&curr->list);
                    kfree(curr);
                    found = 1;
                    break;
                }
            }
            spin_unlock(&list_lock);
            if (!found) return -ENOENT;
            break;

        default:
            return -EINVAL;
    }
    return 0;
}

static const struct file_operations monitor_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

static struct miscdevice monitor_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "container_monitor",
    .fops = &monitor_fops,
};

static int __init monitor_init(void) {
    int ret = misc_register(&monitor_miscdev);
    if (ret) {
        pr_err("CONTAINER_MONITOR: Failed to register misc device\n");
        return ret;
    }
    timer_setup(&monitor_timer, monitor_timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + msecs_to_jiffies(TIMER_INTERVAL_MS));
    pr_info("CONTAINER_MONITOR: Module loaded\n");
    return 0;
}

static void __exit monitor_exit(void) {
    struct monitored_container *curr, *tmp;

    timer_shutdown_sync(&monitor_timer);
    misc_deregister(&monitor_miscdev);

    spin_lock(&list_lock);
    list_for_each_entry_safe(curr, tmp, &container_list, list) {
        list_del(&curr->list);
        kfree(curr);
    }
    spin_unlock(&list_lock);

    pr_info("CONTAINER_MONITOR: Module unloaded\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Systems Programmer");
MODULE_DESCRIPTION("Kernel Memory Monitor for Multi-Container Runtime");
