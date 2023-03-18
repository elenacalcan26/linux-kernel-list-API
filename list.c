// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Elena-Claudia Calcan <elena.calcan26@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

#define ADDF "addf"
#define ADDE "adde"
#define DELF "delf"
#define DELA "dela"

#define TYPE_FIRST 'f'
#define TYPE_END 'e'
#define TYPE_ALL 'a'

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/* TODO 2: define your list! */
struct string_data_info {
	char *str;
	struct list_head list;
};

static struct list_head head;

/*
 * Allocates a list element.
 *
 * @name: string data to be added
 */
static struct string_data_info *alloc_list_node(char *name)
{
	struct string_data_info *node;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;

	node->str = kmalloc(strlen(name), GFP_KERNEL);

	if (node->str == NULL) {
		kfree(node);
		return NULL;
	}

	strcpy(node->str, name);

	return node;
}

/*
 * Adds a node to list
 *
 * @name: string data to be added
 * @type: where to add the created list element; to the top/end of the list
 */
static void add_command(char *name, char type)
{
	struct string_data_info *node;

	node = alloc_list_node(name);

	if (type == TYPE_FIRST)
		list_add(&node->list, &head);
	else if (type == TYPE_END)
		list_add_tail(&node->list, &head);
	else
		pr_err("Unknown type!\n");
}

/*
 * Deletes all the elements of the list and frees the memory.
 */
static void purge_list(void)
{
	struct list_head *p, *q;
	struct string_data_info *node;

	list_for_each_safe(p, q, &head) {
		node = list_entry(p, struct string_data_info, list);
		list_del(p);
		kfree(node->str);
		kfree(node);
	}
}

/*
 * Deletes occurrences of the name element in list.
 *
 * @name: data to be deleted
 * @type: type of occurrence; first/all occurrences in the list
 */
static void delete_command(char *name, char type)
{
	struct list_head *p, *q;
	struct string_data_info *node;

	list_for_each_safe(p, q, &head) {
		node = list_entry(p, struct string_data_info, list);

		if (strcmp(node->str, name) == 0) {
			list_del(p);
			kfree(node->str);
			kfree(node);

			if (type == TYPE_FIRST)
				return;
		}
	}
}

static int list_proc_show(struct seq_file *m, void *v)
{
	/* TODO 3: print your list. One element / line. */
	struct list_head *p;
	struct string_data_info *node;

	list_for_each(p, &head) {
		node = list_entry(p, struct string_data_info, list);
		seq_puts(m, node->str);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	char *name;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */

	name = strrchr(local_buffer, ' ') + 1;

	if (strncmp(local_buffer, ADDF, strlen(ADDF)) == 0)
		add_command(name, TYPE_FIRST);
	else if (strncmp(local_buffer, ADDE, strlen(ADDE)) == 0)
		add_command(name, TYPE_END);
	else if (strncmp(local_buffer, DELF, strlen(DELF)) == 0)
		delete_command(name, TYPE_FIRST);
	else if (strncmp(local_buffer, DELA, strlen(DELA)) == 0)
		delete_command(name, TYPE_ALL);
	else
		pr_err("Unknown command!\n");

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{

	INIT_LIST_HEAD(&head);

	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	purge_list();
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("Elena-Claudia Calcan <elena.calcan26@gmail.com>");
MODULE_LICENSE("GPL v2");
