/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/compat.h>

#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; 
int aesd_minor =   0;

MODULE_AUTHOR("Laye E. Tenumah"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static void push_complete_command_locked(struct aesd_dev *dev, const char *data, size_t len)
{
    struct aesd_buffer_entry entry;
    entry.buffptr = data;
    entry.size = len;

    if (dev->circ.full) {
        const struct aesd_buffer_entry *old = &dev->circ.entry[dev->circ.out_offs];
        if (old->buffptr)
            kfree(old->buffptr);
    }

    aesd_circular_buffer_add_entry(&dev->circ, &entry);
}


static inline uint32_t circ_valid_count(const struct aesd_circular_buffer *circ)
{
    return circ->full ? AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED : circ->in_offs;
}

static size_t circ_total_bytes(const struct aesd_circular_buffer *circ)
{
    size_t total = 0;
    uint32_t cnt = circ_valid_count(circ);

    if (!cnt) return 0;

    for (uint32_t i = 0; i < cnt; ++i) {
        uint32_t idx = (circ->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        total += circ->entry[idx].size;
    }
    return total;
}

static int seekto_to_fpos(const struct aesd_circular_buffer *circ,
                          uint32_t cmd_index, uint32_t cmd_offset,
                          loff_t *newpos)
{
    uint32_t valid = circ_valid_count(circ);
    loff_t pos = 0;
    uint32_t i;

    if (valid == 0 || cmd_index >= valid)
        return -EINVAL;

    for (i = 0; i < cmd_index; i++) {
        uint32_t idx = (circ->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        pos += circ->entry[idx].size;
    }

    uint32_t target_idx = (circ->out_offs + cmd_index) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (cmd_offset > circ->entry[target_idx].size)
        return -EINVAL;

    pos += cmd_offset;
    *newpos = pos;
    return 0;
}


int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = &aesd_device;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    size_t entry_offset = 0;
    const struct aesd_buffer_entry *entry;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    if (!dev)
        return -EFAULT;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circ, *f_pos, &entry_offset);
    if (!entry) {
        retval = 0; 
        goto out_unlock;
    }

    {
        size_t available = entry->size - entry_offset;
        size_t to_copy = min(available, count);

        if (copy_to_user(buf, entry->buffptr + entry_offset, to_copy)) {
            retval = -EFAULT;
            goto out_unlock;
        }

        *f_pos += to_copy;
        retval = to_copy;
    }

out_unlock:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    char *kbuf = NULL;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (!dev)
        return -EFAULT;
    if (count == 0)
        return 0;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) {
        retval = -ENOMEM;
        goto out_unlock;
    }

    if (copy_from_user(kbuf, buf, count)) {
        retval = -EFAULT;
        goto out_free_kbuf;
    }

    if (dev->partial_buf) {
        char *newp = krealloc(dev->partial_buf, dev->partial_size + count, GFP_KERNEL);
        if (!newp) {
            retval = -ENOMEM;
            goto out_free_kbuf;
        }
        memcpy(newp + dev->partial_size, kbuf, count);
        dev->partial_buf = newp;
        dev->partial_size += count;
        kbuf = NULL;
    } else {
        dev->partial_buf = kbuf;
        dev->partial_size = count;
        kbuf = NULL;
    }

    while (dev->partial_buf) {
        char *newline = memchr(dev->partial_buf, '\n', dev->partial_size);
        if (!newline)
            break; 

        size_t cmd_len = (size_t)(newline - dev->partial_buf) + 1;
        char *cmd = kmalloc(cmd_len, GFP_KERNEL);
        if (!cmd) {
            retval = -ENOMEM;
            goto out_unlock;
        }
        memcpy(cmd, dev->partial_buf, cmd_len);
        push_complete_command_locked(dev, cmd, cmd_len);

        {
            size_t remain = dev->partial_size - cmd_len;
            if (remain == 0) {
                kfree(dev->partial_buf);
                dev->partial_buf = NULL;
                dev->partial_size = 0;
            } else {
                memmove(dev->partial_buf, dev->partial_buf + cmd_len, remain);
                dev->partial_buf = krealloc(dev->partial_buf, remain, GFP_KERNEL);
                dev->partial_size = remain;
            }
        }
    }

    retval = count;
    goto out_unlock;

out_free_kbuf:
    kfree(kbuf);
out_unlock:
    mutex_unlock(&dev->lock);
    return retval;
}


static loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    loff_t newpos;
    struct aesd_dev *dev = filp->private_data;
    loff_t endpos;

    if (!dev) return -EFAULT;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    endpos = (loff_t)circ_total_bytes(&dev->circ);

    switch (whence) {
    case SEEK_SET:
        newpos = offset;
        break;
    case SEEK_CUR:
        newpos = filp->f_pos + offset;
        break;
    case SEEK_END:
        newpos = endpos + offset;
        break;
    default:
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    if (newpos < 0) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }
    if (newpos > endpos) {
        newpos = endpos;
    }

    filp->f_pos = newpos;
    mutex_unlock(&dev->lock);
    return newpos;
}

static long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    long rc = 0;

    if (!dev) return -EFAULT;

    if (cmd != AESDCHAR_IOCSEEKTO)
        return -ENOTTY;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    do {
        struct aesd_seekto user_seek;
        loff_t newpos;

        if (copy_from_user(&user_seek, (const void __user *)arg, sizeof(user_seek))) {
            rc = -EFAULT;
            break;
        }

        rc = seekto_to_fpos(&dev->circ, user_seek.write_cmd, user_seek.write_cmd_offset, &newpos);
        if (rc)
            break;

        filp->f_pos = newpos;
        rc = 0;
    } while (0);

    mutex_unlock(&dev->lock);
    return rc;
}

#ifdef CONFIG_COMPAT
static long aesd_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return aesd_unlocked_ioctl(filp, cmd, arg);
}
#endif

struct file_operations aesd_fops = {
    .owner          = THIS_MODULE,
    .read           = aesd_read,
    .write          = aesd_write,
    .open           = aesd_open,
    .release        = aesd_release,
    .llseek         = aesd_llseek,   
    .unlocked_ioctl = aesd_unlocked_ioctl, 
#ifdef CONFIG_COMPAT
    .compat_ioctl   = aesd_compat_ioctl,   
#endif
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
        printk(KERN_ERR "Error %d adding aesd cdev", err);

    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.circ);
    mutex_init(&aesd_device.lock);
    aesd_device.partial_buf  = NULL;
    aesd_device.partial_size = 0;

    result = aesd_setup_cdev(&aesd_device);
    if (result)
        unregister_chrdev_region(dev, 1);

    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    if (aesd_device.partial_buf) {
        kfree(aesd_device.partial_buf);
        aesd_device.partial_buf = NULL;
        aesd_device.partial_size = 0;
    }

    {
        const struct aesd_buffer_entry *entry;
        uint8_t idx;
        AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circ, idx) {
            if (entry->buffptr)
                kfree(entry->buffptr);
        }
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
